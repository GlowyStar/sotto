"""The client transport of docs/protocol.md, section 23, over the session layer.

`Transport` dials the relay, logs in, runs the steps after the LoggedIn and serves the
frames of the relay until the connection ends; it reconnects or stops as section 11 says.
It only moves frames: every rule of a message is a method of `Client`, which commits before
it answers. The SQLite work of `Client` runs on the thread of the event loop.
"""

import asyncio
import ipaddress
import mimetypes
import re
import secrets
from collections.abc import Callable, Coroutine
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit

from google.protobuf.message import DecodeError
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, InvalidHandshake

from sotto.client.envelope import (
    MAX_FILE_NAME_BYTES,
    MAX_MEDIA_TYPE_BYTES,
    NotAnImageError,
    cut_to,
    encode_text,
    encode_timer,
)
from sotto.client.session import (
    BLOB_GONE,
    Client,
    Delivered,
    FileState,
    FilesUnsupportedError,
    FileTooLargeError,
    Outgoing,
    PrekeyUpload,
    Received,
)
from sotto.client.store import FileRow, UploadRow
from sotto.crypto.blob import BadBlobError, blob_length
from sotto.crypto.identity import (
    KEM_PUBLIC_KEY_LENGTH,
    KEY_LENGTH,
    NONCE_LENGTH,
    SIGNATURE_LENGTH,
    Bundle,
    CryptoError,
    OneTimePrekey,
    SignedPrekey,
)
from sotto.proto.sotto_pb2 import (
    Ack,
    Attachment,
    BlobData,
    BlobStored,
    BundleStored,
    ClientFrame,
    DeleteBlob,
    Deliver,
    ErrorCode,
    FetchBlob,
    FetchBundle,
    Hello,
    LoggedIn,
    MessageRef,
    PutBlob,
    Send,
    ServerFrame,
    StartBlob,
    Stored,
    UploadBundle,
)
from sotto.proto.sotto_pb2 import Bundle as BundleFrame
from sotto.proto.sotto_pb2 import Error as ErrorFrame
from sotto.proto.sotto_pb2 import OneTimePrekey as OneTimePrekeyFrame
from sotto.proto.sotto_pb2 import SignedPrekey as SignedPrekeyFrame
from sotto.relay.frames import (
    BLOB_CHUNK_BYTES,
    BLOB_ID_LENGTH,
    MAX_FRAME_BYTES,
    MAX_PAYLOAD_BYTES,
    MESSAGE_ID_LENGTH,
)
from sotto.relay.server import CloseCode

RELAY_PROTOCOL_VERSION = 1
EXPIRY_CHECK_SECONDS = 1
RETRY_MAX_SECONDS = 60
FRAME_REFILL_SECONDS = 1
NORMAL_CLOSURE = 1000
# TimeoutError, the end of the open timeout, is an OSError.
DIAL_FAILURES = (OSError, InvalidHandshake)
SERVER_NAME = re.compile(r"[a-z0-9._:-]{1,255}")
DOTTED_DECIMAL = re.compile(r"(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}")
LOOPBACK_IPV6 = ipaddress.IPv6Address("::1")
STOP_CLOSE_CODES = frozenset(
    {
        CloseCode.TEXT_FRAME,
        CloseCode.PROTOCOL_VIOLATION,
        CloseCode.FRAME_TOO_BIG,
        CloseCode.LOGIN_REFUSED,
        CloseCode.REPLACED,
    }
)
BACK_OFF_CODES = frozenset(
    {ErrorCode.QUEUE_FULL, ErrorCode.STORAGE_FULL, ErrorCode.RATE_LIMITED}
)
# The frame bucket and the page ceiling are shared by every request (section 23.5).
HOLDING_CODES = frozenset({ErrorCode.STORAGE_FULL, ErrorCode.RATE_LIMITED})
SENDS = frozenset({"send"})
BUNDLE_UPLOADS = frozenset({"upload_bundle"})
BUNDLE_FETCHES = frozenset({"fetch_bundle"})
BLOB_WRITES = frozenset({"start_blob", "put_blob"})
BLOB_READS = frozenset({"fetch_blob"})

type ServerMessage = (
    Hello
    | LoggedIn
    | BundleStored
    | BundleFrame
    | Stored
    | Deliver
    | ErrorFrame
    | BlobStored
    | BlobData
)
type BlobReply = BlobStored | BlobData | ErrorFrame
type TransferKey = tuple[str, bytes]
type Jitter = Callable[[float], float]

_system_random = secrets.SystemRandom()


class Action(StrEnum):
    """The three actions of section 11.1."""

    RETRY = "Retry"
    STOP = "Stop"
    BACK_OFF = "Back off"


class UrlRefusedError(ValueError):
    """The URL is not dialed: section 8.2, rule 4, or the loopback rule of section 23.1."""


class MalformedFrameError(Exception):
    """A binary message is a malformed frame by section 7.3."""


class UnknownVersionError(MalformedFrameError):
    """The Hello names a relay protocol version other than 1 (section 14.1)."""

    def __init__(self, version: int) -> None:
        super().__init__(f"the relay speaks protocol version {version}")
        self.version = version


class RefusedError(Exception):
    """The relay refused a FetchBundle with an Error whose action is Stop."""

    def __init__(self, result: str) -> None:
        super().__init__(result)
        self.result = result


class _ViolationError(Exception):
    def __init__(self, code: CloseCode) -> None:
        super().__init__(code.name)
        self.code = code


class _StopError(Exception):
    pass


class _ConnectionLostError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Connected:
    """The relay accepted the Login and the steps of section 23.3 went out."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Incoming:
    """A Deliver after `Client.receive`, which committed before its Ack left."""

    sender: bytes
    received: Received


@dataclass(frozen=True, slots=True, kw_only=True)
class Refused:
    """A Send or an UploadBundle that the relay refused with an action Stop.

    `contact` is the recipient of a Send and None for an UploadBundle.
    """

    result: str
    contact: bytes | None


@dataclass(frozen=True, slots=True, kw_only=True)
class Retrying:
    """The connection is gone or was never made; the next attempt follows the wait."""

    seconds: float


@dataclass(frozen=True, slots=True, kw_only=True)
class Stopped:
    """The client does not reconnect; a person takes the next step (section 11.1)."""

    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class FileUpdate:
    """A file of section 33.5 changed its state or its progress.

    `contact` is the recipient of a file being sent and the sender of a received one;
    `file_name` is the name in the attachment, a text of the peer for a received file.
    `done` out of `total` bytes of the blob are stored at the relay or downloaded.
    `avatar` marks the avatar of a profile (section 36), which is no file of the chat.
    """

    contact: bytes
    blob_id: bytes
    file_name: str
    state: FileState
    done: int = 0
    total: int = 0
    result: str | None = None
    path: Path | None = None
    avatar: bool = False


@dataclass(frozen=True, slots=True, kw_only=True)
class TransferFailed:
    """A transfer stopped on a local failure; the next login starts it again."""

    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class Written:
    """An own text entered the log under `number`, before its Send left."""

    contact: bytes
    number: int
    text: str
    reply_to: int | None
    expires_after: int


@dataclass(frozen=True, slots=True, kw_only=True)
class Sent:
    """The relay stored an own message of the log that no receipt has reached."""

    number: int


@dataclass(frozen=True, slots=True, kw_only=True)
class Expired:
    """The timer of these messages ran out, and they are gone (section 39.6)."""

    numbers: tuple[int, ...]


type Event = (
    Connected
    | Incoming
    | Refused
    | Retrying
    | Stopped
    | FileUpdate
    | TransferFailed
    | Written
    | Sent
    | Expired
)


def even_jitter(upper: float) -> float:
    return _system_random.uniform(0, upper)


def server_name_of(url: str, *, insecure: bool) -> str:
    """Returns the server name of section 8.2 of a URL that the client may dial.

    Args:
        url: The URL of the relay, as the user gave it.
        insecure: The override of section 23.1 for a ws URL to another host.

    Raises:
        UrlRefusedError: The URL breaks rule 4 of section 8.2 or the rule of section 23.1.
    """
    try:
        parts = urlsplit(url)
        parts.port  # noqa: B018 - a port that is not a number raises here
    except ValueError as error:
        raise UrlRefusedError("the URL does not parse") from error
    if parts.scheme not in ("ws", "wss"):
        raise UrlRefusedError("the scheme of the URL is not ws or wss")

    name = parts.hostname
    if name is None or SERVER_NAME.fullmatch(name) is None:
        raise UrlRefusedError("the host of the URL gives no server name (section 8.2)")

    is_plain = parts.scheme == "ws"
    is_remote = not is_loopback(name)
    if is_plain and is_remote and not insecure:
        raise UrlRefusedError(
            "a ws URL is dialed only to a loopback host without the insecure override"
        )
    return name


def is_loopback(server_name: str) -> bool:
    """The loopback host of section 23.1: localhost, 127.x.y.z in full, or ::1."""
    if server_name == "localhost":
        return True
    if DOTTED_DECIMAL.fullmatch(server_name):
        numbers = [int(number) for number in server_name.split(".")]
        return numbers[0] == 127 and max(numbers) <= 255
    try:
        return ipaddress.IPv6Address(server_name) == LOOPBACK_IPV6
    except ValueError:
        return False


def retry_seconds(attempt: int, *, jitter: Jitter = even_jitter) -> float:
    """The wait before attempt n of section 23.4."""
    # The exponent is capped, so that the power stays a small float.
    wait = min(2.0 ** min(attempt - 1, 10), RETRY_MAX_SECONDS)
    return wait + jitter(wait / 2)


def back_off_seconds(refusals: int, *, jitter: Jitter = even_jitter) -> float:
    """The wait of section 23.5 after the k-th refusal in a row of one frame."""
    wait = min(FRAME_REFILL_SECONDS * 2.0 ** min(refusals - 1, 10), RETRY_MAX_SECONDS)
    return wait + jitter(wait / 2)


def close_action(code: int | None) -> Action:
    """The action of a close that the relay sent (section 11.3); None for no close."""
    if code in STOP_CLOSE_CODES:
        return Action.STOP
    return Action.RETRY


def error_action(code: int) -> Action:
    """The action of an Error code (section 11.2); an unknown code is Stop."""
    if code in BACK_OFF_CODES:
        return Action.BACK_OFF
    return Action.STOP


def read_server_frame(message: bytes) -> ServerMessage:
    """Returns the frame that a binary message from the relay holds (section 7.3).

    Raises:
        UnknownVersionError: A Hello whose version is not 1, read before its other fields.
        MalformedFrameError: The message is a malformed frame.
    """
    envelope = ServerFrame()
    try:
        envelope.ParseFromString(message)
    except DecodeError as error:
        raise MalformedFrameError("the message is not a ServerFrame") from error

    match envelope.WhichOneof("frame"):
        case "hello":
            if envelope.hello.version != RELAY_PROTOCOL_VERSION:
                raise UnknownVersionError(envelope.hello.version)
            _require_length("nonce", envelope.hello.nonce, NONCE_LENGTH)
            return envelope.hello
        case "logged_in":
            return envelope.logged_in
        case "bundle_stored":
            return envelope.bundle_stored
        case "bundle":
            _check_bundle(envelope.bundle)
            return envelope.bundle
        case "stored":
            _require_length("message_id", envelope.stored.message_id, MESSAGE_ID_LENGTH)
            return envelope.stored
        case "deliver":
            _check_deliver(envelope.deliver)
            return envelope.deliver
        case "error":
            _check_error(envelope.error)
            return envelope.error
        case "blob_stored":
            _require_length("blob_id", envelope.blob_stored.blob_id, BLOB_ID_LENGTH)
            return envelope.blob_stored
        case "blob_data":
            _check_blob_data(envelope.blob_data)
            return envelope.blob_data
        case _:
            raise MalformedFrameError("no frame of the schema is set")


def upload_frame(upload: PrekeyUpload) -> UploadBundle:
    pq_prekey = None
    if upload.pq_prekey is not None:
        pq_prekey = _signed_prekey_frame(upload.pq_prekey)
    return UploadBundle(
        identity_dh_key=upload.identity_dh_key,
        identity_dh_signature=upload.identity_dh_signature,
        signed_prekey=_signed_prekey_frame(upload.signed_prekey),
        one_time_prekeys=[
            OneTimePrekeyFrame(id=prekey.id, key=prekey.key)
            for prekey in upload.one_time_prekeys
        ],
        pq_prekey=pq_prekey,
        pq_one_time_prekeys=[
            _signed_prekey_frame(prekey) for prekey in upload.pq_one_time_prekeys
        ],
    )


def bundle_of(frame: BundleFrame) -> Bundle:
    extra = None
    if frame.HasField("one_time_prekey"):
        handed = frame.one_time_prekey
        extra = OneTimePrekey(id=handed.id, key=handed.key)
    pq_prekey = None
    if frame.HasField("pq_prekey"):
        pq_prekey = _signed_prekey(frame.pq_prekey)
    return Bundle(
        identity=frame.identity,
        identity_dh_key=frame.identity_dh_key,
        identity_dh_signature=frame.identity_dh_signature,
        signed_prekey=_signed_prekey(frame.signed_prekey),
        one_time_prekey=extra,
        pq_prekey=pq_prekey,
    )


def _signed_prekey(frame: SignedPrekeyFrame) -> SignedPrekey:
    return SignedPrekey(id=frame.id, key=frame.key, signature=frame.signature)


def _signed_prekey_frame(prekey: SignedPrekey) -> SignedPrekeyFrame:
    return SignedPrekeyFrame(id=prekey.id, key=prekey.key, signature=prekey.signature)


def send_frame(outgoing: Outgoing) -> ClientFrame:
    return ClientFrame(
        send=Send(
            message_id=outgoing.message_id,
            recipient=outgoing.recipient,
            payload=outgoing.payload,
        )
    )


@dataclass(slots=True, kw_only=True)
class _Request:
    """A frame that waits for its answer on the connection that sent it.

    `sequence` counts the requests of the client in the order they left.
    """

    frame: ClientFrame
    upload: PrekeyUpload | None = None
    bundle: asyncio.Future[Bundle] | None = None
    reply: asyncio.Future[BlobReply] | None = None
    sequence: int = 0
    refusals: int = 0
    waiting: bool = False
    holds_others: bool = False

    def answers_to(self, kinds: frozenset[str], key: bytes) -> bool:
        frame = self.frame
        match frame.WhichOneof("frame"):
            case "send":
                own_key = frame.send.message_id
            case "fetch_bundle":
                own_key = frame.fetch_bundle.identity
            case "start_blob":
                own_key = frame.start_blob.blob_id
            case "put_blob":
                own_key = frame.put_blob.blob_id
            case "fetch_blob":
                own_key = frame.fetch_blob.blob_id + frame.fetch_blob.uploader
            case _:
                own_key = b""
        return frame.WhichOneof("frame") in kinds and own_key == key


class Transport:
    """The connection of one client to its relay.

    Args:
        client: The session layer of the identity.
        url: The URL of the relay, dialed as given (section 23.1).
        insecure: The override that allows a ws URL to a host that is not a loopback host.
        jitter: Chooses a number evenly between 0 and its argument (sections 23.4, 23.5).
        received_files: The folder for received files; every offered file is downloaded
            into it by itself (section 33.3). None leaves offered files offered.

    Raises:
        UrlRefusedError: The URL is not dialed; nothing else ran.
    """

    def __init__(
        self,
        client: Client,
        url: str,
        *,
        insecure: bool = False,
        jitter: Jitter = even_jitter,
        received_files: Path | None = None,
    ) -> None:
        self.server_name = server_name_of(url, insecure=insecure)
        self.client = client
        self.url = url
        self.jitter = jitter
        self.received_files = received_files
        self.blob_max_bytes = 0
        self.events: asyncio.Queue[Event] = asyncio.Queue()
        self._connection: ClientConnection | None = None
        # Set once the steps of section 23.3 are done: no Send of the user precedes them.
        self._ready = asyncio.Event()
        self._unblocked = asyncio.Event()
        self._unblocked.set()
        self._holders = 0
        self._requests: list[_Request] = []
        self._back_offs: set[asyncio.Task[None]] = set()
        self._owed_sends: set[asyncio.Task[None]] = set()
        self._transfers: dict[TransferKey, asyncio.Task[None]] = {}
        self._sequence = 0
        # A DeleteBlob sent on this connection, with the sequence of the last request
        # that left before it: an answer to a later request confirms it.
        self._deletions_sent: dict[tuple[bytes, bytes], int] = {}

    async def run(self) -> None:
        """Serves connections until an action Stop, which it puts as `Stopped` in `events`.

        A Retry waits by the schedule of section 23.4. Cancel the task to stop the client.
        """
        self.client.delete_expired_prekeys()
        attempt = 0
        # In one group, so that a failure of the expiry ends `run` instead of the expiry.
        async with asyncio.TaskGroup() as tasks:
            expiry = tasks.create_task(self._expire_periodically())
            try:
                while True:
                    if attempt > 0:
                        wait = retry_seconds(attempt, jitter=self.jitter)
                        self.events.put_nowait(Retrying(seconds=wait))
                        await asyncio.sleep(wait)
                    try:
                        logged_in = await self._serve_connection()
                    except _StopError as stop:
                        self.events.put_nowait(Stopped(reason=str(stop)))
                        return
                    attempt = 1 if logged_in else attempt + 1
            finally:
                expiry.cancel()

    async def send_text(
        self, contact: bytes, text: str, *, reply_to: int | None = None
    ) -> None:
        """Commits a text to the outbox, reports it as `Written` and sends it; a Send
        without a Stored is sent again after the next login. `reply_to` is the number of
        the message of the chat that the text quotes (section 39.2).

        A contact without a session gets its bundle fetched first, which waits for a login.

        Raises:
            TextTooLongError: Before any frame.
            RefusedError: The relay refused the FetchBundle with a Stop.
            CryptoError: `Client.send_text` failed with the result that it names.
        """
        encode_text(text)
        bundle = await self._bundle_unless_in_session(contact)
        outgoing = self.client.send_text(contact, text, bundle=bundle, reply_to=reply_to)
        if outgoing.number is not None:
            written = Written(
                contact=contact,
                number=outgoing.number,
                text=text,
                reply_to=reply_to,
                expires_after=self.client.timer(contact),
            )
            self.events.put_nowait(written)
        await self._send(outgoing)

    async def edit(self, contact: bytes, number: int, text: str) -> None:
        """Sends an edit of an own message (section 39.3).

        Raises:
            CryptoError: `Client.edit` refused it with the result that it names.
            RefusedError: The relay refused the FetchBundle with a Stop.
        """
        bundle = await self._bundle_unless_in_session(contact)
        await self._send(self.client.edit(contact, number, text, bundle=bundle))

    async def delete(self, contact: bytes, number: int) -> None:
        """Deletes an own message for both (section 39.4).

        Raises:
            CryptoError: `Client.delete` refused it with the result that it names.
            RefusedError: The relay refused the FetchBundle with a Stop.
        """
        bundle = await self._bundle_unless_in_session(contact)
        await self._send(self.client.delete(contact, number, bundle=bundle))

    async def set_timer(self, contact: bytes, seconds: int) -> None:
        """Sets the disappearing timer of the chat, 0 for none (section 39.6).

        Raises:
            BadTimerError: The seconds are above MAX_TIMER_SECONDS.
            RefusedError: The relay refused the FetchBundle with a Stop.
        """
        encode_timer(seconds)
        bundle = await self._bundle_unless_in_session(contact)
        await self._send(self.client.set_timer(contact, seconds, bundle=bundle))

    def mark_read(self, contact: bytes, number: int) -> None:
        """The user has seen a message: its timer starts, and its read receipt goes out
        once logged in unless read receipts are off (section 39.5)."""
        self.client.mark_read(contact, [number])
        self._send_owed_later()

    async def _bundle_unless_in_session(self, contact: bytes) -> Bundle | None:
        if self.client.has_session(contact):
            return None
        return await self.fetch_bundle(contact)

    async def _send(self, outgoing: Outgoing) -> None:
        if self._ready.is_set():
            await self._request(_Request(frame=send_frame(outgoing)))
        await self._send_owed()

    async def send_file(self, contact: bytes, path: Path, *, caption: str = "") -> bytes:
        """Steps 1 and 2 of section 33.2 once logged in; the upload goes on in the
        background and reports itself as FileUpdate events.

        Returns:
            The blob id that the FileUpdate events of the file name.

        Raises:
            NotAContactError, FilesUnsupportedError, FileTooLargeError: A check of 33.1.
            OSError: The file cannot be read.
            ValueError: The caption is longer than MAX_CAPTION_BYTES.
        """
        await self._ready.wait()
        size = (await asyncio.to_thread(path.stat)).st_size
        self.client.check_file(contact, size, blob_max_bytes=self.blob_max_bytes)
        data = await asyncio.to_thread(path.read_bytes)
        media_type = mimetypes.guess_type(path.name)[0] or ""
        upload = self.client.start_upload(
            contact,
            data,
            blob_max_bytes=self.blob_max_bytes,
            file_name=cut_to(path.name, MAX_FILE_NAME_BYTES),
            media_type=media_type if len(media_type) <= MAX_MEDIA_TYPE_BYTES else "",
            caption=caption,
        )
        self._report_upload(upload, FileState.SENDING)
        if self._ready.is_set():
            self._start_transfers()
        return upload.blob_id

    async def reset_session(self, contact: bytes) -> int:
        """L2 of section 20.6 with a fresh bundle; returns the GAP of the session that left."""
        bundle = await self.fetch_bundle(contact)
        missing = self.client.start_session(contact, bundle)
        await self._send_owed()
        return missing

    async def fetch_bundle(self, contact: bytes) -> Bundle:
        """The bundle of a contact, fetched again after a reconnect until an answer.

        Raises:
            RefusedError: The relay refused the FetchBundle with a Stop.
        """
        while True:
            await self._ready.wait()
            future: asyncio.Future[Bundle] = asyncio.get_running_loop().create_future()
            frame = ClientFrame(fetch_bundle=FetchBundle(identity=contact))
            if not await self._request(_Request(frame=frame, bundle=future)):
                continue
            try:
                return await future
            except _ConnectionLostError:
                continue

    async def _serve_connection(self) -> bool:
        """One connection from the dial to its end; True when the relay sent LoggedIn.

        Raises:
            _StopError: The connection ended with an action Stop.
        """
        logged_in = False
        try:
            async with connect(
                self.url, proxy=None, max_size=MAX_FRAME_BYTES, compression=None
            ) as connection:
                try:
                    logged_in_frame = await self._log_in(connection)
                    logged_in = True
                    await self._after_login(logged_in_frame)
                    await self._serve(connection)
                except _ViolationError as violation:
                    await connection.close(violation.code)
        except ConnectionClosed as closed:
            code = closed.rcvd.code if closed.rcvd is not None else None
            relay_closed_first = bool(closed.rcvd_then_sent)
            if relay_closed_first and close_action(code) is Action.STOP:
                raise _StopError(f"the relay closed the connection with {code}") from closed
        except DIAL_FAILURES:
            return logged_in
        finally:
            self._end_connection()
        return logged_in

    async def _log_in(self, connection: ClientConnection) -> LoggedIn:
        """Hello, Login and LoggedIn of section 8.1; returns the LoggedIn."""
        try:
            hello = read_server_frame(await _receive_binary(connection))
        except UnknownVersionError as unknown:
            await connection.close(NORMAL_CLOSURE)
            raise _StopError(
                f"the relay speaks protocol version {unknown.version}"
            ) from unknown
        except MalformedFrameError as error:
            raise _ViolationError(CloseCode.PROTOCOL_VIOLATION) from error
        if not isinstance(hello, Hello):
            raise _ViolationError(CloseCode.PROTOCOL_VIOLATION)

        login = self.client.sign_login(server_name=self.server_name, server_nonce=hello.nonce)
        await connection.send(ClientFrame(login=login).SerializeToString())
        logged_in = await _receive(connection)
        if not isinstance(logged_in, LoggedIn):
            raise _ViolationError(CloseCode.PROTOCOL_VIOLATION)

        self._connection = connection
        self.blob_max_bytes = logged_in.blob_max_bytes
        return logged_in

    async def _after_login(self, logged_in: LoggedIn) -> None:
        """The three steps of section 23.3, then the transfers of section 33.4."""
        await self._send_blob_deletions()
        upload = self.client.prepare_upload(
            logged_in.one_time_prekey_count, logged_in.pq_one_time_prekey_count
        )
        if upload is not None:
            frame = ClientFrame(upload_bundle=upload_frame(upload))
            await self._request(_Request(frame=frame, upload=upload))
        sent: set[bytes] = set()
        # Again until no row is new: a text committed while a Send was on its way is sent
        # here, and one committed after the last look finds the transport ready.
        while rows := [row for row in self.client.outbox() if row.message_id not in sent]:
            for outgoing in rows:
                sent.add(outgoing.message_id)
                await self._request(_Request(frame=send_frame(outgoing)))
        self.client.forget_seen_ids()
        self._ready.set()
        self.events.put_nowait(Connected())
        self._end_transfers_beyond_the_relay()
        await self._send_owed()

    async def _serve(self, connection: ClientConnection) -> None:
        while True:
            frame = await _receive(connection)
            match frame:
                case Deliver():
                    await self._deliver(connection, frame)
                case Stored():
                    if self._take(SENDS, frame.message_id) is not None:
                        self._confirm_stored(frame.message_id)
                case BundleStored():
                    request = self._take(BUNDLE_UPLOADS, b"")
                    if request is not None and request.upload is not None:
                        self.client.confirm_upload(request.upload)
                case BundleFrame():
                    request = self._take(BUNDLE_FETCHES, frame.identity)
                    if request is not None and request.bundle is not None:
                        _resolve(request.bundle, bundle_of(frame))
                case BlobStored():
                    request = self._take(BLOB_WRITES, frame.blob_id)
                    if request is not None and request.reply is not None:
                        _resolve(request.reply, frame)
                case BlobData():
                    # A FetchBlob gets its answer in the order of the frames (section 7.4),
                    # so a BlobData that names another blob answers the oldest one.
                    request = self._take(BLOB_READS, frame.blob_id + frame.uploader)
                    request = request or self._take_oldest(BLOB_READS)
                    if request is not None and request.reply is not None:
                        _resolve(request.reply, frame)
                case ErrorFrame():
                    await self._refused(connection, frame)
                case _:
                    raise _ViolationError(CloseCode.PROTOCOL_VIOLATION)

    async def _deliver(self, connection: ClientConnection, deliver: Deliver) -> None:
        delivered = Delivered(
            sender=deliver.sender, message_id=deliver.message_id, payload=deliver.payload
        )
        received = self.client.receive(delivered)
        if received.profile is not None or received.deleted:
            # Before the first await: the task of a replaced avatar or of a deleted file
            # must not write into the row that took its position.
            self._cancel_ended_downloads()
        if received.ack:
            reference = MessageRef(message_id=deliver.message_id, sender=deliver.sender)
            await connection.send(
                ClientFrame(ack=Ack(messages=[reference])).SerializeToString()
            )
        self.events.put_nowait(Incoming(sender=deliver.sender, received=received))
        self._send_owed_later()

    def _send_owed_later(self) -> None:
        """`_send_owed` in a task, so that a held request never stops the reading loop."""
        task = asyncio.create_task(self._send_owed())
        self._owed_sends.add(task)
        task.add_done_callback(self._owed_sends.discard)

    def _confirm_stored(self, message_id: bytes) -> None:
        number = self.client.sent_number(message_id)
        file = self.client.confirm_stored(message_id)
        if number is not None:
            self.events.put_nowait(Sent(number=number))
        if file is not None:
            self.events.put_nowait(_file_update(file, FileState.SENT))

    async def _refused(self, connection: ClientConnection, error: ErrorFrame) -> None:
        kinds, ref = BUNDLE_UPLOADS, b""
        if error.message_id:
            kinds, ref = SENDS, error.message_id
        elif error.blob_id and error.identity:
            kinds, ref = BLOB_READS, error.blob_id + error.identity
        elif error.blob_id:
            kinds, ref = BLOB_WRITES, error.blob_id
        elif error.identity:
            kinds, ref = BUNDLE_FETCHES, error.identity
        request = self._first(kinds, ref)
        if request is None:
            return

        if error_action(error.code) is Action.BACK_OFF:
            request.holds_others = error.code in HOLDING_CODES
            self._back_off(connection, request)
            return

        self._requests.remove(request)
        self._answered(request)
        result = _error_name(error.code)
        if request.bundle is not None:
            _resolve(request.bundle, RefusedError(result))
        elif request.reply is not None:
            _resolve(request.reply, error)
        elif request.upload is not None:
            self.events.put_nowait(Refused(result=result, contact=None))
        else:
            file = self.client.drop_refused_send(ref)
            self.events.put_nowait(
                Refused(result=result, contact=request.frame.send.recipient)
            )
            if file is not None:
                self.events.put_nowait(_file_update(file, FileState.NOT_SENT, result=result))
                await self._send_blob_deletions()

    def _back_off(self, connection: ClientConnection, request: _Request) -> None:
        request.refusals += 1
        request.waiting = True
        if request.holds_others:
            self._holders += 1
            self._unblocked.clear()
        task = asyncio.create_task(self._send_again(connection, request))
        self._back_offs.add(task)
        task.add_done_callback(self._back_offs.discard)

    async def _send_again(self, connection: ClientConnection, request: _Request) -> None:
        try:
            await asyncio.sleep(back_off_seconds(request.refusals, jitter=self.jitter))
            request.waiting = False
            request.sequence = self._next_sequence()
            with suppress(ConnectionClosed):
                await connection.send(request.frame.SerializeToString())
        finally:
            if request.holds_others:
                request.holds_others = False
                self._holders -= 1
                if self._holders == 0:
                    self._unblocked.set()

    async def _request(self, request: _Request) -> bool:
        """Sends a request on the live connection; False when there is none."""
        await self._unblocked.wait()
        connection = self._connection
        if connection is None:
            return False
        # Listed before it leaves, so that its answer always finds it.
        request.sequence = self._next_sequence()
        self._requests.append(request)
        with suppress(ConnectionClosed):
            await connection.send(request.frame.SerializeToString())
        return True

    def _first(self, kinds: frozenset[str], key: bytes) -> _Request | None:
        for request in self._requests:
            if request.answers_to(kinds, key) and not request.waiting:
                return request
        return None

    def _take(self, kinds: frozenset[str], key: bytes) -> _Request | None:
        """Removes the request that an answer matches; None means the answer is ignored."""
        request = self._first(kinds, key)
        if request is not None:
            self._requests.remove(request)
            self._answered(request)
        return request

    def _take_oldest(self, kinds: frozenset[str]) -> _Request | None:
        for request in self._requests:
            if request.frame.WhichOneof("frame") in kinds and not request.waiting:
                self._requests.remove(request)
                self._answered(request)
                return request
        return None

    def _next_sequence(self) -> int:
        self._sequence += 1
        return self._sequence

    def _answered(self, request: _Request) -> None:
        """Forgets the DeleteBlob frames that left before the request: the relay handled
        them, as it handles the frames of a connection in order (section 33.2)."""
        handled = [
            deletion
            for deletion, sent_after in self._deletions_sent.items()
            if request.sequence > sent_after
        ]
        for uploader, blob_id in handled:
            del self._deletions_sent[uploader, blob_id]
            self.client.confirm_blob_deletion(uploader, blob_id)

    async def _send_blob_deletions(self) -> None:
        """Sends the saved DeleteBlob frames that this connection has not sent; none to a
        relay without blob frames (section 30.1)."""
        connection = self._connection
        if connection is None or self.blob_max_bytes == 0:
            return
        for uploader, blob_id in self.client.blob_deletions():
            # A connection that ended while a send waited takes no more of them.
            if self._connection is not connection:
                return
            if (uploader, blob_id) in self._deletions_sent:
                continue
            self._deletions_sent[uploader, blob_id] = self._sequence
            frame = ClientFrame(delete_blob=DeleteBlob(blob_id=blob_id, uploader=uploader))
            with suppress(ConnectionClosed):
                await connection.send(frame.SerializeToString())

    def _end_transfers_beyond_the_relay(self) -> None:
        """The last row of the table of section 33.4, after a LoggedIn."""
        for upload in self.client.uploads():
            result = None
            if self.blob_max_bytes == 0:
                result = FilesUnsupportedError.result
            elif upload.length > self.blob_max_bytes:
                result = FileTooLargeError.result
            if result is None:
                continue
            self.client.give_up_upload(upload.blob_id)
            if upload.profile:
                # Owed again, the profile goes out without its avatar (section 36.2).
                self.client.owe_profile(upload.contact)
            else:
                self._report_upload(upload, FileState.NOT_SENT, result=result)

        if self.blob_max_bytes == 0 and self.received_files is not None:
            result = FilesUnsupportedError.result
            for file in self.client.downloads():
                state = self.client.fail_download(file.position, result)
                self.events.put_nowait(_file_update(file, state, result=result))

    def _start_transfers(self) -> None:
        """Starts a task for every upload and download of the store that has none."""
        if self.blob_max_bytes == 0:
            return
        for upload in self.client.uploads():
            key: TransferKey = ("upload", upload.blob_id)
            if key not in self._transfers:
                self._track(key, self._upload(upload))
        folder = self.received_files
        for file in self.client.downloads():
            key = _download_key(file)
            if key in self._transfers:
                continue
            if file.avatar:
                self._track(key, self._download(file, None))
            elif folder is not None:
                self._track(key, self._download(file, folder))

    def _cancel_ended_downloads(self) -> None:
        """Cancels the download tasks whose file the store no longer offers."""
        offered = {_download_key(file) for file in self.client.downloads()}
        for key, transfer in list(self._transfers.items()):
            if key[0] == "download" and key not in offered:
                transfer.cancel()
                del self._transfers[key]

    async def _send_owed(self) -> None:
        """Sections 36.2 and 39.5 once logged in: the owed profiles go out as Sends or as
        avatar uploads and the owed receipts as Sends, every transfer without a task gets
        one, and the saved DeleteBlob frames go out."""
        if not self._ready.is_set():
            return
        for outgoing in self.client.send_owed_profiles(blob_max_bytes=self.blob_max_bytes):
            await self._request(_Request(frame=send_frame(outgoing)))
        for outgoing in self.client.send_owed_receipts():
            await self._request(_Request(frame=send_frame(outgoing)))
        self._start_transfers()
        await self._send_blob_deletions()

    async def _expire_periodically(self) -> None:
        """Removes the messages whose timer ran out, every EXPIRY_CHECK_SECONDS."""
        while True:
            await asyncio.sleep(EXPIRY_CHECK_SECONDS)
            numbers = self.client.expire_messages()
            if numbers:
                self._cancel_ended_downloads()
                self.events.put_nowait(Expired(numbers=tuple(numbers)))
                await self._send_blob_deletions()

    def _track(self, key: TransferKey, transfer: Coroutine[None, None, None]) -> None:
        task = asyncio.create_task(_until_the_connection_ends(transfer))
        self._transfers[key] = task

        def forget(done: asyncio.Task[None]) -> None:
            if self._transfers.get(key) is done:
                del self._transfers[key]
            if done.cancelled():
                # A task cancelled before its first step never started the transfer.
                transfer.close()
            elif (error := done.exception()) is not None:
                self.events.put_nowait(TransferFailed(reason=repr(error)))

        task.add_done_callback(forget)

    async def _upload(self, upload: UploadRow) -> None:
        """Steps 3 to 5 of section 33.2. A connection that ends cancels the task, and the
        next login starts it again from the stored length (section 33.4)."""
        start = StartBlob(
            blob_id=upload.blob_id, recipient=upload.contact, length=upload.length
        )
        reply = await self._write_blob(ClientFrame(start_blob=start))
        sent_a_piece = False
        while True:
            if isinstance(reply, ErrorFrame):
                if sent_a_piece and reply.code == ErrorCode.NOT_FOUND:
                    sent_a_piece = False
                    reply = await self._write_blob(ClientFrame(start_blob=start))
                    continue
                await self._not_sent(upload, _error_name(reply.code))
                return

            stored = reply.stored_length
            if stored > upload.length:
                await self._not_sent(upload, BadBlobError.result)
                return
            self._report_upload(upload, FileState.SENDING, done=stored)
            if stored == upload.length:
                break
            piece = self.client.read_upload(upload.blob_id, stored, BLOB_CHUNK_BYTES)
            put = PutBlob(blob_id=upload.blob_id, offset=stored, data=piece)
            reply = await self._write_blob(ClientFrame(put_blob=put))
            sent_a_piece = True

        await self._send_attachment(upload)

    async def _send_attachment(self, upload: UploadRow) -> None:
        """Step 5 of section 33.2: the message of the file, after START when needed."""
        bundle = None
        try:
            if not self.client.has_session(upload.contact):
                bundle = await self.fetch_bundle(upload.contact)
            outgoing = self.client.send_attachment(upload, bundle=bundle)
        except (RefusedError, CryptoError) as error:
            await self._not_sent(upload, error.result)
            return
        await self._request(_Request(frame=send_frame(outgoing)))
        await self._send_owed()

    async def _not_sent(self, upload: UploadRow, result: str) -> None:
        self.client.give_up_upload(upload.blob_id)
        self._report_upload(upload, FileState.NOT_SENT, result=result)
        await self._send_blob_deletions()

    def _report_upload(
        self, upload: UploadRow, state: FileState, *, done: int = 0, result: str | None = None
    ) -> None:
        self.events.put_nowait(
            FileUpdate(
                contact=upload.contact,
                blob_id=upload.blob_id,
                file_name=upload.attachment.file_name,
                state=state,
                done=done,
                total=upload.length,
                result=result,
                avatar=upload.profile,
            )
        )

    async def _download(self, file: FileRow, folder: Path | None) -> None:
        """Steps 2 to 6 of section 33.3 from the bytes the store holds; `folder` is None
        for an avatar, which stays in the store (section 36.3)."""
        attachment = file.attachment
        length = blob_length(attachment.size)
        held = file.held
        self.client.begin_download(file.position)
        while held < length:
            asked = min(BLOB_CHUNK_BYTES, length - held)
            fetch = FetchBlob(
                blob_id=attachment.blob_id, uploader=file.contact, offset=held, length=asked
            )
            reply = await self._read_blob(ClientFrame(fetch_blob=fetch))
            if isinstance(reply, ErrorFrame):
                await self._not_received(file, BLOB_GONE)
                return

            is_another_range = reply.offset != held or reply.blob_id != attachment.blob_id
            is_of_another_uploader = reply.uploader != file.contact
            is_not_the_length_asked = len(reply.data) != asked
            if is_another_range or is_of_another_uploader or is_not_the_length_asked:
                await self._not_received(file, BadBlobError.result)
                return
            self.client.save_download_piece(file.position, reply.data)
            held += len(reply.data)
            self.events.put_nowait(
                _file_update(file, FileState.RECEIVING, done=held, total=length)
            )

        try:
            if folder is None:
                self.client.finish_avatar_download(file.position)
                path = None
            else:
                path = self.client.finish_download(file.position, folder)
        except (BadBlobError, NotAnImageError) as error:
            await self._not_received(file, error.result)
            return
        except OSError as error:
            failure = f"cannot write into {folder}: {error.strerror}"
            self.events.put_nowait(TransferFailed(reason=failure))
            return
        self.events.put_nowait(_file_update(file, FileState.RECEIVED, path=path))
        await self._send_blob_deletions()

    async def _not_received(self, file: FileRow, result: str) -> None:
        state = self.client.fail_download(file.position, result)
        self.events.put_nowait(_file_update(file, state, result=result))
        await self._send_blob_deletions()

    async def _write_blob(self, frame: ClientFrame) -> BlobStored | ErrorFrame:
        reply = await self._ask_blob(frame)
        if isinstance(reply, BlobData):
            raise TypeError("a BlobData answers no StartBlob or PutBlob")
        return reply

    async def _read_blob(self, frame: ClientFrame) -> BlobData | ErrorFrame:
        reply = await self._ask_blob(frame)
        if isinstance(reply, BlobStored):
            raise TypeError("a BlobStored answers no FetchBlob")
        return reply

    async def _ask_blob(self, frame: ClientFrame) -> BlobReply:
        """Sends a blob frame and waits for its answer; an Error with an action Back off is
        handled by the frame being sent again, so only a Stop comes back as an Error.

        Raises:
            _ConnectionLostError: There is no connection, or it ended before the answer.
        """
        reply: asyncio.Future[BlobReply] = asyncio.get_running_loop().create_future()
        if not await self._request(_Request(frame=frame, reply=reply)):
            raise _ConnectionLostError
        return await reply

    def _end_connection(self) -> None:
        """What section 21.4 and 23.5 ask when a connection ends with requests open."""
        for task in self._back_offs | self._owed_sends:
            task.cancel()
        for transfer in self._transfers.values():
            transfer.cancel()
        self._transfers.clear()
        for request in self._requests:
            if request.upload is not None and request.waiting:
                self.client.drop_refused_upload(request.upload)
            if request.bundle is not None:
                _resolve(request.bundle, _ConnectionLostError())
            if request.reply is not None:
                _resolve(request.reply, _ConnectionLostError())
        self._requests.clear()
        self._deletions_sent.clear()
        self._connection = None
        self._ready.clear()
        self._holders = 0
        self._unblocked.set()


async def _receive_binary(connection: ClientConnection) -> bytes:
    message = await connection.recv()
    if isinstance(message, str):
        raise _ViolationError(CloseCode.TEXT_FRAME)
    return message


async def _receive(connection: ClientConnection) -> ServerMessage:
    """The next frame after the Hello, where a second Hello is a malformed frame too."""
    try:
        return read_server_frame(await _receive_binary(connection))
    except MalformedFrameError as error:
        raise _ViolationError(CloseCode.PROTOCOL_VIOLATION) from error


def _check_bundle(bundle: BundleFrame) -> None:
    if not bundle.HasField("signed_prekey"):
        raise MalformedFrameError("the bundle has no signed prekey")
    _require_length("identity", bundle.identity, KEY_LENGTH)
    _require_length("identity_dh_key", bundle.identity_dh_key, KEY_LENGTH)
    _require_length("identity_dh_signature", bundle.identity_dh_signature, SIGNATURE_LENGTH)
    _require_length("signed_prekey.key", bundle.signed_prekey.key, KEY_LENGTH)
    _require_length(
        "signed_prekey.signature", bundle.signed_prekey.signature, SIGNATURE_LENGTH
    )
    if bundle.HasField("one_time_prekey"):
        _require_length("one_time_prekey.key", bundle.one_time_prekey.key, KEY_LENGTH)
    if bundle.HasField("pq_prekey"):
        _require_length("pq_prekey.key", bundle.pq_prekey.key, KEM_PUBLIC_KEY_LENGTH)
        _require_length("pq_prekey.signature", bundle.pq_prekey.signature, SIGNATURE_LENGTH)


def _check_deliver(deliver: Deliver) -> None:
    _require_length("message_id", deliver.message_id, MESSAGE_ID_LENGTH)
    _require_length("sender", deliver.sender, KEY_LENGTH)
    if not 1 <= len(deliver.payload) <= MAX_PAYLOAD_BYTES:
        raise MalformedFrameError(
            f"payload is {len(deliver.payload)} bytes long, not 1 to {MAX_PAYLOAD_BYTES}"
        )


def _check_error(error: ErrorFrame) -> None:
    _require_length("message_id", error.message_id, 0, MESSAGE_ID_LENGTH)
    _require_length("identity", error.identity, 0, KEY_LENGTH)
    _require_length("blob_id", error.blob_id, 0, BLOB_ID_LENGTH)
    if error.message_id and error.identity:
        raise MalformedFrameError("the error names a Send and a FetchBundle")
    if error.message_id and error.blob_id:
        raise MalformedFrameError("the error names a Send and a blob")


def _check_blob_data(data: BlobData) -> None:
    _require_length("blob_id", data.blob_id, BLOB_ID_LENGTH)
    _require_length("uploader", data.uploader, KEY_LENGTH)
    if len(data.data) > BLOB_CHUNK_BYTES:
        raise MalformedFrameError(f"data is {len(data.data)} bytes, above {BLOB_CHUNK_BYTES}")


def _file_update(
    file: FileRow,
    state: FileState,
    *,
    done: int = 0,
    total: int = 0,
    result: str | None = None,
    path: Path | None = None,
) -> FileUpdate:
    attachment: Attachment = file.attachment
    return FileUpdate(
        contact=file.contact,
        blob_id=attachment.blob_id,
        file_name=attachment.file_name,
        state=state,
        done=done,
        total=total,
        result=result,
        path=path,
        avatar=file.avatar,
    )


def _download_key(file: FileRow) -> TransferKey:
    """A download by its blob: the position of a deleted file can be taken by another."""
    return ("download", file.contact + file.attachment.blob_id)


def _error_name(code: int) -> str:
    try:
        return ErrorCode.Name(code)
    except ValueError:
        return f"error code {code}"


def _require_length(field: str, value: bytes, *lengths: int) -> None:
    if len(value) not in lengths:
        raise MalformedFrameError(f"{field} is {len(value)} bytes long, not {lengths}")


async def _until_the_connection_ends(transfer: Coroutine[None, None, None]) -> None:
    """Runs a transfer; the next login starts it again when its connection is lost."""
    with suppress(_ConnectionLostError):
        await transfer


def _resolve[T](future: asyncio.Future[T], outcome: T | Exception) -> None:
    """Settles a fetch whose caller still waits; a cancelled caller gets nothing."""
    if future.done():
        return
    if isinstance(outcome, Exception):
        future.set_exception(outcome)
    else:
        future.set_result(outcome)
