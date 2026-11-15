"""The client transport of docs/protocol.md, section 23, over the session layer.

`Transport` dials the relay, logs in, runs the steps after the LoggedIn and serves the
frames of the relay until the connection ends; it reconnects or stops as section 11 says.
It only moves frames: every rule of a message is a method of `Client`, which commits before
it answers. The SQLite work of `Client` runs on the thread of the event loop.
"""

import asyncio
import ipaddress
import re
import secrets
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

from google.protobuf.message import DecodeError
from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import ConnectionClosed, InvalidHandshake

from sotto.client.envelope import encode_text
from sotto.client.session import Client, Delivered, Outgoing, PrekeyUpload, Received
from sotto.crypto.identity import (
    KEY_LENGTH,
    NONCE_LENGTH,
    SIGNATURE_LENGTH,
    Bundle,
    OneTimePrekey,
    SignedPrekey,
)
from sotto.proto.sotto_pb2 import (
    Ack,
    BundleStored,
    ClientFrame,
    Deliver,
    ErrorCode,
    FetchBundle,
    Hello,
    LoggedIn,
    MessageRef,
    Send,
    ServerFrame,
    Stored,
    UploadBundle,
)
from sotto.proto.sotto_pb2 import Bundle as BundleFrame
from sotto.proto.sotto_pb2 import Error as ErrorFrame
from sotto.proto.sotto_pb2 import OneTimePrekey as OneTimePrekeyFrame
from sotto.proto.sotto_pb2 import SignedPrekey as SignedPrekeyFrame
from sotto.relay.frames import MAX_FRAME_BYTES, MAX_PAYLOAD_BYTES, MESSAGE_ID_LENGTH
from sotto.relay.server import CloseCode

RELAY_PROTOCOL_VERSION = 1
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

type ServerMessage = (
    Hello | LoggedIn | BundleStored | BundleFrame | Stored | Deliver | ErrorFrame
)
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


type Event = Connected | Incoming | Refused | Retrying | Stopped


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
        case _:
            raise MalformedFrameError("no frame of the schema is set")


def upload_frame(upload: PrekeyUpload) -> UploadBundle:
    prekey = upload.signed_prekey
    signed = SignedPrekeyFrame(id=prekey.id, key=prekey.key, signature=prekey.signature)
    return UploadBundle(
        identity_dh_key=upload.identity_dh_key,
        identity_dh_signature=upload.identity_dh_signature,
        signed_prekey=signed,
        one_time_prekeys=[
            OneTimePrekeyFrame(id=prekey.id, key=prekey.key)
            for prekey in upload.one_time_prekeys
        ],
    )


def bundle_of(frame: BundleFrame) -> Bundle:
    extra = None
    if frame.HasField("one_time_prekey"):
        handed = frame.one_time_prekey
        extra = OneTimePrekey(id=handed.id, key=handed.key)
    prekey = frame.signed_prekey
    signed = SignedPrekey(id=prekey.id, key=prekey.key, signature=prekey.signature)
    return Bundle(
        identity=frame.identity,
        identity_dh_key=frame.identity_dh_key,
        identity_dh_signature=frame.identity_dh_signature,
        signed_prekey=signed,
        one_time_prekey=extra,
    )


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
    """A frame that waits for its answer on the connection that sent it."""

    frame: ClientFrame
    upload: PrekeyUpload | None = None
    bundle: asyncio.Future[Bundle] | None = None
    refusals: int = 0
    waiting: bool = False
    holds_others: bool = False

    def answers_to(self, kind: str, key: bytes) -> bool:
        match self.frame.WhichOneof("frame"):
            case "send":
                own_key = self.frame.send.message_id
            case "fetch_bundle":
                own_key = self.frame.fetch_bundle.identity
            case _:
                own_key = b""
        return self.frame.WhichOneof("frame") == kind and own_key == key


class Transport:
    """The connection of one client to its relay.

    Args:
        client: The session layer of the identity.
        url: The URL of the relay, dialed as given (section 23.1).
        insecure: The override that allows a ws URL to a host that is not a loopback host.
        jitter: Chooses a number evenly between 0 and its argument (sections 23.4, 23.5).

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
    ) -> None:
        self.server_name = server_name_of(url, insecure=insecure)
        self.client = client
        self.url = url
        self.jitter = jitter
        self.events: asyncio.Queue[Event] = asyncio.Queue()
        self._connection: ClientConnection | None = None
        # Set once the steps of section 23.3 are done: no Send of the user precedes them.
        self._ready = asyncio.Event()
        self._unblocked = asyncio.Event()
        self._unblocked.set()
        self._holders = 0
        self._requests: list[_Request] = []
        self._back_offs: set[asyncio.Task[None]] = set()

    async def run(self) -> None:
        """Serves connections until an action Stop, which it puts as `Stopped` in `events`.

        A Retry waits by the schedule of section 23.4. Cancel the task to stop the client.
        """
        self.client.delete_expired_prekeys()
        attempt = 0
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

    async def send_text(self, contact: bytes, text: str) -> None:
        """Commits a text to the outbox and sends it; a Send without a Stored is sent
        again after the next login.

        A contact without a session gets its bundle fetched first, which waits for a login.

        Raises:
            TextTooLongError: Before any frame.
            RefusedError: The relay refused the FetchBundle with a Stop.
            CryptoError: `Client.send_text` failed with the result that it names.
        """
        encode_text(text)
        bundle = None
        if not self.client.has_session(contact):
            bundle = await self.fetch_bundle(contact)
        outgoing = self.client.send_text(contact, text, bundle=bundle)
        if self._ready.is_set():
            await self._request(_Request(frame=send_frame(outgoing)))

    async def reset_session(self, contact: bytes) -> int:
        """L2 of section 20.6 with a fresh bundle; returns the GAP of the session that left."""
        bundle = await self.fetch_bundle(contact)
        return self.client.start_session(contact, bundle)

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
                    one_time_prekey_count = await self._log_in(connection)
                    logged_in = True
                    await self._after_login(one_time_prekey_count)
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

    async def _log_in(self, connection: ClientConnection) -> int:
        """Hello, Login and LoggedIn of section 8.1; returns the count of the LoggedIn."""
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
        return logged_in.one_time_prekey_count

    async def _after_login(self, one_time_prekey_count: int) -> None:
        """The three steps of section 23.3."""
        upload = self.client.prepare_upload(one_time_prekey_count)
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

    async def _serve(self, connection: ClientConnection) -> None:
        while True:
            frame = await _receive(connection)
            match frame:
                case Deliver():
                    await self._deliver(connection, frame)
                case Stored():
                    if self._take("send", frame.message_id) is not None:
                        self.client.confirm_stored(frame.message_id)
                case BundleStored():
                    request = self._take("upload_bundle", b"")
                    if request is not None and request.upload is not None:
                        self.client.confirm_upload(request.upload)
                case BundleFrame():
                    request = self._take("fetch_bundle", frame.identity)
                    if request is not None and request.bundle is not None:
                        _resolve(request.bundle, bundle_of(frame))
                case ErrorFrame():
                    self._refused(connection, frame)
                case _:
                    raise _ViolationError(CloseCode.PROTOCOL_VIOLATION)

    async def _deliver(self, connection: ClientConnection, deliver: Deliver) -> None:
        delivered = Delivered(
            sender=deliver.sender, message_id=deliver.message_id, payload=deliver.payload
        )
        received = self.client.receive(delivered)
        if received.ack:
            reference = MessageRef(message_id=deliver.message_id, sender=deliver.sender)
            await connection.send(
                ClientFrame(ack=Ack(messages=[reference])).SerializeToString()
            )
        self.events.put_nowait(Incoming(sender=deliver.sender, received=received))

    def _refused(self, connection: ClientConnection, error: ErrorFrame) -> None:
        kind = "upload_bundle"
        if error.message_id:
            kind = "send"
        elif error.identity:
            kind = "fetch_bundle"
        ref = error.message_id or error.identity
        request = self._first(kind, ref)
        if request is None:
            return

        if error_action(error.code) is Action.BACK_OFF:
            request.holds_others = error.code in HOLDING_CODES
            self._back_off(connection, request)
            return

        self._requests.remove(request)
        result = _error_name(error.code)
        if request.bundle is not None:
            _resolve(request.bundle, RefusedError(result))
        elif request.upload is not None:
            self.events.put_nowait(Refused(result=result, contact=None))
        else:
            self.client.drop_refused_send(ref)
            self.events.put_nowait(
                Refused(result=result, contact=request.frame.send.recipient)
            )

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
        self._requests.append(request)
        with suppress(ConnectionClosed):
            await connection.send(request.frame.SerializeToString())
        return True

    def _first(self, kind: str, key: bytes) -> _Request | None:
        for request in self._requests:
            if request.answers_to(kind, key) and not request.waiting:
                return request
        return None

    def _take(self, kind: str, key: bytes) -> _Request | None:
        """Removes the request that an answer matches; None means the answer is ignored."""
        request = self._first(kind, key)
        if request is not None:
            self._requests.remove(request)
        return request

    def _end_connection(self) -> None:
        """What section 21.4 and 23.5 ask when a connection ends with requests open."""
        for task in self._back_offs:
            task.cancel()
        for request in self._requests:
            if request.upload is not None and request.waiting:
                self.client.drop_refused_upload(request.upload)
            if request.bundle is not None:
                _resolve(request.bundle, _ConnectionLostError())
        self._requests.clear()
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
    if error.message_id and error.identity:
        raise MalformedFrameError("the error names a Send and a FetchBundle")


def _error_name(code: int) -> str:
    try:
        return ErrorCode.Name(code)
    except ValueError:
        return f"error code {code}"


def _require_length(field: str, value: bytes, *lengths: int) -> None:
    if len(value) not in lengths:
        raise MalformedFrameError(f"{field} is {len(value)} bytes long, not {lengths}")


def _resolve(future: asyncio.Future[Bundle], outcome: Bundle | Exception) -> None:
    """Settles a fetch whose caller still waits; a cancelled caller gets nothing."""
    if future.done():
        return
    if isinstance(outcome, Exception):
        future.set_exception(outcome)
    else:
        future.set_result(outcome)
