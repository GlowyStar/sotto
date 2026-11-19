import asyncio
import logging
import os
import time
from collections.abc import AsyncIterator, Callable
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from enum import IntEnum
from http import HTTPStatus

from websockets.asyncio.server import Server, ServerConnection, serve
from websockets.exceptions import ConnectionClosed
from websockets.http11 import Request, Response
from websockets.typing import Data

from sotto.crypto.identity import (
    NONCE_LENGTH,
    BadBundleError,
    IdentityKeyMismatchError,
    LoginRefusedError,
    verify_identity_dh_key,
    verify_login,
    verify_pq_prekey,
    verify_signed_prekey,
)
from sotto.proto.sotto_pb2 import (
    Ack,
    BlobData,
    BlobStored,
    BundleStored,
    DeleteBlob,
    Error,
    ErrorCode,
    FetchBlob,
    FetchBundle,
    Hello,
    LoggedIn,
    Login,
    PutBlob,
    Send,
    ServerFrame,
    StartBlob,
    Stored,
    UploadBundle,
)
from sotto.relay.frames import (
    MAX_FRAME_BYTES,
    MalformedFrameError,
    ParsedFrame,
    parse_client_frame,
)
from sotto.relay.limits import TokenBuckets
from sotto.relay.logs import ConnectionLogger
from sotto.relay.metrics import Metrics
from sotto.relay.settings import Settings
from sotto.relay.storage import (
    BlobNotFoundError,
    BlobTooLargeError,
    Fetched,
    QueueFullError,
    QuotaFullError,
    Storage,
    StorageFullError,
    UnknownRecipientError,
)

logger = logging.getLogger(__name__)

WEBSOCKET_PATH = "/ws"
HEALTH_PATH = "/healthz"
METRICS_PATH = "/metrics"
PROTOCOL_VERSION = 1
# The code that websockets closes with when a handler fails (section 11.3).
INTERNAL_ERROR = 1011

type AnsweredFrame = UploadBundle | FetchBundle | Send | StartBlob | PutBlob | FetchBlob


class CloseCode(IntEnum):
    """The close codes of docs/protocol.md, section 11.3, under the names of its table."""

    SHUTDOWN = 1001
    TEXT_FRAME = 1003
    PROTOCOL_VIOLATION = 1008
    FRAME_TOO_BIG = 1009
    LOGIN_REFUSED = 3000
    LOGIN_TIMEOUT = 3008
    REPLACED = 4001


class ViolationError(Exception):
    """The client broke a rule that closes its connection with `code`."""

    def __init__(self, code: CloseCode) -> None:
        super().__init__(code.name)
        self.code = code


def route_request(connection: ServerConnection, request: Request) -> Response | None:
    if request.path == WEBSOCKET_PATH:
        return None
    if request.path == HEALTH_PATH:
        return connection.respond(HTTPStatus.OK, "OK\n")
    return connection.respond(HTTPStatus.NOT_FOUND, "Not found\n")


def read_frame(message: Data) -> ParsedFrame:
    """Applies sections 6.2 and 7.3 to one WebSocket message, in every state."""
    if isinstance(message, str):
        raise ViolationError(CloseCode.TEXT_FRAME)

    try:
        return parse_client_frame(message)
    except MalformedFrameError as error:
        raise ViolationError(CloseCode.PROTOCOL_VIOLATION) from error


async def close_connection(connection: ServerConnection, code: CloseCode) -> None:
    connection.logger.info("closing with %d %s", code, code.name)
    await connection.close(code)


def refusal(frame: AnsweredFrame, code: ErrorCode) -> ServerFrame:
    """Builds the Error for a refused frame with the key fields of sections 7.16 and 30.8."""
    match frame:
        case Send():
            return ServerFrame(error=Error(code=code, message_id=frame.message_id))
        case FetchBundle():
            return ServerFrame(error=Error(code=code, identity=frame.identity))
        case UploadBundle():
            return ServerFrame(error=Error(code=code))
        case StartBlob() | PutBlob():
            return ServerFrame(error=Error(code=code, blob_id=frame.blob_id))
        case FetchBlob():
            error = Error(code=code, blob_id=frame.blob_id, identity=frame.uploader)
            return ServerFrame(error=error)


def result_of(answer: ServerFrame) -> str:
    """Names an answer for the metrics: the frame it is, or the code of its Error."""
    if answer.HasField("error"):
        return ErrorCode.Name(answer.error.code)
    return str(answer.WhichOneof("frame"))


async def refuse_connection(connection: ServerConnection) -> None:
    """The handler of the metrics listener, whose answers never open a connection."""


@dataclass(frozen=True, slots=True)
class Listeners:
    websocket: Server
    metrics: Server | None


class Relay:
    """What the connections of one relay process share."""

    def __init__(
        self,
        settings: Settings,
        storage: Storage,
        *,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings
        self.storage = storage
        self.logged_in: dict[bytes, ServerConnection] = {}
        # Set for the live connection of an identity when a message to it is stored.
        self.wakeups: dict[bytes, asyncio.Event] = {}
        self.closings: set[asyncio.Task[None]] = set()
        self.frame_buckets = TokenBuckets(
            settings.frame_bucket_size, settings.frame_refill_seconds, monotonic
        )
        self.handout_buckets = TokenBuckets(
            settings.handout_bucket_size, settings.handout_refill_seconds, monotonic
        )
        self.metrics = Metrics()
        self.open_connections = 0

    async def handle_connection(self, connection: ServerConnection) -> None:
        self.open_connections += 1
        try:
            identity_key = await self.log_in(connection)
            await self.serve_logged_in(connection, identity_key)
        except ConnectionClosed:
            # Raised further, websockets would log the end of a connection as a failure of
            # the handler.
            return
        except ViolationError as violation:
            await close_connection(connection, violation.code)
        finally:
            self.open_connections -= 1

    def answer_metrics(self, connection: ServerConnection, request: Request) -> Response:
        """Answers a request to the metrics listener, which never upgrades a connection."""
        if request.path != METRICS_PATH:
            return connection.respond(HTTPStatus.NOT_FOUND, "Not found\n")
        gauges = {
            "sotto_connections_open": self.open_connections,
            "sotto_database_bytes": self.storage.size_bytes(),
            "sotto_blob_bytes": self.storage.blob_bytes(),
        }
        return connection.respond(HTTPStatus.OK, self.metrics.render(gauges))

    async def log_in(self, connection: ServerConnection) -> bytes:
        """Runs steps 1 to 5 of section 8.3 and returns the identity key that logged in."""
        nonce = os.urandom(NONCE_LENGTH)
        hello = ServerFrame(hello=Hello(version=PROTOCOL_VERSION, nonce=nonce))
        await connection.send(hello.SerializeToString())

        try:
            async with asyncio.timeout(self.settings.login_deadline_seconds):
                message = await connection.recv()
        except TimeoutError as error:
            raise ViolationError(CloseCode.LOGIN_TIMEOUT) from error

        login = read_frame(message)
        if not isinstance(login, Login):
            raise ViolationError(CloseCode.PROTOCOL_VIOLATION)
        try:
            verify_login(
                login.identity_key,
                signature=login.signature,
                server_name=self.settings.name,
                server_nonce=nonce,
                client_nonce=login.client_nonce,
            )
        except LoginRefusedError as error:
            raise ViolationError(CloseCode.LOGIN_REFUSED) from error
        return login.identity_key

    async def serve_logged_in(self, connection: ServerConnection, identity_key: bytes) -> None:
        """Runs steps 6 and 7 of section 8.3, then handles the frames of the connection."""
        older = self.logged_in.get(identity_key)
        self.logged_in[identity_key] = connection
        wakeup = self.wakeups[identity_key] = asyncio.Event()
        if older is not None:
            # Not awaited, because an older connection that does not answer the close would
            # hold up this one.
            closing = asyncio.create_task(close_connection(older, CloseCode.REPLACED))
            self.closings.add(closing)
            closing.add_done_callback(self.closings.discard)

        try:
            connection.logger.info("logged in")
            self.metrics.count("sotto_logins_total")
            logged_in = ServerFrame(
                logged_in=LoggedIn(
                    one_time_prekey_count=self.storage.count_one_time_prekeys(identity_key),
                    blob_max_bytes=self.settings.blob_max_bytes,
                    pq_one_time_prekey_count=self.storage.count_pq_one_time_prekeys(
                        identity_key
                    ),
                )
            )
            await connection.send(logged_in.SerializeToString())

            delivery = asyncio.create_task(
                self.deliver_queue(connection, identity_key, wakeup)
            )
            try:
                await self.handle_frames(connection, identity_key)
            finally:
                delivery.cancel()
                if delivery.done():
                    # Raises what made the delivery fail, as the failure of the handler.
                    delivery.result()
        finally:
            if self.logged_in.get(identity_key) is connection:
                del self.logged_in[identity_key]
                del self.wakeups[identity_key]

    async def handle_frames(self, connection: ServerConnection, identity_key: bytes) -> None:
        """Answers the frames of a logged-in connection one at a time, in their order."""
        async for message in connection:
            if self.logged_in.get(identity_key) is not connection:
                # A replaced connection waits here for its close: websockets hands its
                # frames over until the client answers, and a return would close it with
                # 1000 before the 4001 is sent.
                continue

            frame = read_frame(message)
            if isinstance(frame, Login):
                raise ViolationError(CloseCode.PROTOCOL_VIOLATION)
            if isinstance(frame, Ack):
                acked = self.storage.delete_messages(identity_key, frame.messages)
                self.metrics.count("sotto_messages_acked_total", acked)
                self.metrics.count("sotto_frames_total", type="Ack", result="none")
                continue
            if isinstance(frame, DeleteBlob):
                self.delete_blob(identity_key, frame)
                self.metrics.count("sotto_frames_total", type="DeleteBlob", result="none")
                continue

            # A token per piece would hold a large blob to a frame a second (section 31.2).
            takes_no_token = isinstance(frame, PutBlob | FetchBlob)
            if takes_no_token or self.frame_buckets.take(identity_key):
                answer = self.answer_request(identity_key, frame)
            else:
                self.metrics.count("sotto_limit_refusals_total", kind="frame_bucket")
                answer = refusal(frame, ErrorCode.RATE_LIMITED)
            self.metrics.count(
                "sotto_frames_total", type=type(frame).__name__, result=result_of(answer)
            )
            await connection.send(answer.SerializeToString())

    def answer_request(self, identity_key: bytes, frame: AnsweredFrame) -> ServerFrame:
        """Answers a frame that passed the frame bucket of the identity or needs no token."""
        match frame:
            case UploadBundle():
                return self.answer_upload(identity_key, frame)
            case FetchBundle():
                return self.answer_fetch(frame)
            case Send():
                return self.answer_send(identity_key, frame)
            case StartBlob():
                return self.answer_start_blob(identity_key, frame)
            case PutBlob():
                return self.answer_put_blob(identity_key, frame)
            case FetchBlob():
                return self.answer_fetch_blob(identity_key, frame)

    async def deliver_queue(
        self, connection: ServerConnection, identity_key: bytes, wakeup: asyncio.Event
    ) -> None:
        """Sends the queue of the identity as Deliver frames until the connection is replaced.

        The queue goes out oldest first, then every message as it is stored; a message goes
        out once on a connection and stays in the queue until its Ack (section 10.4).
        """
        after = 0
        try:
            while True:
                queued = self.storage.next_message(identity_key, after=after)
                if queued is None:
                    # No await between the read and the clear, so no message is missed.
                    wakeup.clear()
                    await wakeup.wait()
                    continue

                if self.logged_in.get(identity_key) is not connection:
                    return
                after, deliver = queued
                await connection.send(ServerFrame(deliver=deliver).SerializeToString())
                self.metrics.count("sotto_messages_delivered_total")
        except ConnectionClosed:
            return
        except Exception:
            # The client would otherwise wait on a connection that delivers nothing. Not
            # awaited, so that the failure reaches the handler before the close ends it.
            closing = asyncio.create_task(connection.close(INTERNAL_ERROR))
            self.closings.add(closing)
            closing.add_done_callback(self.closings.discard)
            raise

    def answer_upload(self, identity_key: bytes, upload: UploadBundle) -> ServerFrame:
        """Runs steps 2 to 5 of section 9.1 for the identity of the connection."""
        signed_prekey = upload.signed_prekey
        try:
            verify_identity_dh_key(
                identity_key,
                identity_dh_key=upload.identity_dh_key,
                signature=upload.identity_dh_signature,
            )
            verify_signed_prekey(
                identity_key,
                signed_prekey=signed_prekey.key,
                signature=signed_prekey.signature,
            )
            pq_prekeys = list(upload.pq_one_time_prekeys)
            if upload.HasField("pq_prekey"):
                pq_prekeys.append(upload.pq_prekey)
            for pq_prekey in pq_prekeys:
                verify_pq_prekey(
                    identity_key, pq_prekey=pq_prekey.key, signature=pq_prekey.signature
                )
            counts = self.storage.store_bundle(
                identity_key,
                upload,
                cap=self.settings.one_time_prekey_cap,
                pq_cap=self.settings.pq_one_time_prekey_cap,
            )
        except BadBundleError:
            return ServerFrame(error=Error(code=ErrorCode.BAD_BUNDLE))
        except IdentityKeyMismatchError:
            return ServerFrame(error=Error(code=ErrorCode.IDENTITY_KEY_MISMATCH))
        except StorageFullError:
            return ServerFrame(error=Error(code=ErrorCode.STORAGE_FULL))
        stored = BundleStored(
            one_time_prekey_count=counts.one_time, pq_one_time_prekey_count=counts.pq_one_time
        )
        return ServerFrame(bundle_stored=stored)

    def answer_send(self, sender: bytes, send: Send) -> ServerFrame:
        """Runs steps 2 to 6 of section 10.2; the recipient's delivery sends the message."""
        try:
            is_new = self.storage.store_message(
                sender,
                send,
                max_messages=self.settings.queue_max_messages,
                max_bytes=self.settings.queue_max_bytes,
            )
        except UnknownRecipientError:
            code = ErrorCode.UNKNOWN_RECIPIENT
        except QueueFullError:
            self.metrics.count("sotto_limit_refusals_total", kind="queue")
            code = ErrorCode.QUEUE_FULL
        except StorageFullError:
            code = ErrorCode.STORAGE_FULL
        else:
            if is_new:
                self.metrics.count("sotto_messages_stored_total")
            wakeup = self.wakeups.get(send.recipient)
            if wakeup is not None:
                wakeup.set()
            return ServerFrame(stored=Stored(message_id=send.message_id))
        return ServerFrame(error=Error(code=code, message_id=send.message_id))

    def answer_fetch(self, fetch: FetchBundle) -> ServerFrame:
        """Runs steps 2 to 4 of section 9.2, with the handout of section 9.3."""
        target = fetch.identity
        if self.handout_buckets.has_token(target):
            fetched = self.storage.fetch_bundle(target)
        else:
            self.metrics.count("sotto_limit_refusals_total", kind="handout_bucket")
            bundle = self.storage.read_bundle(target)
            fetched = None if bundle is None else Fetched(bundle=bundle, handed_out=False)
        if fetched is None:
            return ServerFrame(error=Error(code=ErrorCode.NOT_FOUND, identity=target))

        bundle = fetched.bundle
        if fetched.handed_out:
            self.handout_buckets.take(target)
        has_one_time_prekey = bundle.HasField("one_time_prekey")
        handed_out = "yes" if has_one_time_prekey else "no"
        self.metrics.count("sotto_bundle_fetches_total", one_time_prekey=handed_out)
        return ServerFrame(bundle=bundle)

    def answer_start_blob(self, uploader: bytes, start: StartBlob) -> ServerFrame:
        """Runs steps 2 to 7 of section 31.1 for the identity of the connection."""
        try:
            started = self.storage.start_blob(
                uploader,
                start,
                max_bytes=self.settings.blob_max_bytes,
                quota_bytes=self.settings.blob_quota_bytes,
            )
        except BlobTooLargeError:
            code = ErrorCode.BLOB_TOO_LARGE
        except UnknownRecipientError:
            code = ErrorCode.UNKNOWN_RECIPIENT
        except QuotaFullError:
            self.metrics.count("sotto_limit_refusals_total", kind="blob_quota")
            code = ErrorCode.QUOTA_FULL
        except StorageFullError:
            code = ErrorCode.STORAGE_FULL
        else:
            if started.is_new:
                self.metrics.count("sotto_blobs_started_total")
            stored = BlobStored(blob_id=start.blob_id, stored_length=started.stored_length)
            return ServerFrame(blob_stored=stored)
        return refusal(start, code)

    def answer_put_blob(self, uploader: bytes, put: PutBlob) -> ServerFrame:
        """Runs section 31.2 for the identity of the connection."""
        try:
            done = self.storage.put_blob(uploader, put)
        except BlobNotFoundError:
            code = ErrorCode.NOT_FOUND
        except BlobTooLargeError:
            code = ErrorCode.BLOB_TOO_LARGE
        except StorageFullError:
            code = ErrorCode.STORAGE_FULL
        else:
            self.metrics.count("sotto_blob_bytes_stored_total", done.appended)
            if done.completes:
                self.metrics.count("sotto_blobs_completed_total")
            stored = BlobStored(blob_id=put.blob_id, stored_length=done.stored_length)
            return ServerFrame(blob_stored=stored)
        return refusal(put, code)

    def answer_fetch_blob(self, recipient: bytes, fetch: FetchBlob) -> ServerFrame:
        """Runs section 31.3 for the identity of the connection."""
        data = self.storage.fetch_blob(recipient, fetch)
        if data is None:
            return refusal(fetch, ErrorCode.NOT_FOUND)

        self.metrics.count("sotto_blob_bytes_fetched_total", len(data))
        blob_data = BlobData(
            blob_id=fetch.blob_id, uploader=fetch.uploader, offset=fetch.offset, data=data
        )
        return ServerFrame(blob_data=blob_data)

    def delete_blob(self, identity_key: bytes, delete: DeleteBlob) -> None:
        """Runs section 31.4: deletes the blob when the identity may, else does nothing."""
        if self.storage.delete_blob(identity_key, delete):
            by = "uploader" if delete.uploader == identity_key else "recipient"
            self.metrics.count("sotto_blobs_deleted_total", by=by)


async def sweep_periodically(relay: Relay) -> None:
    """Sweeps the database every sweep interval until it is cancelled (section 13.2).

    Each sweep also forgets the token buckets that are full again (section 12.2).
    """
    settings = relay.settings
    while True:
        await asyncio.sleep(settings.sweep_interval_seconds)
        relay.frame_buckets.forget_full()
        relay.handout_buckets.forget_full()
        try:
            swept = relay.storage.sweep(
                ttl_seconds=settings.message_ttl_seconds,
                blob_ttl_seconds=settings.blob_ttl_seconds,
            )
        except Exception:
            # The next sweep can succeed, and a relay that stopped sweeping would keep
            # deleted messages in its files without a sign.
            logger.exception("the sweep failed")
            continue
        relay.metrics.count("sotto_messages_expired_total", swept.messages)
        relay.metrics.count("sotto_blobs_expired_total", swept.blobs)
        if swept.messages:
            logger.info("the sweep deleted %d expired messages", swept.messages)
        if swept.blobs:
            logger.info("the sweep deleted %d expired blobs", swept.blobs)


@asynccontextmanager
async def serve_relay(
    settings: Settings,
    *,
    clock: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
) -> AsyncIterator[Listeners]:
    """Serves until the block ends, then closes the database once every handler returned.

    The sweep runs from the start and stops before the database closes. The metrics
    listener runs only when `settings.metrics_port` is set.
    """
    storage = Storage(settings.database, max_pages=settings.max_pages, clock=clock)
    relay = Relay(settings, storage, monotonic=monotonic)
    sweeping = asyncio.create_task(sweep_periodically(relay))
    connection_logger = ConnectionLogger(logging.getLogger("websockets.server"))
    try:
        async with AsyncExitStack() as servers:
            websocket = await servers.enter_async_context(
                serve(
                    relay.handle_connection,
                    settings.host,
                    settings.port,
                    process_request=route_request,
                    compression=None,
                    server_header=None,
                    max_size=MAX_FRAME_BYTES,
                    logger=connection_logger,
                )
            )
            metrics = None
            if settings.metrics_port is not None:
                metrics = await servers.enter_async_context(
                    serve(
                        refuse_connection,
                        settings.host,
                        settings.metrics_port,
                        process_request=relay.answer_metrics,
                        server_header=None,
                        logger=connection_logger,
                    )
                )
            yield Listeners(websocket, metrics)
    finally:
        # The task waits only in its sleep, so once cancelled it touches the database no more.
        sweeping.cancel()
        storage.close()
