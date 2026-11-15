import asyncio
import logging
import os
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
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
    verify_signed_prekey,
)
from sotto.proto.sotto_pb2 import (
    Ack,
    BundleStored,
    Error,
    ErrorCode,
    FetchBundle,
    Hello,
    LoggedIn,
    Login,
    Send,
    ServerFrame,
    Stored,
    UploadBundle,
)
from sotto.relay.frames import (
    MAX_FRAME_BYTES,
    MalformedFrameError,
    ParsedFrame,
    parse_client_frame,
)
from sotto.relay.logs import ConnectionLogger
from sotto.relay.settings import Settings
from sotto.relay.storage import Storage, StorageFullError, UnknownRecipientError

logger = logging.getLogger(__name__)

WEBSOCKET_PATH = "/ws"
HEALTH_PATH = "/healthz"
PROTOCOL_VERSION = 1
# The code that websockets closes with when a handler fails (section 11.3).
INTERNAL_ERROR = 1011


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


class Relay:
    """What the connections of one relay process share."""

    def __init__(self, settings: Settings, storage: Storage) -> None:
        self.settings = settings
        self.storage = storage
        self.logged_in: dict[bytes, ServerConnection] = {}
        # Set for the live connection of an identity when a message to it is stored.
        self.wakeups: dict[bytes, asyncio.Event] = {}
        self.closings: set[asyncio.Task[None]] = set()

    async def handle_connection(self, connection: ServerConnection) -> None:
        try:
            identity_key = await self.log_in(connection)
            await self.serve_logged_in(connection, identity_key)
        except ConnectionClosed:
            # Raised further, websockets would log the end of a connection as a failure of
            # the handler.
            return
        except ViolationError as violation:
            await close_connection(connection, violation.code)

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
            count = self.storage.count_one_time_prekeys(identity_key)
            logged_in = ServerFrame(logged_in=LoggedIn(one_time_prekey_count=count))
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

            match read_frame(message):
                case Login():
                    raise ViolationError(CloseCode.PROTOCOL_VIOLATION)
                case UploadBundle() as upload:
                    answer = self.answer_upload(identity_key, upload)
                case FetchBundle() as fetch:
                    answer = self.answer_fetch(fetch)
                case Send() as send:
                    answer = self.answer_send(identity_key, send)
                case Ack() as ack:
                    self.storage.delete_messages(identity_key, ack.messages)
                    continue
            await connection.send(answer.SerializeToString())

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
            count = self.storage.store_bundle(
                identity_key, upload, cap=self.settings.one_time_prekey_cap
            )
        except BadBundleError:
            return ServerFrame(error=Error(code=ErrorCode.BAD_BUNDLE))
        except IdentityKeyMismatchError:
            return ServerFrame(error=Error(code=ErrorCode.IDENTITY_KEY_MISMATCH))
        except StorageFullError:
            return ServerFrame(error=Error(code=ErrorCode.STORAGE_FULL))
        return ServerFrame(bundle_stored=BundleStored(one_time_prekey_count=count))

    def answer_send(self, sender: bytes, send: Send) -> ServerFrame:
        """Runs steps 2 to 6 of section 10.2; the recipient's delivery sends the message."""
        try:
            self.storage.store_message(sender, send)
        except UnknownRecipientError:
            code = ErrorCode.UNKNOWN_RECIPIENT
        except StorageFullError:
            code = ErrorCode.STORAGE_FULL
        else:
            wakeup = self.wakeups.get(send.recipient)
            if wakeup is not None:
                wakeup.set()
            return ServerFrame(stored=Stored(message_id=send.message_id))
        return ServerFrame(error=Error(code=code, message_id=send.message_id))

    def answer_fetch(self, fetch: FetchBundle) -> ServerFrame:
        """Runs steps 2 to 4 of section 9.2."""
        bundle = self.storage.fetch_bundle(fetch.identity)
        if bundle is None:
            return ServerFrame(error=Error(code=ErrorCode.NOT_FOUND, identity=fetch.identity))
        return ServerFrame(bundle=bundle)


async def sweep_periodically(storage: Storage, settings: Settings) -> None:
    """Sweeps the database every sweep interval until it is cancelled (section 13.2)."""
    while True:
        await asyncio.sleep(settings.sweep_interval_seconds)
        try:
            expired = storage.sweep(ttl_seconds=settings.message_ttl_seconds)
        except Exception:
            # The next sweep can succeed, and a relay that stopped sweeping would keep
            # deleted messages in its files without a sign.
            logger.exception("the sweep failed")
            continue
        if expired:
            logger.info("the sweep deleted %d expired messages", expired)


@asynccontextmanager
async def serve_relay(
    settings: Settings, *, clock: Callable[[], float] = time.time
) -> AsyncIterator[Server]:
    """Serves until the block ends, then closes the database once every handler returned.

    The sweep runs from the start and stops before the database closes.
    """
    storage = Storage(settings.database, max_pages=settings.max_pages, clock=clock)
    sweeping = asyncio.create_task(sweep_periodically(storage, settings))
    try:
        relay = Relay(settings, storage)
        async with serve(
            relay.handle_connection,
            settings.host,
            settings.port,
            process_request=route_request,
            compression=None,
            server_header=None,
            max_size=MAX_FRAME_BYTES,
            logger=ConnectionLogger(logging.getLogger("websockets.server")),
        ) as server:
            yield server
    finally:
        # The task waits only in its sleep, so once cancelled it touches the database no more.
        sweeping.cancel()
        storage.close()
