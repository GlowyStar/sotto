import asyncio
import logging
import os
from collections.abc import AsyncIterator
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
    BundleStored,
    Error,
    ErrorCode,
    FetchBundle,
    Hello,
    LoggedIn,
    Login,
    ServerFrame,
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
from sotto.relay.storage import Storage, StorageFullError

WEBSOCKET_PATH = "/ws"
HEALTH_PATH = "/healthz"
PROTOCOL_VERSION = 1


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

            async for message in connection:
                if self.logged_in.get(identity_key) is not connection:
                    # A replaced connection waits here for its close: websockets hands its
                    # frames over until the client answers, and a return would close it
                    # with 1000 before the 4001 is sent.
                    continue

                match read_frame(message):
                    case Login():
                        raise ViolationError(CloseCode.PROTOCOL_VIOLATION)
                    case UploadBundle() as upload:
                        answer = self.answer_upload(identity_key, upload)
                    case FetchBundle() as fetch:
                        answer = self.answer_fetch(fetch)
                await connection.send(answer.SerializeToString())
        finally:
            if self.logged_in.get(identity_key) is connection:
                del self.logged_in[identity_key]

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

    def answer_fetch(self, fetch: FetchBundle) -> ServerFrame:
        """Runs steps 2 to 4 of section 9.2."""
        bundle = self.storage.fetch_bundle(fetch.identity)
        if bundle is None:
            return ServerFrame(error=Error(code=ErrorCode.NOT_FOUND, identity=fetch.identity))
        return ServerFrame(bundle=bundle)


@asynccontextmanager
async def serve_relay(settings: Settings) -> AsyncIterator[Server]:
    """Serves until the block ends, then closes the database once every handler returned."""
    storage = Storage(settings.database, max_pages=settings.max_pages)
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
        storage.close()
