import asyncio
import logging
import os
from enum import IntEnum
from http import HTTPStatus

from websockets.asyncio.server import Server, ServerConnection, serve
from websockets.exceptions import ConnectionClosed
from websockets.http11 import Request, Response
from websockets.typing import Data

from sotto.crypto.identity import NONCE_LENGTH, LoginRefusedError, verify_login
from sotto.proto.sotto_pb2 import Hello, LoggedIn, Login, ServerFrame
from sotto.relay.frames import MAX_FRAME_BYTES, MalformedFrameError, parse_client_frame
from sotto.relay.logs import ConnectionLogger
from sotto.relay.settings import Settings

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


def read_frame(message: Data) -> Login:
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

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
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
            await connection.send(ServerFrame(logged_in=LoggedIn()).SerializeToString())

            async for message in connection:
                if self.logged_in.get(identity_key) is not connection:
                    # A replaced connection waits here for its close: websockets hands its
                    # frames over until the client answers, and a return would close it
                    # with 1000 before the 4001 is sent.
                    continue
                read_frame(message)
                # The only frame of the schema is a Login, which section 7.4 allows once.
                raise ViolationError(CloseCode.PROTOCOL_VIOLATION)
        finally:
            if self.logged_in.get(identity_key) is connection:
                del self.logged_in[identity_key]


def serve_relay(settings: Settings) -> Server:
    relay = Relay(settings)
    return serve(
        relay.handle_connection,
        settings.host,
        settings.port,
        process_request=route_request,
        compression=None,
        server_header=None,
        max_size=MAX_FRAME_BYTES,
        logger=ConnectionLogger(logging.getLogger("websockets.server")),
    )
