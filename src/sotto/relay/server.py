from http import HTTPStatus

from websockets.asyncio.server import Server, ServerConnection, serve
from websockets.http11 import Request, Response

from sotto.relay.settings import Settings

WEBSOCKET_PATH = "/ws"
HEALTH_PATH = "/healthz"


def route_request(connection: ServerConnection, request: Request) -> Response | None:
    if request.path == WEBSOCKET_PATH:
        return None
    if request.path == HEALTH_PATH:
        return connection.respond(HTTPStatus.OK, "OK\n")
    return connection.respond(HTTPStatus.NOT_FOUND, "Not found\n")


async def handle_connection(connection: ServerConnection) -> None:
    """No frame is defined yet, so the connection closes right after the handshake."""


def serve_relay(settings: Settings) -> Server:
    return serve(
        handle_connection,
        settings.host,
        settings.port,
        process_request=route_request,
        compression=None,
    )
