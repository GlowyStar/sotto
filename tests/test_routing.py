import asyncio
from contextlib import closing
from http import HTTPStatus
from http.client import HTTPConnection
from urllib.parse import urlsplit

import pytest
from websockets.asyncio.client import connect
from websockets.exceptions import InvalidStatus
from websockets.typing import Subprotocol

pytestmark = pytest.mark.stand


def fetch_status(relay_url: str, path: str) -> int:
    with closing(HTTPConnection(urlsplit(relay_url).netloc, timeout=5)) as connection:
        connection.request("GET", path)
        return connection.getresponse().status


def fetch_server_header(relay_url: str, path: str) -> str | None:
    with closing(HTTPConnection(urlsplit(relay_url).netloc, timeout=5)) as connection:
        connection.request("GET", path)
        return connection.getresponse().getheader("Server")


async def test_healthz_answers_200(relay_url: str) -> None:
    status = await asyncio.to_thread(fetch_status, relay_url, "/healthz")

    assert status == HTTPStatus.OK


async def test_unknown_path_answers_404(relay_url: str) -> None:
    status = await asyncio.to_thread(fetch_status, relay_url, "/")

    assert status == HTTPStatus.NOT_FOUND


async def test_websocket_opens_on_ws(relay_url: str) -> None:
    async with connect(f"{relay_url}/ws", proxy=None) as websocket:
        handshake = websocket.response

    assert handshake is not None
    assert handshake.status_code == HTTPStatus.SWITCHING_PROTOCOLS
    assert "Sec-WebSocket-Extensions" not in handshake.headers


@pytest.mark.parametrize(
    ("path", "status"),
    [
        ("/", HTTPStatus.NOT_FOUND),
        ("/ws/", HTTPStatus.NOT_FOUND),
        ("/ws?x=1", HTTPStatus.NOT_FOUND),
        ("/healthz", HTTPStatus.OK),
    ],
)
async def test_websocket_is_refused_off_ws(
    relay_url: str, path: str, status: HTTPStatus
) -> None:
    with pytest.raises(InvalidStatus) as refusal:
        async with connect(f"{relay_url}{path}", proxy=None):
            pass

    assert refusal.value.response.status_code == status


async def test_no_subprotocol_is_selected(relay_url: str) -> None:
    async with connect(f"{relay_url}/ws", proxy=None, subprotocols=[Subprotocol("sotto")]) as (
        websocket
    ):
        handshake = websocket.response
        selected = websocket.subprotocol

    assert handshake is not None
    assert "Sec-WebSocket-Protocol" not in handshake.headers
    assert selected is None


async def test_answers_do_not_name_the_software(relay_url: str) -> None:
    async with connect(f"{relay_url}/ws", proxy=None) as websocket:
        handshake = websocket.response
    health = await asyncio.to_thread(fetch_server_header, relay_url, "/healthz")
    not_found = await asyncio.to_thread(fetch_server_header, relay_url, "/")

    assert handshake is not None
    assert "Server" not in handshake.headers
    assert health is None
    assert not_found is None
