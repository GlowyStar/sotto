import logging
import os
from collections.abc import AsyncIterator, Iterator
from contextlib import AsyncExitStack
from urllib.parse import urlsplit

import pytest
from hypothesis import settings
from relay_harness import OpenClient, RawClient, Wire, find_leaks, receive_frame, running_relay
from websockets.asyncio.client import connect

from sotto.relay.settings import Settings

# The profile that hypothesis picks by itself in CI is derandomized, so every run there
# would replay the same examples.
settings.register_profile("sotto", derandomize=False, print_blob=True, deadline=None)
settings.load_profile("sotto")


@pytest.fixture(autouse=True)
def wire(caplog: pytest.LogCaptureFixture) -> Iterator[Wire]:
    """Fails a test when a log record holds bytes that crossed its wire or a client address."""
    # As configure_logging sets it up: the root logger at INFO and a handler without a
    # level, which prints the DEBUG records of a logger that was switched to DEBUG.
    caplog.set_level(logging.INFO)
    caplog.handler.setLevel(logging.NOTSET)
    wire = Wire()
    yield wire

    records = [
        *caplog.get_records("setup"),
        *caplog.get_records("call"),
        *caplog.get_records("teardown"),
    ]
    assert find_leaks(records, wire) == []


@pytest.fixture
async def relay_url() -> AsyncIterator[str]:
    stand_url = os.environ.get("RELAY_URL")
    if stand_url is not None:
        yield stand_url
        return

    async with running_relay(Settings(port=0)) as url:
        yield url


@pytest.fixture
async def open_client(wire: Wire) -> AsyncIterator[OpenClient]:
    """Opens raw clients that have read their Hello; they are closed after the test."""
    async with AsyncExitStack() as connections:

        async def open_raw_client(url: str) -> RawClient:
            websocket = await connections.enter_async_context(connect(f"{url}/ws", proxy=None))
            host, port = websocket.local_address[:2]
            wire.client_addresses.extend([f"{host}:{port}", f"{host!r}, {port}"])

            hello = (await receive_frame(websocket, wire)).hello
            server_name = urlsplit(url).hostname
            assert server_name is not None
            return RawClient(websocket, hello, server_name, wire)

        yield open_raw_client
