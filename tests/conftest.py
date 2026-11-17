import logging
import os
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import AsyncExitStack
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from hypothesis import settings as hypothesis_settings
from relay_harness import OpenClient, RawClient, Wire, find_leaks, receive_frame, running_relay
from websockets.asyncio.client import connect

from sotto.client.session import Client
from sotto.client.store import Store
from sotto.relay.settings import Settings
from sotto.relay.storage import Storage

# The profile that hypothesis picks by itself in CI is derandomized, so every run there
# would replay the same examples.
hypothesis_settings.register_profile(
    "sotto", derandomize=False, print_blob=True, deadline=None
)
hypothesis_settings.load_profile("sotto")

STAND_BUCKET_SIZE = 1000


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
def settings(tmp_path: Path) -> Settings:
    """The settings of a relay in the process: a free port and a database of the test.

    The buckets are those of the stand (compose.yaml), large enough for the bursts of the
    tests; the tests of the limits set their own.
    """
    return Settings(
        database=tmp_path / "relay.db",
        port=0,
        frame_bucket_size=STAND_BUCKET_SIZE,
        handout_bucket_size=STAND_BUCKET_SIZE,
    )


@pytest.fixture
def storage(settings: Settings) -> Iterator[Storage]:
    """The storage of a test that calls it or a handler without a relay."""
    storage = Storage(settings.database, max_pages=settings.max_pages)
    yield storage
    storage.close()


@pytest.fixture
async def relay_url(settings: Settings) -> AsyncIterator[str]:
    stand_url = os.environ.get("RELAY_URL")
    if stand_url is not None:
        yield stand_url
        return

    async with running_relay(settings) as url:
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


@pytest.fixture
def make_client(tmp_path: Path) -> Iterator[Callable[[str], Client]]:
    """Opens the client of a name under the test folder; a second call is a restart."""
    stores: list[Store] = []

    def open_client(name: str) -> Client:
        store = Store(tmp_path / name / "store.db")
        stores.append(store)
        return Client(store)

    yield open_client
    for store in stores:
        store.close()
