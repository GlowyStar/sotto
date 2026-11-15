import os
from collections.abc import AsyncIterator

import pytest

from sotto.relay.server import serve_relay
from sotto.relay.settings import Settings


@pytest.fixture
async def relay_url() -> AsyncIterator[str]:
    stand_url = os.environ.get("RELAY_URL")
    if stand_url is not None:
        yield stand_url
        return

    async with serve_relay(Settings(port=0)) as server:
        port = server.sockets[0].getsockname()[1]
        yield f"ws://127.0.0.1:{port}"
