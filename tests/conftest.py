import os
from collections.abc import AsyncIterator

import pytest
from hypothesis import settings

from sotto.relay.server import serve_relay
from sotto.relay.settings import Settings

# The profile that hypothesis picks by itself in CI is derandomized, so every run there
# would replay the same examples.
settings.register_profile("sotto", derandomize=False, print_blob=True, deadline=None)
settings.load_profile("sotto")


@pytest.fixture
async def relay_url() -> AsyncIterator[str]:
    stand_url = os.environ.get("RELAY_URL")
    if stand_url is not None:
        yield stand_url
        return

    async with serve_relay(Settings(port=0)) as server:
        port = server.sockets[0].getsockname()[1]
        yield f"ws://127.0.0.1:{port}"
