import asyncio
import os
import signal

from sotto.relay.logs import configure_logging
from sotto.relay.server import serve_relay
from sotto.relay.settings import Settings

STOP_SIGNALS = (signal.SIGTERM, signal.SIGINT)


async def run(settings: Settings) -> None:
    stop_requested = asyncio.Event()
    loop = asyncio.get_running_loop()
    for stop_signal in STOP_SIGNALS:
        loop.add_signal_handler(stop_signal, stop_requested.set)

    async with serve_relay(settings):
        await stop_requested.wait()


def main() -> None:
    settings = Settings.from_env(os.environ)
    configure_logging()
    asyncio.run(run(settings))


if __name__ == "__main__":
    main()
