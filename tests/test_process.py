import asyncio
import json
import os
import signal
import sys


async def test_relay_logs_json_lines_and_exits_0_on_sigterm() -> None:
    relay = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "sotto.relay",
        env={**os.environ, "RELAY_HOST": "127.0.0.1", "RELAY_PORT": "0"},
        stdout=asyncio.subprocess.PIPE,
    )
    assert relay.stdout is not None

    try:
        async with asyncio.timeout(10):
            first_line = await relay.stdout.readline()
            relay.send_signal(signal.SIGTERM)
            other_lines, _ = await relay.communicate()
    finally:
        if relay.returncode is None:
            relay.kill()
            await relay.wait()

    lines = (first_line + other_lines).splitlines()
    messages = [json.loads(line)["message"] for line in lines]
    assert relay.returncode == 0
    assert messages[0].startswith("server listening on 127.0.0.1:")
    assert messages[-1] == "server closed"
