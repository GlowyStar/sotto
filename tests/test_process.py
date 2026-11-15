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


async def test_relay_does_not_start_with_a_server_name_that_breaks_rule_4() -> None:
    relay = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "sotto.relay",
        env={**os.environ, "RELAY_PORT": "0", "RELAY_NAME": "Relay.Example.org"},
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        async with asyncio.timeout(10):
            output, errors = await relay.communicate()
    finally:
        if relay.returncode is None:
            relay.kill()
            await relay.wait()

    assert relay.returncode == 1
    assert output == b""
    assert b"RELAY_NAME is not a server name" in errors
