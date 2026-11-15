import asyncio
import json
import os
import signal
import sys
from pathlib import Path


def files_in(folder: Path) -> list[str]:
    return sorted(path.name for path in folder.iterdir())


async def test_relay_logs_json_lines_and_exits_0_on_sigterm(tmp_path: Path) -> None:
    relay = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "sotto.relay",
        env={
            **os.environ,
            "RELAY_DATABASE": str(tmp_path / "relay.db"),
            "RELAY_HOST": "127.0.0.1",
            "RELAY_PORT": "0",
        },
        stdout=asyncio.subprocess.PIPE,
    )
    assert relay.stdout is not None

    try:
        async with asyncio.timeout(10):
            first_lines = [await relay.stdout.readline() for _ in range(2)]
            files_while_it_runs = files_in(tmp_path)
            relay.send_signal(signal.SIGTERM)
            other_lines, _ = await relay.communicate()
    finally:
        if relay.returncode is None:
            relay.kill()
            await relay.wait()

    lines = [*first_lines, *other_lines.splitlines()]
    messages = [json.loads(line)["message"] for line in lines]
    assert relay.returncode == 0
    assert messages[0].startswith("database open: SQLite ")
    assert messages[1].startswith("server listening on 127.0.0.1:")
    assert messages[-1] == "server closed"
    assert files_while_it_runs == ["relay.db", "relay.db-shm", "relay.db-wal"]
    assert files_in(tmp_path) == ["relay.db"]


async def test_relay_does_not_start_with_a_server_name_that_breaks_rule_4(
    tmp_path: Path,
) -> None:
    relay = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "sotto.relay",
        env={
            **os.environ,
            "RELAY_DATABASE": str(tmp_path / "relay.db"),
            "RELAY_PORT": "0",
            "RELAY_NAME": "Relay.Example.org",
        },
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
    assert files_in(tmp_path) == []
