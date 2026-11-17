import asyncio
import json
import os
import signal
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from relay_harness import OpenClient, build_upload

from sotto.crypto.identity import derive_identity_key
from sotto.proto.sotto_pb2 import (
    BlobStored,
    PutBlob,
    Send,
    ServerFrame,
    StartBlob,
    Stored,
)
from sotto.relay.frames import BLOB_CHUNK_BYTES


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


async def test_message_answered_with_stored_survives_a_kill_of_the_relay(
    tmp_path: Path, open_client: OpenClient
) -> None:
    sender_seed, recipient_seed = os.urandom(32), os.urandom(32)
    send = Send(
        message_id=os.urandom(16),
        recipient=derive_identity_key(recipient_seed),
        payload=os.urandom(100),
    )
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
            port = json.loads(first_lines[1])["message"].rsplit(":", 1)[1]
            url = f"ws://127.0.0.1:{port}"
            recipient = await open_client(url)
            await recipient.log_in(recipient_seed)
            await recipient.ask(build_upload(recipient_seed))
            sender = await open_client(url)
            await sender.log_in(sender_seed)
            answer = await sender.ask(send)
            relay.kill()
            await relay.communicate()
    finally:
        if relay.returncode is None:
            relay.kill()
            await relay.wait()

    with closing(sqlite3.connect(tmp_path / "relay.db")) as database:
        rows = database.execute(
            "SELECT sender, recipient, message_id, payload FROM messages"
        ).fetchall()
    assert relay.returncode == -signal.SIGKILL
    assert answer == ServerFrame(stored=Stored(message_id=send.message_id))
    assert rows == [
        (derive_identity_key(sender_seed), send.recipient, send.message_id, send.payload)
    ]


async def test_blob_stored_length_survives_a_kill_of_the_relay(
    tmp_path: Path, open_client: OpenClient
) -> None:
    uploader_seed, recipient_seed = os.urandom(32), os.urandom(32)
    start = StartBlob(
        blob_id=os.urandom(16),
        recipient=derive_identity_key(recipient_seed),
        length=3 * BLOB_CHUNK_BYTES,
    )
    piece = PutBlob(blob_id=start.blob_id, offset=0, data=os.urandom(BLOB_CHUNK_BYTES))
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
            port = json.loads(first_lines[1])["message"].rsplit(":", 1)[1]
            url = f"ws://127.0.0.1:{port}"
            recipient = await open_client(url)
            await recipient.log_in(recipient_seed)
            await recipient.ask(build_upload(recipient_seed))
            uploader = await open_client(url)
            await uploader.log_in(uploader_seed)
            await uploader.ask(start)
            answer = await uploader.ask(piece)
            relay.kill()
            await relay.communicate()
    finally:
        if relay.returncode is None:
            relay.kill()
            await relay.wait()

    with closing(sqlite3.connect(tmp_path / "relay.db")) as database:
        progress = database.execute("SELECT stored_length FROM blobs").fetchall()
        pieces = database.execute("SELECT offset, data FROM blob_chunks").fetchall()
    assert relay.returncode == -signal.SIGKILL
    assert answer == ServerFrame(
        blob_stored=BlobStored(blob_id=start.blob_id, stored_length=BLOB_CHUNK_BYTES)
    )
    assert progress == [(BLOB_CHUNK_BYTES,)]
    assert pieces == [(0, piece.data)]
