import asyncio
import dataclasses
import json
import logging
import os
import re
from collections.abc import AsyncIterator
from dataclasses import replace
from typing import cast
from urllib.parse import urlsplit

import pytest
from relay_harness import OpenClient, Wire, build_upload, running_relay
from websockets.asyncio.server import ServerConnection

from sotto.crypto.identity import derive_identity_key
from sotto.proto.sotto_pb2 import ClientFrame, Error, ErrorCode, FetchBundle, ServerFrame
from sotto.relay import server
from sotto.relay.logs import JsonFormatter
from sotto.relay.server import CloseCode, Relay
from sotto.relay.settings import Settings
from sotto.relay.storage import Storage

# Sent by the WebSocket library when the handler of a connection raises.
INTERNAL_ERROR = 1011


async def test_silence_after_the_hello_closes_with_3008(
    settings: Settings, open_client: OpenClient
) -> None:
    async with running_relay(replace(settings, login_deadline_seconds=0.2)) as url:
        client = await open_client(url)

        assert await client.frames_until_close() == ([], CloseCode.LOGIN_TIMEOUT)


async def test_half_a_message_leaves_the_login_deadline_running(
    settings: Settings, open_client: OpenClient
) -> None:
    async def first_fragment_of_many() -> AsyncIterator[bytes]:
        yield os.urandom(16)
        await asyncio.Event().wait()

    async with running_relay(replace(settings, login_deadline_seconds=0.2)) as url:
        client = await open_client(url)
        sending = asyncio.create_task(client.websocket.send(first_fragment_of_many()))
        try:
            assert await client.frames_until_close() == ([], CloseCode.LOGIN_TIMEOUT)
        finally:
            sending.cancel()


async def test_login_is_verified_under_the_name_in_the_settings(
    settings: Settings, open_client: OpenClient
) -> None:
    async with running_relay(replace(settings, name="relay.example.org")) as url:
        signed_for_the_address = await open_client(url)
        await signed_for_the_address.send(signed_for_the_address.login(os.urandom(32)))
        refusal = await signed_for_the_address.frames_until_close()

        dialed = await open_client(url)
        signed_for_the_name = dataclasses.replace(dialed, server_name="relay.example.org")
        answer = await signed_for_the_name.log_in(os.urandom(32))

    assert refusal == ([], CloseCode.LOGIN_REFUSED)
    assert answer.WhichOneof("frame") == "logged_in"


async def test_shutdown_closes_every_connection_with_1001(
    settings: Settings, open_client: OpenClient
) -> None:
    async with running_relay(settings) as url:
        before_login = await open_client(url)
        after_login = await open_client(url)
        await after_login.log_in(os.urandom(32))

    assert await before_login.frames_until_close() == ([], CloseCode.SHUTDOWN)
    assert await after_login.frames_until_close() == ([], CloseCode.SHUTDOWN)


async def test_frame_of_a_replaced_connection_is_not_handled(
    settings: Settings, open_client: OpenClient, caplog: pytest.LogCaptureFixture
) -> None:
    seed = os.urandom(32)

    async with running_relay(settings) as url:
        older = await open_client(url)
        await older.log_in(seed)
        # The close stays unread in the socket, so the client can still send a frame.
        older.websocket.transport.pause_reading()
        newer = await open_client(url)
        await newer.log_in(seed)

        await older.send(os.urandom(16).hex())
        older.websocket.transport.resume_reading()
        closing = await older.frames_until_close()

    assert closing == ([], CloseCode.REPLACED)
    assert "closing with 4001 REPLACED" in caplog.messages
    assert "closing with 1003 TEXT_FRAME" not in caplog.messages


async def test_upload_of_a_replaced_connection_stores_nothing(
    settings: Settings, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    identity = derive_identity_key(seed)

    async with running_relay(settings) as url:
        older = await open_client(url)
        await older.log_in(seed)
        # The close stays unread in the socket, so the client can still send a frame.
        older.websocket.transport.pause_reading()
        newer = await open_client(url)
        await newer.log_in(seed)

        await older.send(ClientFrame(upload_bundle=build_upload(seed, [1])))
        older.websocket.transport.resume_reading()
        closing = await older.frames_until_close()
        lookup = await newer.ask(FetchBundle(identity=identity))

    assert closing == ([], CloseCode.REPLACED)
    assert lookup == ServerFrame(error=Error(code=ErrorCode.NOT_FOUND, identity=identity))


async def test_handler_of_a_replaced_connection_reads_on_until_the_close(
    settings: Settings, storage: Storage
) -> None:
    relay = Relay(settings, storage)
    identity_key = os.urandom(32)
    newer = cast(ServerConnection, object())
    frames_read = []

    class ReplacedConnection:
        """What `serve_logged_in` uses of a connection, replaced before its next frame."""

        logger = logging.getLogger("websockets.server")

        async def send(self, message: bytes) -> None:
            pass

        async def __aiter__(self) -> AsyncIterator[bytes]:
            relay.logged_in[identity_key] = newer
            for number in range(2):
                frames_read.append(number)
                yield os.urandom(16)

    await relay.serve_logged_in(cast(ServerConnection, ReplacedConnection()), identity_key)

    assert frames_read == [0, 1]
    assert relay.logged_in == {identity_key: newer}


async def test_closed_connection_is_no_longer_the_live_one_of_its_identity(
    settings: Settings, open_client: OpenClient, caplog: pytest.LogCaptureFixture
) -> None:
    seed = os.urandom(32)

    async with running_relay(settings) as url:
        first = await open_client(url)
        await first.log_in(seed)
        await first.websocket.close()
        second = await open_client(url)
        await second.log_in(seed)

    assert caplog.messages.count("logged in") == 2
    assert "closing with 4001 REPLACED" not in caplog.messages


async def test_client_that_leaves_is_no_failure_of_the_handler(
    settings: Settings, open_client: OpenClient, caplog: pytest.LogCaptureFixture
) -> None:
    async with running_relay(settings) as url:
        leaving_before_login = await open_client(url)
        await leaving_before_login.websocket.close()
        leaving_after_login = await open_client(url)
        await leaving_after_login.log_in(os.urandom(32))
        await leaving_after_login.websocket.close()
        cut_off = await open_client(url)
        cut_off.websocket.transport.abort()

    assert {record.levelname for record in caplog.records} == {"INFO"}


async def test_failed_handler_closes_with_1011_and_logs_no_text_of_the_exception(
    settings: Settings,
    open_client: OpenClient,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def fail_with_the_login_in_the_text(identity_key: bytes, **fields: bytes | str) -> None:
        raise KeyError(identity_key, fields)

    monkeypatch.setattr(server, "verify_login", fail_with_the_login_in_the_text)

    async with running_relay(settings) as url:
        client = await open_client(url)
        await client.send(client.login(os.urandom(32)))
        closing = await client.frames_until_close()

    failures = [record for record in caplog.records if record.levelno == logging.ERROR]
    assert closing == ([], INTERNAL_ERROR)
    assert [failure.getMessage() for failure in failures] == ["connection handler failed"]
    logged = json.loads(JsonFormatter().format(failures[0]))
    assert "in fail_with_the_login_in_the_text" in logged["exception"]
    assert logged["exception"].endswith("KeyError")
    assert "connection" in logged
    # The formatter of the standard library prints the key, the nonces and the signature,
    # so the exception did carry them.
    assert "KeyError: (b" in logging.Formatter().format(failures[0])


async def test_log_lines_of_a_connection_carry_its_id(
    settings: Settings, open_client: OpenClient, caplog: pytest.LogCaptureFixture
) -> None:
    async with running_relay(settings) as url:
        logged_in = await open_client(url)
        await logged_in.log_in(os.urandom(32))
        closed = await open_client(url)
        await closed.send(os.urandom(16).hex())
        await closed.frames_until_close()

    lines = [json.loads(JsonFormatter().format(record)) for record in caplog.records]
    ids: dict[str, list[str]] = {}
    for line in lines:
        if "connection" in line:
            ids.setdefault(line["connection"], []).append(line["message"])
    assert sorted(ids.values()) == [
        ["connection open", "closing with 1003 TEXT_FRAME", "connection closed"],
        ["connection open", "logged in", "connection closed"],
    ]
    assert all(re.fullmatch(r"[0-9a-f]{32}", connection_id) for connection_id in ids)


async def test_bytes_behind_a_plain_request_reach_no_log(
    settings: Settings, wire: Wire
) -> None:
    surplus = os.urandom(64)
    wire.messages.append(surplus)

    async with running_relay(settings) as url:
        address = urlsplit(url)
        reader, writer = await asyncio.open_connection(address.hostname, address.port)
        writer.write(b"GET /healthz HTTP/1.1\r\nHost: relay\r\n\r\n" + surplus)
        await writer.drain()
        await reader.read()
        writer.close()
        await writer.wait_closed()
