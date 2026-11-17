"""The metrics listener of the relay (docs/threat-model.md, "What the relay keeps")."""

import asyncio
import os
import re
from contextlib import closing
from dataclasses import replace
from http import HTTPStatus
from http.client import HTTPConnection

from relay_harness import PATIENCE_SECONDS, Clock, OpenClient, build_upload
from websockets.asyncio.server import Server

from sotto.crypto.identity import derive_identity_key
from sotto.proto.sotto_pb2 import (
    Ack,
    ClientFrame,
    DeleteBlob,
    FetchBlob,
    FetchBundle,
    MessageRef,
    PutBlob,
    Send,
    StartBlob,
)
from sotto.relay.server import serve_relay
from sotto.relay.settings import Settings

COMMENT_LINE = re.compile(r"# TYPE [a-z_]+ (counter|gauge)")
SAMPLE_LINE = re.compile(r'[a-z_]+(\{[a-z_]+="[A-Za-z_]+"(,[a-z_]+="[A-Za-z_]+")*\})? \d+')


def port_of(server: Server) -> int:
    port: int = server.sockets[0].getsockname()[1]
    return port


def fetch_text(port: int, path: str) -> tuple[int, str]:
    with closing(HTTPConnection("127.0.0.1", port, timeout=5)) as connection:
        connection.request("GET", path)
        response = connection.getresponse()
        return response.status, response.read().decode()


async def scrape(port: int) -> tuple[list[str], dict[str, int]]:
    """Returns the lines of /metrics and the value of every sample."""
    status, text = await asyncio.to_thread(fetch_text, port, "/metrics")
    assert status == HTTPStatus.OK
    lines = text.splitlines()
    samples = {}
    for line in lines:
        if not line.startswith("#"):
            name, value = line.rsplit(" ", 1)
            samples[name] = int(value)
    return lines, samples


async def test_metrics_move_by_a_login_send_delivery_and_ack(
    settings: Settings, open_client: OpenClient
) -> None:
    recipient_seed, sender_seed = os.urandom(32), os.urandom(32)
    recipient_key, sender_key = map(derive_identity_key, (recipient_seed, sender_seed))
    send = Send(message_id=os.urandom(16), recipient=recipient_key, payload=os.urandom(100))

    async with serve_relay(replace(settings, metrics_port=0)) as listeners:
        assert listeners.metrics is not None
        url, metrics_port = (
            f"ws://127.0.0.1:{port_of(listeners.websocket)}",
            port_of(listeners.metrics),
        )
        _, before = await scrape(metrics_port)
        recipient, sender = await open_client(url), await open_client(url)
        await recipient.log_in(recipient_seed)
        await recipient.ask(build_upload(recipient_seed))
        await sender.log_in(sender_seed)
        await sender.ask(send)
        deliver = (await recipient.receive()).deliver
        pair = MessageRef(message_id=deliver.message_id, sender=deliver.sender)
        await recipient.send(ClientFrame(ack=Ack(messages=[pair])))
        await recipient.ask(FetchBundle(identity=recipient_key))
        lines, after = await scrape(metrics_port)
        other_path = await asyncio.to_thread(fetch_text, metrics_port, "/")

    moved = {name: after[name] - before.get(name, 0) for name in after}
    del moved["sotto_database_bytes"]
    del moved["sotto_blob_bytes"]
    assert {name: count for name, count in moved.items() if count} == {
        "sotto_connections_open": 2,
        "sotto_logins_total": 2,
        "sotto_messages_stored_total": 1,
        "sotto_messages_delivered_total": 1,
        "sotto_messages_acked_total": 1,
        'sotto_frames_total{type="UploadBundle",result="bundle_stored"}': 1,
        'sotto_frames_total{type="Send",result="stored"}': 1,
        'sotto_frames_total{type="Ack",result="none"}': 1,
        'sotto_frames_total{type="FetchBundle",result="bundle"}': 1,
        'sotto_bundle_fetches_total{one_time_prekey="no"}': 1,
    }
    assert after["sotto_database_bytes"] > 0
    assert all(COMMENT_LINE.fullmatch(line) or SAMPLE_LINE.fullmatch(line) for line in lines)
    assert not any(key.hex() in "\n".join(lines) for key in (recipient_key, sender_key))
    assert other_path[0] == HTTPStatus.NOT_FOUND


async def test_metrics_listener_is_off_unless_its_port_is_set(settings: Settings) -> None:
    async with serve_relay(settings) as listeners:
        metrics = listeners.metrics

    assert settings.metrics_port is None
    assert metrics is None


async def test_metrics_count_the_blob_frames_without_an_identity(
    settings: Settings, open_client: OpenClient
) -> None:
    clock = Clock()
    ttl_seconds, sweep_seconds = 100, 0.01
    relay_settings = replace(
        settings,
        metrics_port=0,
        blob_quota_bytes=1000,
        blob_ttl_seconds=ttl_seconds,
        sweep_interval_seconds=sweep_seconds,
    )
    uploader_seed, recipient_seed = os.urandom(32), os.urandom(32)
    uploader_key, recipient_key = map(derive_identity_key, (uploader_seed, recipient_seed))
    fetched, kept, given_up, expiring = (
        StartBlob(blob_id=os.urandom(16), recipient=recipient_key, length=length)
        for length in (100, 300, 200, 50)
    )
    over_quota = StartBlob(blob_id=os.urandom(16), recipient=recipient_key, length=401)

    async with serve_relay(relay_settings, clock=clock) as listeners:
        assert listeners.metrics is not None
        url, metrics_port = (
            f"ws://127.0.0.1:{port_of(listeners.websocket)}",
            port_of(listeners.metrics),
        )
        _, before = await scrape(metrics_port)
        recipient, uploader = await open_client(url), await open_client(url)
        await recipient.log_in(recipient_seed)
        await recipient.ask(build_upload(recipient_seed))
        await uploader.log_in(uploader_seed)
        for start in (fetched, kept, given_up):
            await uploader.ask(start)
        await uploader.ask(fetched)
        await uploader.ask(over_quota)
        await uploader.ask(PutBlob(blob_id=fetched.blob_id, offset=0, data=os.urandom(100)))
        await uploader.ask(PutBlob(blob_id=kept.blob_id, offset=0, data=os.urandom(30)))
        await uploader.ask(PutBlob(blob_id=given_up.blob_id, offset=0, data=os.urandom(20)))
        fetch = FetchBlob(blob_id=fetched.blob_id, uploader=uploader_key, offset=0, length=80)
        await recipient.ask(fetch)
        _, while_held = await scrape(metrics_port)
        await recipient.send(
            ClientFrame(delete_blob=DeleteBlob(blob_id=fetched.blob_id, uploader=uploader_key))
        )
        await uploader.send(
            ClientFrame(
                delete_blob=DeleteBlob(blob_id=given_up.blob_id, uploader=uploader_key)
            )
        )
        await uploader.ask(expiring)
        clock.now += ttl_seconds
        for _ in range(int(PATIENCE_SECONDS / sweep_seconds)):
            lines, after = await scrape(metrics_port)
            if after["sotto_blobs_expired_total"] == 2:
                break
            await asyncio.sleep(sweep_seconds)

    moved = {name: after[name] - before.get(name, 0) for name in after}
    del moved["sotto_database_bytes"]
    assert while_held["sotto_blob_bytes"] == 150
    assert {name: count for name, count in moved.items() if count} == {
        "sotto_connections_open": 2,
        "sotto_logins_total": 2,
        "sotto_blobs_started_total": 4,
        "sotto_blobs_completed_total": 1,
        "sotto_blobs_expired_total": 2,
        "sotto_blob_bytes_stored_total": 150,
        "sotto_blob_bytes_fetched_total": 80,
        'sotto_blobs_deleted_total{by="recipient"}': 1,
        'sotto_blobs_deleted_total{by="uploader"}': 1,
        'sotto_limit_refusals_total{kind="blob_quota"}': 1,
        'sotto_frames_total{type="UploadBundle",result="bundle_stored"}': 1,
        'sotto_frames_total{type="StartBlob",result="blob_stored"}': 5,
        'sotto_frames_total{type="StartBlob",result="QUOTA_FULL"}': 1,
        'sotto_frames_total{type="PutBlob",result="blob_stored"}': 3,
        'sotto_frames_total{type="FetchBlob",result="blob_data"}': 1,
        'sotto_frames_total{type="DeleteBlob",result="none"}': 2,
    }
    assert after["sotto_blob_bytes"] == 0
    assert all(COMMENT_LINE.fullmatch(line) or SAMPLE_LINE.fullmatch(line) for line in lines)
    assert not any(key.hex() in "\n".join(lines) for key in (recipient_key, uploader_key))
