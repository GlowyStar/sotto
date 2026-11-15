"""The relay on a database file of the test: what a socket of the stand cannot show."""

import logging
import os
import sqlite3
import time
from collections.abc import AsyncIterator
from contextlib import closing
from dataclasses import replace
from typing import cast

import pytest
from relay_harness import OpenClient, RawClient, build_upload, running_relay
from websockets.asyncio.server import ServerConnection

from sotto.crypto.identity import derive_identity_key
from sotto.proto.sotto_pb2 import (
    Ack,
    ClientFrame,
    Deliver,
    Error,
    ErrorCode,
    FetchBundle,
    MessageRef,
    Send,
    ServerFrame,
    Stored,
)
from sotto.relay import storage as storage_module
from sotto.relay.frames import MAX_PAYLOAD_BYTES
from sotto.relay.server import Relay
from sotto.relay.settings import Settings
from sotto.relay.storage import Storage

# Sent by the WebSocket library when the handler of a connection raises.
INTERNAL_ERROR = 1011
PAGE_BYTES = 4096
# The empty schema takes 8 pages and an upload of 100 one-time prekeys takes 3 or 4.
FEW_PAGES = 12
NOT_FOUND = ErrorCode.NOT_FOUND


def files_of(settings: Settings) -> list[str]:
    return sorted(path.name for path in settings.database.parent.iterdir())


def messages_in(settings: Settings) -> list[tuple[bytes, bytes, bytes, bytes, int]]:
    """Reads the queued messages from the file, beside the connection of a running relay."""
    with closing(sqlite3.connect(settings.database)) as database:
        rows = database.execute(
            "SELECT sender, recipient, message_id, payload, stored_at FROM messages"
        ).fetchall()
    return rows


def ack_of(deliver: Deliver) -> ClientFrame:
    pair = MessageRef(message_id=deliver.message_id, sender=deliver.sender)
    return ClientFrame(ack=Ack(messages=[pair]))


async def log_in(open_client: OpenClient, url: str, seed: bytes) -> RawClient:
    client = await open_client(url)
    answer = await client.log_in(seed)
    assert answer.WhichOneof("frame") == "logged_in"
    return client


async def register(open_client: OpenClient, url: str, seed: bytes) -> RawClient:
    client = await log_in(open_client, url, seed)
    answer = await client.ask(build_upload(seed))
    assert answer.WhichOneof("frame") == "bundle_stored"
    return client


def test_every_open_sets_the_pragmas_of_the_relay(settings: Settings) -> None:
    Storage(settings.database, max_pages=1000).close()

    with closing(Storage(settings.database, max_pages=500)) as storage:
        pragmas = {
            name: storage.connection.execute(f"PRAGMA {name}").fetchone()[0]
            for name in ("journal_mode", "synchronous", "secure_delete", "max_page_count")
        }
        is_in_a_transaction = storage.connection.in_transaction

    # 2 is FULL and 1 is ON.
    assert pragmas == {
        "journal_mode": "wal",
        "synchronous": 2,
        "secure_delete": 1,
        "max_page_count": 500,
    }
    assert not is_in_a_transaction


def test_same_key_under_another_signature_is_stored_and_keeps_the_first_signature(
    storage: Storage,
) -> None:
    seed = os.urandom(32)
    identity_key = derive_identity_key(seed)
    first = build_upload(seed)
    second = build_upload(seed)
    second.identity_dh_key = first.identity_dh_key
    # The storage verifies nothing, so any other 64 bytes stand for a second signature of
    # the same key, which a signer with randomization makes.
    second.identity_dh_signature = os.urandom(64)

    storage.store_bundle(identity_key, first, cap=100)
    storage.store_bundle(identity_key, second, cap=100)
    bundle = storage.fetch_bundle(identity_key)

    assert bundle is not None
    assert bundle.identity_dh_signature == first.identity_dh_signature
    assert bundle.signed_prekey == second.signed_prekey


async def test_relay_restarted_on_the_same_file_serves_the_bundle(
    settings: Settings, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    identity = derive_identity_key(seed)
    upload = build_upload(seed, [1, 2])

    async with running_relay(settings) as url:
        owner = await log_in(open_client, url, seed)
        await owner.ask(upload)
        before = await owner.ask(FetchBundle(identity=identity))
        files_while_it_runs = files_of(settings)
    files_after_the_first_stop = files_of(settings)

    async with running_relay(settings) as url:
        owner_again = await open_client(url)
        logged_in = await owner_again.log_in(seed)
        after = await owner_again.ask(FetchBundle(identity=identity))
    files_after_the_second_stop = files_of(settings)

    assert files_while_it_runs == ["relay.db", "relay.db-shm", "relay.db-wal"]
    assert files_after_the_first_stop == files_after_the_second_stop == ["relay.db"]
    assert logged_in.logged_in.one_time_prekey_count == 1
    assert before.bundle.one_time_prekey == upload.one_time_prekeys[0]
    assert after.bundle.one_time_prekey == upload.one_time_prekeys[1]
    after.bundle.one_time_prekey.CopyFrom(upload.one_time_prekeys[0])
    assert after == before


async def test_upload_into_a_full_database_answers_storage_full_and_the_relay_serves_on(
    settings: Settings, open_client: OpenClient, caplog: pytest.LogCaptureFixture
) -> None:
    stored_seeds = []

    async with running_relay(replace(settings, max_pages=FEW_PAGES)) as url:
        for _ in range(FEW_PAGES):
            seed = os.urandom(32)
            client = await log_in(open_client, url, seed)
            answer = await client.ask(build_upload(seed, list(range(100))))
            if answer.WhichOneof("frame") == "error":
                break
            stored_seeds.append(seed)

        refused_identity = derive_identity_key(seed)
        stored_identity = derive_identity_key(stored_seeds[0])
        lookup = await client.ask(FetchBundle(identity=refused_identity))
        handout = await client.ask(FetchBundle(identity=stored_identity))
        newcomer = await log_in(open_client, url, os.urandom(32))
        second_handout = await newcomer.ask(FetchBundle(identity=stored_identity))
        again = await client.ask(build_upload(seed, list(range(100))))

    assert stored_seeds
    assert answer == ServerFrame(error=Error(code=ErrorCode.STORAGE_FULL))
    assert again == ServerFrame(error=Error(code=ErrorCode.STORAGE_FULL))
    assert lookup == ServerFrame(error=Error(code=NOT_FOUND, identity=refused_identity))
    assert handout.bundle.one_time_prekey.id == 0
    assert second_handout.bundle.one_time_prekey.id == 1
    assert caplog.messages.count("the database is full") == 2
    assert {record.levelname for record in caplog.records} == {"INFO", "WARNING"}
    assert settings.database.stat().st_size <= FEW_PAGES * PAGE_BYTES


async def test_fetch_whose_handout_cannot_be_written_gets_the_bundle_without_one(
    settings: Settings,
    open_client: OpenClient,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    seed = os.urandom(32)
    identity = derive_identity_key(seed)
    upload = build_upload(seed, [1])
    # A statement in the place of the handout that needs more pages than the ceiling has.
    needs_too_many_pages = """
        INSERT INTO one_time_prekeys (identity_key, prekey_id, public_key)
        VALUES (?, 2, zeroblob(1000000)) RETURNING prekey_id, public_key
    """

    async with running_relay(replace(settings, max_pages=FEW_PAGES)) as url:
        owner = await log_in(open_client, url, seed)
        await owner.ask(upload)
        monkeypatch.setattr(
            storage_module, "TAKE_OLDEST_ONE_TIME_PREKEY", needs_too_many_pages
        )
        on_the_full_database = await owner.ask(FetchBundle(identity=identity))
        monkeypatch.undo()
        afterwards = await owner.ask(FetchBundle(identity=identity))

    assert on_the_full_database.bundle.signed_prekey == upload.signed_prekey
    assert not on_the_full_database.bundle.HasField("one_time_prekey")
    assert afterwards.bundle.one_time_prekey == upload.one_time_prekeys[0]
    assert caplog.messages.count("the database is full") == 1


async def test_failed_write_is_rolled_back_and_closes_with_1011_while_the_relay_serves_on(
    settings: Settings,
    open_client: OpenClient,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    seed = os.urandom(32)
    identity = derive_identity_key(seed)
    # The row of the identity is written before this statement fails.
    monkeypatch.setattr(
        storage_module, "STORE_ONE_TIME_PREKEY", "INSERT INTO no_such_table VALUES (?, ?, ?)"
    )

    async with running_relay(settings) as url:
        owner = await log_in(open_client, url, seed)
        someone = await log_in(open_client, url, os.urandom(32))
        await owner.send(ClientFrame(upload_bundle=build_upload(seed, [1])))
        closing_of_the_owner = await owner.frames_until_close()
        lookup = await someone.ask(FetchBundle(identity=identity))
        monkeypatch.undo()
        owner_again = await log_in(open_client, url, seed)
        retry = await owner_again.ask(build_upload(seed, [1]))

    failures = [record for record in caplog.records if record.levelno == logging.ERROR]
    assert closing_of_the_owner == ([], INTERNAL_ERROR)
    assert [failure.getMessage() for failure in failures] == ["connection handler failed"]
    assert lookup == ServerFrame(error=Error(code=NOT_FOUND, identity=identity))
    assert retry.bundle_stored.one_time_prekey_count == 1


async def test_bundle_is_sent_after_the_commit_that_deleted_its_one_time_prekey(
    settings: Settings, storage: Storage
) -> None:
    seed = os.urandom(32)
    identity = derive_identity_key(seed)
    storage.store_bundle(identity, build_upload(seed, [1, 2]), cap=100)
    relay = Relay(settings, storage)
    states_at_each_send = []

    class Connection:
        """What `serve_logged_in` uses of a connection that sends one FetchBundle."""

        logger = logging.getLogger("websockets.server")

        async def send(self, message: bytes) -> None:
            frame = ServerFrame.FromString(message).WhichOneof("frame")
            stored = storage.count_one_time_prekeys(identity)
            states_at_each_send.append((frame, storage.connection.in_transaction, stored))

        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield ClientFrame(fetch_bundle=FetchBundle(identity=identity)).SerializeToString()

    await relay.serve_logged_in(cast(ServerConnection, Connection()), os.urandom(32))

    assert states_at_each_send == [("logged_in", False, 2), ("bundle", False, 1)]


async def test_message_is_one_row_until_its_recipient_acks_it(
    settings: Settings, open_client: OpenClient
) -> None:
    sender_seed, recipient_seed = os.urandom(32), os.urandom(32)
    sender_key, recipient_key = (
        derive_identity_key(sender_seed),
        derive_identity_key(recipient_seed),
    )
    send = Send(message_id=os.urandom(16), recipient=recipient_key, payload=os.urandom(100))
    lookup = FetchBundle(identity=recipient_key)

    async with running_relay(settings) as url:
        recipient = await register(open_client, url, recipient_seed)
        someone = await log_in(open_client, url, os.urandom(32))
        sender = await log_in(open_client, url, sender_seed)
        earliest = int(time.time())
        await sender.ask(send)
        await sender.ask(send)
        latest = int(time.time())
        rows_after_the_repeat = messages_in(settings)
        deliver = (await recipient.receive()).deliver
        await someone.send(ack_of(deliver))
        await someone.ask(lookup)
        rows_after_an_ack_of_someone_else = messages_in(settings)
        await recipient.send(ack_of(deliver))
        await recipient.ask(lookup)
        rows_after_the_ack = messages_in(settings)

    [(*row, stored_at)] = rows_after_the_repeat
    assert row == [sender_key, recipient_key, send.message_id, send.payload]
    assert earliest <= stored_at <= latest
    assert rows_after_an_ack_of_someone_else == rows_after_the_repeat
    assert rows_after_the_ack == []


async def test_stored_is_sent_after_the_commit_of_the_message(
    settings: Settings, storage: Storage
) -> None:
    seed = os.urandom(32)
    recipient = derive_identity_key(seed)
    storage.store_bundle(recipient, build_upload(seed), cap=100)
    send = Send(message_id=os.urandom(16), recipient=recipient, payload=os.urandom(100))
    relay = Relay(settings, storage)
    states_at_each_send = []

    class Connection:
        """What `serve_logged_in` uses of a connection that sends one Send."""

        logger = logging.getLogger("websockets.server")

        async def send(self, message: bytes) -> None:
            frame = ServerFrame.FromString(message).WhichOneof("frame")
            rows = storage.connection.execute("SELECT count(*) FROM messages").fetchone()[0]
            states_at_each_send.append((frame, storage.connection.in_transaction, rows))

        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield ClientFrame(send=send).SerializeToString()

    await relay.serve_logged_in(cast(ServerConnection, Connection()), os.urandom(32))

    assert states_at_each_send == [("logged_in", False, 0), ("stored", False, 1)]


async def test_relay_restarted_on_the_same_file_delivers_the_queued_message(
    settings: Settings, open_client: OpenClient
) -> None:
    sender_seed, recipient_seed = os.urandom(32), os.urandom(32)
    recipient_key = derive_identity_key(recipient_seed)
    send = Send(message_id=os.urandom(16), recipient=recipient_key, payload=os.urandom(100))

    async with running_relay(settings) as url:
        await (await register(open_client, url, recipient_seed)).websocket.close()
        sender = await log_in(open_client, url, sender_seed)
        answer = await sender.ask(send)

    async with running_relay(settings) as url:
        recipient = await log_in(open_client, url, recipient_seed)
        delivery = await recipient.receive()

    assert answer == ServerFrame(stored=Stored(message_id=send.message_id))
    assert delivery.deliver == Deliver(
        message_id=send.message_id,
        sender=derive_identity_key(sender_seed),
        payload=send.payload,
    )


async def test_send_into_a_full_database_answers_storage_full_and_stores_nothing(
    settings: Settings, open_client: OpenClient, caplog: pytest.LogCaptureFixture
) -> None:
    recipient_seed = os.urandom(32)
    recipient_key = derive_identity_key(recipient_seed)
    # The payload alone needs 16 pages.
    too_large = Send(
        message_id=os.urandom(16), recipient=recipient_key, payload=bytes(MAX_PAYLOAD_BYTES)
    )
    small = Send(message_id=os.urandom(16), recipient=recipient_key, payload=os.urandom(100))

    async with running_relay(replace(settings, max_pages=FEW_PAGES)) as url:
        await register(open_client, url, recipient_seed)
        sender = await log_in(open_client, url, os.urandom(32))
        refused = await sender.ask(too_large)
        rows_after_the_refusal = messages_in(settings)
        accepted = await sender.ask(small)

    assert refused == ServerFrame(
        error=Error(code=ErrorCode.STORAGE_FULL, message_id=too_large.message_id)
    )
    assert rows_after_the_refusal == []
    assert accepted == ServerFrame(stored=Stored(message_id=small.message_id))
    assert caplog.messages.count("the database is full") == 1


async def test_failed_send_closes_with_1011_and_the_relay_serves_on(
    settings: Settings,
    open_client: OpenClient,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    recipient_seed = os.urandom(32)
    recipient_key = derive_identity_key(recipient_seed)
    send = Send(message_id=os.urandom(16), recipient=recipient_key, payload=os.urandom(100))
    monkeypatch.setattr(
        storage_module, "STORE_MESSAGE", "INSERT INTO no_such_table VALUES (?, ?, ?, ?, ?)"
    )

    async with running_relay(settings) as url:
        await register(open_client, url, recipient_seed)
        sender = await log_in(open_client, url, os.urandom(32))
        await sender.send(ClientFrame(send=send))
        closing_of_the_sender = await sender.frames_until_close()
        rows_after_the_failure = messages_in(settings)
        monkeypatch.undo()
        sender_again = await log_in(open_client, url, os.urandom(32))
        retry = await sender_again.ask(send)

    failures = [record for record in caplog.records if record.levelno == logging.ERROR]
    assert closing_of_the_sender == ([], INTERNAL_ERROR)
    assert [failure.getMessage() for failure in failures] == ["connection handler failed"]
    assert rows_after_the_failure == []
    assert retry == ServerFrame(stored=Stored(message_id=send.message_id))


async def test_failed_delivery_closes_with_1011_and_the_message_stays_queued(
    settings: Settings,
    open_client: OpenClient,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    sender_seed, recipient_seed = os.urandom(32), os.urandom(32)
    recipient_key = derive_identity_key(recipient_seed)
    send = Send(message_id=os.urandom(16), recipient=recipient_key, payload=os.urandom(100))
    no_table = "SELECT * FROM no_such_table WHERE ? AND ?"

    async with running_relay(settings) as url:
        await (await register(open_client, url, recipient_seed)).websocket.close()
        sender = await log_in(open_client, url, sender_seed)
        await sender.ask(send)
        monkeypatch.setattr(storage_module, "READ_NEXT_MESSAGE", no_table)
        recipient = await log_in(open_client, url, recipient_seed)
        closing_of_the_recipient = await recipient.frames_until_close()
        monkeypatch.undo()
        recipient_again = await log_in(open_client, url, recipient_seed)
        delivery = await recipient_again.receive()

    failures = [record for record in caplog.records if record.levelno == logging.ERROR]
    assert closing_of_the_recipient == ([], INTERNAL_ERROR)
    assert [failure.getMessage() for failure in failures] == ["connection handler failed"]
    assert delivery.deliver.message_id == send.message_id
