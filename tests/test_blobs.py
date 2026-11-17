"""The blob frames of docs/protocol.md, part 3: sections 30 and 31."""

import asyncio
import logging
import os
import sqlite3
from collections.abc import AsyncIterator, Callable
from contextlib import closing
from dataclasses import dataclass, replace
from typing import cast

import pytest
from relay_harness import (
    PATIENCE_SECONDS,
    Clock,
    OpenClient,
    RawClient,
    build_upload,
    frame_of,
    running_relay,
    traces_in,
)
from websockets.asyncio.server import ServerConnection

from sotto.crypto.identity import derive_identity_key
from sotto.proto.sotto_pb2 import (
    BlobData,
    BlobStored,
    ClientFrame,
    DeleteBlob,
    Error,
    ErrorCode,
    FetchBlob,
    PutBlob,
    ServerFrame,
    StartBlob,
)
from sotto.relay.frames import BLOB_CHUNK_BYTES
from sotto.relay.server import Relay
from sotto.relay.settings import Settings
from sotto.relay.storage import Storage

CHUNK = BLOB_CHUNK_BYTES
BLOB_LENGTH = 2 * CHUNK + 1000
DEFAULT_BLOB_MAX_BYTES = 104883216
PROTOCOL_VIOLATION = 1008
TTL_SECONDS = 100
SWEEP_SECONDS = 0.01
# The empty schema takes 12 pages and a piece of BLOB_CHUNK_BYTES 17.
FEW_PAGES = 64
# secure_delete clears whole pages, so a sample from every page of a blob shows its bytes.
SAMPLE_STEP = 4096
SAMPLE_BYTES = 64


@dataclass(frozen=True, slots=True)
class Pair:
    """An uploader and a registered recipient, logged in to one relay."""

    uploader_seed: bytes
    uploader: RawClient
    recipient_seed: bytes
    recipient: RawClient

    @property
    def uploader_key(self) -> bytes:
        return derive_identity_key(self.uploader_seed)

    @property
    def recipient_key(self) -> bytes:
        return derive_identity_key(self.recipient_seed)

    def start(self, length: int = BLOB_LENGTH, blob_id: bytes | None = None) -> StartBlob:
        blob_id = os.urandom(16) if blob_id is None else blob_id
        return StartBlob(blob_id=blob_id, recipient=self.recipient_key, length=length)

    def fetch(self, start: StartBlob, offset: int = 0, length: int = CHUNK) -> FetchBlob:
        return FetchBlob(
            blob_id=start.blob_id, uploader=self.uploader_key, offset=offset, length=length
        )

    def delete(self, start: StartBlob) -> ClientFrame:
        return ClientFrame(
            delete_blob=DeleteBlob(blob_id=start.blob_id, uploader=self.uploader_key)
        )


async def log_in(open_client: OpenClient, url: str, seed: bytes) -> RawClient:
    client = await open_client(url)
    answer = await client.log_in(seed)
    assert answer.WhichOneof("frame") == "logged_in"
    return client


async def connect_pair(open_client: OpenClient, url: str) -> Pair:
    uploader_seed, recipient_seed = os.urandom(32), os.urandom(32)
    recipient = await log_in(open_client, url, recipient_seed)
    registered = await recipient.ask(build_upload(recipient_seed))
    assert registered.WhichOneof("frame") == "bundle_stored"
    uploader = await log_in(open_client, url, uploader_seed)
    return Pair(uploader_seed, uploader, recipient_seed, recipient)


def stored(blob_id: bytes, stored_length: int) -> ServerFrame:
    return ServerFrame(blob_stored=BlobStored(blob_id=blob_id, stored_length=stored_length))


def refused(code: ErrorCode, blob_id: bytes, uploader: bytes = b"") -> ServerFrame:
    return ServerFrame(error=Error(code=code, blob_id=blob_id, identity=uploader))


def pieces_of(start: StartBlob, blob: bytes, offset: int = 0) -> list[PutBlob]:
    return [
        PutBlob(blob_id=start.blob_id, offset=piece, data=blob[piece : piece + CHUNK])
        for piece in range(offset, len(blob), CHUNK)
    ]


async def put_all(client: RawClient, puts: list[PutBlob]) -> list[ServerFrame]:
    """Sends every piece before it reads an answer, as a client MAY (section 30.1)."""
    for put in puts:
        await client.send(frame_of(put))
    return [await client.receive() for _ in puts]


async def download(pair: Pair, client: RawClient, start: StartBlob, offset: int = 0) -> bytes:
    data = b""
    for piece in range(offset, start.length, CHUNK):
        answer = await client.ask(pair.fetch(start, piece))
        data += answer.blob_data.data
    return data


async def upload_blob(pair: Pair, length: int = BLOB_LENGTH) -> tuple[StartBlob, bytes]:
    start, blob = pair.start(length), os.urandom(length)
    assert await pair.uploader.ask(start) == stored(start.blob_id, 0)
    answers = await put_all(pair.uploader, pieces_of(start, blob))
    assert answers[-1] == stored(start.blob_id, length)
    return start, blob


def blobs_in(settings: Settings) -> list[tuple[bytes, int, int]]:
    """Reads the blob id, length and stored length of every blob from the file."""
    with closing(sqlite3.connect(settings.database)) as database:
        rows = database.execute(
            "SELECT blob_id, length, stored_length FROM blobs ORDER BY position"
        ).fetchall()
    return rows


async def eventually(condition: Callable[[], bool]) -> None:
    for _ in range(int(PATIENCE_SECONDS / SWEEP_SECONDS)):
        if condition():
            return
        await asyncio.sleep(SWEEP_SECONDS)
    assert condition()


@pytest.mark.stand
async def test_logged_in_announces_the_largest_blob(
    relay_url: str, open_client: OpenClient
) -> None:
    client = await open_client(relay_url)

    answer = await client.log_in(os.urandom(32))

    assert answer.logged_in.blob_max_bytes == DEFAULT_BLOB_MAX_BYTES


@pytest.mark.stand
async def test_blob_frame_before_the_login_closes_with_1008(
    relay_url: str, open_client: OpenClient
) -> None:
    client = await open_client(relay_url)
    start = StartBlob(blob_id=os.urandom(16), recipient=os.urandom(32), length=1)

    await client.send(ClientFrame(start_blob=start))

    assert await client.frames_until_close() == ([], PROTOCOL_VIOLATION)


@pytest.mark.stand
async def test_blob_uploaded_in_pieces_is_fetched_byte_for_byte_by_its_recipient(
    relay_url: str, open_client: OpenClient
) -> None:
    pair = await connect_pair(open_client, relay_url)
    start, blob = pair.start(), os.urandom(BLOB_LENGTH)

    started = await pair.uploader.ask(start)
    answers = await put_all(pair.uploader, pieces_of(start, blob))
    fetched = await download(pair, pair.recipient, start)
    across_two_pieces = await pair.recipient.ask(pair.fetch(start, CHUNK - 5, 10))
    past_the_end = await pair.recipient.ask(pair.fetch(start, BLOB_LENGTH - 10))
    at_the_end = await pair.recipient.ask(pair.fetch(start, BLOB_LENGTH))
    fetched_again = await download(pair, pair.recipient, start)

    assert started == stored(start.blob_id, 0)
    assert answers == [
        stored(start.blob_id, CHUNK),
        stored(start.blob_id, 2 * CHUNK),
        stored(start.blob_id, BLOB_LENGTH),
    ]
    assert fetched == fetched_again == blob
    assert across_two_pieces.blob_data.data == blob[CHUNK - 5 : CHUNK + 5]
    assert past_the_end.blob_data.data == blob[-10:]
    assert at_the_end == ServerFrame(
        blob_data=BlobData(
            blob_id=start.blob_id, uploader=pair.uploader_key, offset=BLOB_LENGTH, data=b""
        )
    )


@pytest.mark.stand
async def test_repeated_start_answers_the_stored_length_and_looks_at_nothing_else(
    relay_url: str, open_client: OpenClient
) -> None:
    pair = await connect_pair(open_client, relay_url)
    start, blob = pair.start(), os.urandom(BLOB_LENGTH)
    await pair.uploader.ask(start)
    await put_all(pair.uploader, pieces_of(start, blob)[:1])
    other = StartBlob(blob_id=start.blob_id, recipient=os.urandom(32), length=1)

    again = await pair.uploader.ask(start)
    with_other_fields = await pair.uploader.ask(other)
    await put_all(pair.uploader, pieces_of(start, blob, CHUNK))
    fetched = await download(pair, pair.recipient, start)

    assert again == with_other_fields == stored(start.blob_id, CHUNK)
    assert fetched == blob


@pytest.mark.stand
async def test_put_at_another_offset_than_the_stored_length_stores_nothing(
    relay_url: str, open_client: OpenClient
) -> None:
    pair = await connect_pair(open_client, relay_url)
    start, blob = pair.start(), os.urandom(BLOB_LENGTH)
    first, second, third = pieces_of(start, blob)
    await pair.uploader.ask(start)
    await pair.uploader.ask(first)

    repeated = await pair.uploader.ask(first)
    ahead = await pair.uploader.ask(third)
    rest = await put_all(pair.uploader, [second, third])
    fetched = await download(pair, pair.recipient, start)

    assert repeated == ahead == stored(start.blob_id, CHUNK)
    assert rest[-1] == stored(start.blob_id, BLOB_LENGTH)
    assert fetched == blob


@pytest.mark.stand
async def test_piece_that_ends_past_the_length_is_blob_too_large_and_stores_nothing(
    relay_url: str, open_client: OpenClient
) -> None:
    pair = await connect_pair(open_client, relay_url)
    start, blob = pair.start(100), os.urandom(101)
    await pair.uploader.ask(start)

    too_long = await pair.uploader.ask(PutBlob(blob_id=start.blob_id, offset=0, data=blob))
    exact = await pair.uploader.ask(PutBlob(blob_id=start.blob_id, offset=0, data=blob[:100]))
    behind_the_end = await pair.uploader.ask(
        PutBlob(blob_id=start.blob_id, offset=100, data=blob[100:])
    )
    fetched = await pair.recipient.ask(pair.fetch(start))

    assert too_long == behind_the_end == refused(ErrorCode.BLOB_TOO_LARGE, start.blob_id)
    assert exact == stored(start.blob_id, 100)
    assert fetched.blob_data.data == blob[:100]


@pytest.mark.stand
async def test_start_longer_than_the_largest_blob_is_blob_too_large(
    relay_url: str, open_client: OpenClient
) -> None:
    pair = await connect_pair(open_client, relay_url)
    too_long = pair.start(DEFAULT_BLOB_MAX_BYTES + 1)
    largest = pair.start(DEFAULT_BLOB_MAX_BYTES)

    refusal = await pair.uploader.ask(too_long)
    accepted = await pair.uploader.ask(largest)
    await pair.uploader.send(pair.delete(largest))
    after_the_refusal = await pair.uploader.ask(pair.start(1, too_long.blob_id))

    assert refusal == refused(ErrorCode.BLOB_TOO_LARGE, too_long.blob_id)
    assert accepted == stored(largest.blob_id, 0)
    assert after_the_refusal == stored(too_long.blob_id, 0)


@pytest.mark.stand
async def test_start_to_an_unregistered_recipient_is_unknown_recipient(
    relay_url: str, open_client: OpenClient
) -> None:
    pair = await connect_pair(open_client, relay_url)
    start = pair.start()
    to_nobody = StartBlob(blob_id=start.blob_id, recipient=os.urandom(32), length=1)

    refusal = await pair.uploader.ask(to_nobody)
    after_the_refusal = await pair.uploader.ask(start)

    assert refusal == refused(ErrorCode.UNKNOWN_RECIPIENT, start.blob_id)
    assert after_the_refusal == stored(start.blob_id, 0)


@pytest.mark.stand
async def test_put_of_an_unknown_blob_or_of_another_uploader_is_not_found(
    relay_url: str, open_client: OpenClient
) -> None:
    pair = await connect_pair(open_client, relay_url)
    someone = await log_in(open_client, relay_url, os.urandom(32))
    start, blob = pair.start(), os.urandom(BLOB_LENGTH)
    first = pieces_of(start, blob)[0]
    await pair.uploader.ask(start)

    by_someone = await someone.ask(first)
    unknown = await pair.uploader.ask(PutBlob(blob_id=os.urandom(16), offset=0, data=b"x"))
    progress = await pair.uploader.ask(start)

    assert by_someone == refused(ErrorCode.NOT_FOUND, start.blob_id)
    assert unknown.error.code == ErrorCode.NOT_FOUND
    assert progress == stored(start.blob_id, 0)


@pytest.mark.stand
async def test_fetch_of_a_blob_that_is_not_a_complete_one_of_the_recipient_is_not_found(
    relay_url: str, open_client: OpenClient
) -> None:
    pair = await connect_pair(open_client, relay_url)
    someone = await log_in(open_client, relay_url, os.urandom(32))
    start, blob = pair.start(), os.urandom(BLOB_LENGTH)
    await pair.uploader.ask(start)
    await put_all(pair.uploader, pieces_of(start, blob)[:2])
    not_found = refused(ErrorCode.NOT_FOUND, start.blob_id, pair.uploader_key)

    incomplete = await pair.recipient.ask(pair.fetch(start))
    await put_all(pair.uploader, pieces_of(start, blob, 2 * CHUNK))
    by_the_uploader = await pair.uploader.ask(pair.fetch(start))
    by_someone = await someone.ask(pair.fetch(start))
    other_uploader = await pair.recipient.ask(
        FetchBlob(blob_id=start.blob_id, uploader=os.urandom(32), offset=0, length=CHUNK)
    )
    unknown = await pair.recipient.ask(pair.fetch(pair.start()))
    by_the_recipient = await pair.recipient.ask(pair.fetch(start))

    assert incomplete == by_the_uploader == by_someone == not_found
    assert other_uploader.error.code == unknown.error.code == ErrorCode.NOT_FOUND
    assert by_the_recipient.blob_data.data == blob[:CHUNK]


@pytest.mark.stand
async def test_recipient_deletes_only_a_complete_blob_and_a_start_after_it_is_a_new_blob(
    relay_url: str, open_client: OpenClient
) -> None:
    pair = await connect_pair(open_client, relay_url)
    someone = await log_in(open_client, relay_url, os.urandom(32))
    start, blob = pair.start(), os.urandom(BLOB_LENGTH)
    pieces = pieces_of(start, blob)
    await pair.uploader.ask(start)
    await pair.uploader.ask(pieces[0])

    await pair.recipient.send(pair.delete(start))
    progress_after_an_early_delete = await pair.uploader.ask(start)
    await put_all(pair.uploader, pieces[1:])
    await someone.send(pair.delete(start))
    after_the_delete_of_someone = await pair.recipient.ask(pair.fetch(start))
    await pair.recipient.send(pair.delete(start))
    await pair.recipient.send(pair.delete(start))
    after_the_delete = await pair.recipient.ask(pair.fetch(start))
    started_again = await pair.uploader.ask(start)

    assert progress_after_an_early_delete == stored(start.blob_id, CHUNK)
    assert after_the_delete_of_someone.blob_data.data == blob[:CHUNK]
    assert after_the_delete == refused(ErrorCode.NOT_FOUND, start.blob_id, pair.uploader_key)
    assert started_again == stored(start.blob_id, 0)


@pytest.mark.stand
async def test_uploader_deletes_its_blob_complete_or_not(
    relay_url: str, open_client: OpenClient
) -> None:
    pair = await connect_pair(open_client, relay_url)
    incomplete, blob = pair.start(), os.urandom(BLOB_LENGTH)
    await pair.uploader.ask(incomplete)
    await pair.uploader.ask(pieces_of(incomplete, blob)[0])
    complete, _ = await upload_blob(pair)

    await pair.uploader.send(pair.delete(incomplete))
    await pair.uploader.send(pair.delete(complete))
    put_after_the_delete = await pair.uploader.ask(pieces_of(incomplete, blob)[1])
    fetch_after_the_delete = await pair.recipient.ask(pair.fetch(complete))

    assert put_after_the_delete == refused(ErrorCode.NOT_FOUND, incomplete.blob_id)
    assert fetch_after_the_delete.error.code == ErrorCode.NOT_FOUND


async def test_start_over_the_quota_is_quota_full_and_a_deletion_makes_room(
    settings: Settings, open_client: OpenClient
) -> None:
    small = replace(settings, blob_max_bytes=1000, blob_quota_bytes=1000)

    async with running_relay(small) as url:
        pair = await connect_pair(open_client, url)
        first, second = pair.start(600), pair.start(401)
        await pair.uploader.ask(first)
        over = await pair.uploader.ask(second)
        up_to_the_quota = await pair.uploader.ask(pair.start(400, second.blob_id))
        await pair.uploader.send(pair.delete(first))
        after_the_delete = await pair.uploader.ask(pair.start(600))

    assert over == refused(ErrorCode.QUOTA_FULL, second.blob_id)
    assert up_to_the_quota == stored(second.blob_id, 0)
    assert after_the_delete.WhichOneof("frame") == "blob_stored"


async def test_start_takes_a_token_and_put_fetch_and_delete_take_none(
    settings: Settings, open_client: OpenClient
) -> None:
    one_token = replace(settings, frame_bucket_size=1)
    frozen = Clock()

    async with running_relay(one_token, monotonic=frozen) as url:
        pair = await connect_pair(open_client, url)
        start, blob = pair.start(), os.urandom(BLOB_LENGTH)
        other = pair.start()
        started = await pair.uploader.ask(start)
        limited = await pair.uploader.ask(other)
        answers = await put_all(pair.uploader, pieces_of(start, blob))
        fetched = await download(pair, pair.recipient, start)
        await pair.recipient.send(pair.delete(start))
        after_the_delete = await pair.recipient.ask(pair.fetch(start))
        rows = blobs_in(one_token)

    assert started == stored(start.blob_id, 0)
    assert limited == refused(ErrorCode.RATE_LIMITED, other.blob_id)
    assert answers[-1] == stored(start.blob_id, BLOB_LENGTH)
    assert fetched == blob
    assert after_the_delete.error.code == ErrorCode.NOT_FOUND
    assert rows == []


@pytest.mark.stand
async def test_upload_cut_with_its_connection_goes_on_from_the_stored_length(
    relay_url: str, open_client: OpenClient
) -> None:
    pair = await connect_pair(open_client, relay_url)
    start, blob = pair.start(), os.urandom(BLOB_LENGTH)
    first, second, third = pieces_of(start, blob)
    await pair.uploader.ask(start)
    await put_all(pair.uploader, [first, second])
    # The answer of the last piece is lost with the connection.
    await pair.uploader.send(frame_of(third))
    await pair.uploader.websocket.close()

    uploader_again = await log_in(open_client, relay_url, pair.uploader_seed)
    resumed = (await uploader_again.ask(start)).blob_stored
    repeated = await uploader_again.ask(first)
    rest = await put_all(uploader_again, pieces_of(start, blob, resumed.stored_length))
    fetched = await download(pair, pair.recipient, start)

    assert resumed.stored_length in {2 * CHUNK, BLOB_LENGTH}
    assert repeated == stored(start.blob_id, resumed.stored_length)
    assert [answer.blob_stored.stored_length for answer in rest] in ([], [BLOB_LENGTH])
    assert fetched == blob


@pytest.mark.stand
async def test_download_cut_with_its_connection_goes_on_from_the_bytes_it_holds(
    relay_url: str, open_client: OpenClient
) -> None:
    pair = await connect_pair(open_client, relay_url)
    start, blob = await upload_blob(pair)
    held = (await pair.recipient.ask(pair.fetch(start))).blob_data.data
    await pair.recipient.send(frame_of(pair.fetch(start, CHUNK)))
    await pair.recipient.websocket.close()

    recipient_again = await log_in(open_client, relay_url, pair.recipient_seed)
    rest = await download(pair, recipient_again, start, len(held))
    from_the_start = await download(pair, recipient_again, start)

    assert held + rest == from_the_start == blob


async def test_upload_goes_on_from_the_stored_length_after_a_restart_of_the_relay(
    settings: Settings, open_client: OpenClient
) -> None:
    async with running_relay(settings) as url:
        pair = await connect_pair(open_client, url)
        start, blob = pair.start(), os.urandom(BLOB_LENGTH)
        await pair.uploader.ask(start)
        before = await put_all(pair.uploader, pieces_of(start, blob)[:2])

    async with running_relay(settings) as url:
        uploader = await log_in(open_client, url, pair.uploader_seed)
        recipient = await log_in(open_client, url, pair.recipient_seed)
        resumed = await uploader.ask(start)
        await put_all(uploader, pieces_of(start, blob, 2 * CHUNK))
        fetched = await download(pair, recipient, start)

    assert before[-1] == resumed == stored(start.blob_id, 2 * CHUNK)
    assert fetched == blob


async def test_blob_stored_is_sent_after_the_commit_of_the_piece(
    settings: Settings, storage: Storage
) -> None:
    uploader, recipient_seed = os.urandom(32), os.urandom(32)
    recipient = derive_identity_key(recipient_seed)
    storage.store_bundle(recipient, build_upload(recipient_seed), cap=100)
    start = StartBlob(blob_id=os.urandom(16), recipient=recipient, length=100)
    storage.start_blob(uploader, start, max_bytes=100, quota_bytes=100)
    put = PutBlob(blob_id=start.blob_id, offset=0, data=os.urandom(100))
    relay = Relay(settings, storage)
    states_at_each_send = []

    class Connection:
        """What `serve_logged_in` uses of a connection that sends one PutBlob."""

        logger = logging.getLogger("websockets.server")

        async def send(self, message: bytes) -> None:
            frame = ServerFrame.FromString(message).WhichOneof("frame")
            stored_length = storage.connection.execute(
                "SELECT stored_length FROM blobs"
            ).fetchone()[0]
            states_at_each_send.append(
                (frame, storage.connection.in_transaction, stored_length)
            )

        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield ClientFrame(put_blob=put).SerializeToString()

    await relay.serve_logged_in(cast(ServerConnection, Connection()), uploader)

    assert states_at_each_send == [("logged_in", False, 0), ("blob_stored", False, 100)]


async def test_start_and_put_into_a_full_database_answer_storage_full_and_the_relay_serves_on(
    settings: Settings, open_client: OpenClient, caplog: pytest.LogCaptureFixture
) -> None:
    full = replace(settings, max_pages=FEW_PAGES)
    filler = StartBlob()
    put_refusal = start_refusal = ServerFrame()

    async with running_relay(full) as url:
        pair = await connect_pair(open_client, url)
        start, blob = pair.start(10 * CHUNK), os.urandom(10 * CHUNK)
        await pair.uploader.ask(start)
        for put in pieces_of(start, blob):
            put_refusal = await pair.uploader.ask(put)
            if put_refusal.WhichOneof("frame") == "error":
                break
        progress = await pair.uploader.ask(start)
        for _ in range(500):
            filler = pair.start(1)
            start_refusal = await pair.uploader.ask(filler)
            if start_refusal.WhichOneof("frame") == "error":
                break
        next_piece = pieces_of(start, blob, progress.blob_stored.stored_length)[0]
        put_again = await pair.uploader.ask(next_piece)
        await pair.uploader.send(pair.delete(start))
        after_the_delete = await pair.uploader.ask(filler)

    assert put_refusal == refused(ErrorCode.STORAGE_FULL, start.blob_id)
    assert start_refusal == refused(ErrorCode.STORAGE_FULL, filler.blob_id)
    assert put_again == put_refusal
    assert progress.blob_stored.stored_length > 0
    assert after_the_delete == stored(filler.blob_id, 0)
    assert caplog.messages.count("the database is full") == 3


async def test_blob_expires_its_ttl_after_its_last_write_complete_or_not(
    settings: Settings, open_client: OpenClient, caplog: pytest.LogCaptureFixture
) -> None:
    clock = Clock()
    sweeping = replace(
        settings, blob_ttl_seconds=TTL_SECONDS, sweep_interval_seconds=SWEEP_SECONDS
    )

    async with running_relay(sweeping, clock=clock) as url:
        pair = await connect_pair(open_client, url)
        complete, _ = await upload_blob(pair, 100)
        incomplete = pair.start(100)
        await pair.uploader.ask(incomplete)
        written_later, later_blob = pair.start(200), os.urandom(200)
        await pair.uploader.ask(written_later)
        await pair.uploader.ask(pieces_of(written_later, later_blob[:100])[0])
        clock.now += TTL_SECONDS // 2
        await put_all(pair.uploader, pieces_of(written_later, later_blob, 100))
        clock.now += TTL_SECONDS // 2 - 1
        await asyncio.sleep(10 * SWEEP_SECONDS)
        before_the_ttl = len(blobs_in(sweeping))
        clock.now += 1
        await eventually(lambda: len(blobs_in(sweeping)) == 1)
        fetch_of_the_expired = await pair.recipient.ask(pair.fetch(complete))
        put_of_the_expired = await pair.uploader.ask(
            PutBlob(blob_id=incomplete.blob_id, offset=0, data=b"x")
        )
        fetch_of_the_later = await pair.recipient.ask(pair.fetch(written_later))
        clock.now += TTL_SECONDS // 2
        await eventually(lambda: not blobs_in(sweeping))
        fetch_after_its_ttl = await pair.recipient.ask(pair.fetch(written_later))

    assert before_the_ttl == 3
    assert fetch_of_the_expired.error.code == ErrorCode.NOT_FOUND
    assert put_of_the_expired == refused(ErrorCode.NOT_FOUND, incomplete.blob_id)
    assert fetch_of_the_later.blob_data.data == later_blob
    assert fetch_after_its_ttl.error.code == ErrorCode.NOT_FOUND
    assert "the sweep deleted 2 expired blobs" in caplog.messages
    assert "the sweep deleted 1 expired blobs" in caplog.messages


def blob_traces_in(settings: Settings, start: StartBlob, blob: bytes) -> list[str]:
    samples = {
        f"blob at {offset}": blob[offset : offset + SAMPLE_BYTES]
        for offset in range(0, len(blob), SAMPLE_STEP)
    }
    return traces_in(settings, {"blob id": start.blob_id, **samples})


@pytest.mark.parametrize("deletion", ["by the recipient", "by the uploader", "by expiry"])
def test_deleted_blob_is_in_no_file_of_the_database_after_the_sweep(
    settings: Settings, deletion: str
) -> None:
    clock = Clock()
    uploader, recipient_seed = os.urandom(32), os.urandom(32)
    recipient = derive_identity_key(recipient_seed)
    blob = os.urandom(CHUNK + 5000)
    start = StartBlob(blob_id=os.urandom(16), recipient=recipient, length=len(blob))

    storage = Storage(settings.database, max_pages=settings.max_pages, clock=clock)
    with closing(storage):
        storage.store_bundle(recipient, build_upload(recipient_seed), cap=100)
        storage.start_blob(uploader, start, max_bytes=len(blob), quota_bytes=len(blob))
        for put in pieces_of(start, blob):
            storage.put_blob(uploader, put)
        traces_before = blob_traces_in(settings, start, blob)
        delete = DeleteBlob(blob_id=start.blob_id, uploader=uploader)
        match deletion:
            case "by the recipient":
                assert storage.delete_blob(recipient, delete)
            case "by the uploader":
                assert storage.delete_blob(uploader, delete)
            case "by expiry":
                clock.now += TTL_SECONDS
        swept = storage.sweep(ttl_seconds=TTL_SECONDS, blob_ttl_seconds=TTL_SECONDS)
        traces_after = blob_traces_in(settings, start, blob)
        log_bytes = settings.database.with_name("relay.db-wal").stat().st_size

    assert len(traces_before) == 1 + len(range(0, len(blob), SAMPLE_STEP))
    assert swept.blobs == (1 if deletion == "by expiry" else 0)
    assert traces_after == []
    assert log_bytes == 0
