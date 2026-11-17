"""Files between two network clients (docs/protocol.md, section 33): each transfer ends
with the file whole at the recipient or as a reported failure, whatever breaks."""

import asyncio
import hashlib
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from client_harness import befriend
from relay_harness import Clock, blobs_in, messages_in, running_relay
from transport_harness import (
    PATIENCE_SECONDS,
    AsyncTasks,
    Cut,
    MakeClient,
    Message,
    TamperingProxy,
    client_kind_of,
    free_port,
    is_registered,
    kind_of,
    next_event,
    running,
    tampering_proxy,
    until,
)

from sotto.client.files import OWN_NAME
from sotto.client.session import (
    Client,
    FileState,
    FilesUnsupportedError,
    FileTooLargeError,
    NotAContactError,
)
from sotto.client.store import Store
from sotto.client.transport import (
    Connected,
    FileUpdate,
    Incoming,
    TransferFailed,
    Transport,
)
from sotto.crypto.blob import MAX_FILE_BYTES, blob_length, digest_of
from sotto.proto.sotto_pb2 import (
    Attachment,
    ClientFrame,
    Error,
    ErrorCode,
    ServerFrame,
)
from sotto.relay.frames import BLOB_CHUNK_BYTES
from sotto.relay.settings import Settings

FILE_SIZE = 200_000
FINAL_STATES = frozenset(
    {
        FileState.SENT,
        FileState.NOT_SENT,
        FileState.RECEIVED,
        FileState.NOT_RECEIVED,
        FileState.NOT_AVAILABLE,
    }
)


@dataclass(frozen=True, slots=True)
class Pair:
    alice: Client
    bob: Client
    file: Path
    received: Path

    def received_files(self) -> list[Path]:
        if not self.received.exists():
            return []
        return sorted(self.received.iterdir())


@pytest.fixture
def pair(make_client: MakeClient, tmp_path: Path) -> Pair:
    alice, bob = make_client("alice"), make_client("bob")
    befriend(alice, bob)
    file = tmp_path / "photo.jpg"
    file.write_bytes(os.urandom(FILE_SIZE))
    return Pair(alice, bob, file, tmp_path / "bob-files")


async def final_update(transport: Transport) -> FileUpdate:
    """The next FileUpdate that ends a transfer."""
    async with asyncio.timeout(PATIENCE_SECONDS):
        while True:
            update = await next_event(transport, FileUpdate)
            if update.state in FINAL_STATES:
                return update


async def registered(bob: Client, url: str) -> None:
    async with running(bob, url):
        await until(is_registered(bob))


def frames_to_relay(proxy: TamperingProxy, kind: str, connection: int) -> list[ClientFrame]:
    return [
        ClientFrame.FromString(sent)
        for number, sent in proxy.sent_to_relay
        if number == connection and client_kind_of(sent) == kind
    ]


def nth(kind: str, number: int, connection: int = 1) -> Callable[[int, Message], bool]:
    """True for the frame of `kind` that is the `number`-th of its kind on the connection;
    a kind of ClientFrame is read from the frames to the relay, any other from the relay."""
    read_kind = client_kind_of if kind in ClientFrame.DESCRIPTOR.fields_by_name else kind_of
    seen = 0

    def matches(on: int, message: Message) -> bool:
        nonlocal seen
        if on != connection or read_kind(message) != kind:
            return False
        seen += 1
        return seen == number

    return matches


def cut_at(
    matches: Callable[[int, Message], bool],
) -> Callable[[int, Message], Message | None]:
    def edit(connection: int, message: Message) -> Message | None:
        if matches(connection, message):
            raise Cut
        return message

    return edit


def drop_at(
    matches: Callable[[int, Message], bool], dropped: asyncio.Event
) -> Callable[[int, Message], Message | None]:
    """Drops one frame and every frame after it on its connection: the transfer stalls."""

    def edit(connection: int, message: Message) -> Message | None:
        if dropped.is_set() and connection == 1:
            return None
        if matches(connection, message):
            dropped.set()
            return None
        return message

    return edit


def edit_server_frame(
    kind: str, change: Callable[[ServerFrame], None], *, connection: int = 1, number: int = 1
) -> Callable[[int, Message], Message | None]:
    matches = nth(kind, number, connection)

    def edit(on: int, message: Message) -> Message | None:
        if not matches(on, message):
            return message
        assert isinstance(message, bytes)
        frame = ServerFrame.FromString(message)
        change(frame)
        return frame.SerializeToString()

    return edit


async def test_file_of_four_pieces_is_received_byte_for_byte_and_its_blob_is_deleted(
    relay_url: str, settings: Settings, pair: Pair
) -> None:
    url = f"{relay_url}/ws"
    await registered(pair.bob, url)

    async with running(pair.alice, url) as alice_link:
        blob_id = await alice_link.send_file(pair.bob.identity_key, pair.file, caption="hi")
        sent = await final_update(alice_link)
    async with running(pair.bob, url, received_files=pair.received) as bob_link:
        offered = await next_event(bob_link, Incoming)
        received = await final_update(bob_link)
        await until(lambda: blobs_in(settings) == [])

    assert sent.state == FileState.SENT
    assert sent.blob_id == blob_id
    assert pair.alice.uploads() == []
    attachment = offered.received.attachment
    assert attachment is not None
    assert (attachment.file_name, attachment.caption) == ("photo.jpg", "hi")
    assert (attachment.media_type, attachment.size) == ("image/jpeg", FILE_SIZE)
    assert received.state == FileState.RECEIVED
    assert received.path == pair.received / "photo.jpg"
    assert pair.received_files() == [pair.received / "photo.jpg"]
    assert (pair.received / "photo.jpg").read_bytes() == pair.file.read_bytes()
    assert [file.state for file in pair.bob.store.files()] == [FileState.RECEIVED]


async def test_upload_cut_in_the_middle_goes_on_from_the_stored_length(
    relay_url: str, pair: Pair
) -> None:
    url = f"{relay_url}/ws"
    await registered(pair.bob, url)
    proxy = TamperingProxy(relay_url, to_relay=cut_at(nth("put_blob", 2)))

    async with tampering_proxy(proxy) as proxy_url, running(pair.alice, proxy_url) as link:
        await link.send_file(pair.bob.identity_key, pair.file)
        sent = await final_update(link)
    async with running(pair.bob, url, received_files=pair.received) as bob_link:
        received = await final_update(bob_link)

    resumed = frames_to_relay(proxy, "put_blob", connection=2)
    assert proxy.connections == 2
    assert sent.state == FileState.SENT
    assert resumed[0].put_blob.offset == BLOB_CHUNK_BYTES
    assert received.state == FileState.RECEIVED
    assert received.path is not None
    assert received.path.read_bytes() == pair.file.read_bytes()


async def test_download_cut_in_the_middle_goes_on_from_the_bytes_it_holds(
    relay_url: str, pair: Pair
) -> None:
    url = f"{relay_url}/ws"
    await registered(pair.bob, url)
    async with running(pair.alice, url) as alice_link:
        await alice_link.send_file(pair.bob.identity_key, pair.file)
        await final_update(alice_link)
    proxy = TamperingProxy(relay_url, to_client=cut_at(nth("blob_data", 2)))

    async with (
        tampering_proxy(proxy) as proxy_url,
        running(pair.bob, proxy_url, received_files=pair.received) as bob_link,
    ):
        received = await final_update(bob_link)

    resumed = frames_to_relay(proxy, "fetch_blob", connection=2)
    assert proxy.connections == 2
    assert resumed[0].fetch_blob.offset == BLOB_CHUNK_BYTES
    assert received.state == FileState.RECEIVED
    assert received.path is not None
    assert received.path.read_bytes() == pair.file.read_bytes()


async def test_relay_restarted_in_the_middle_of_an_upload_and_of_a_download(
    settings: Settings, pair: Pair
) -> None:
    settings = replace(settings, port=free_port())
    stalled = asyncio.Event()
    upstream = f"ws://127.0.0.1:{settings.port}"
    alice_proxy = TamperingProxy(upstream, to_relay=drop_at(nth("put_blob", 2), stalled))
    bob_proxy = TamperingProxy(upstream)

    async with (
        AsyncTasks() as tasks,
        tampering_proxy(alice_proxy) as alice_url,
        tampering_proxy(bob_proxy) as bob_url,
    ):
        alice_link = Transport(pair.alice, alice_url)
        bob_link = Transport(pair.bob, bob_url, received_files=pair.received)
        async with running_relay(settings):
            tasks.start(bob_link.run(), alice_link.run())
            await next_event(alice_link, Connected)
            await until(is_registered(pair.bob))
            await alice_link.send_file(pair.bob.identity_key, pair.file)
            await asyncio.wait_for(stalled.wait(), PATIENCE_SECONDS)

        stalled.clear()
        bob_proxy.to_client = drop_at(nth("blob_data", 2, connection=2), stalled)
        async with running_relay(settings):
            sent = await final_update(alice_link)
            await asyncio.wait_for(stalled.wait(), PATIENCE_SECONDS)
        async with running_relay(settings):
            received = await final_update(bob_link)

    assert sent.state == FileState.SENT
    assert frames_to_relay(alice_proxy, "put_blob", 2)[0].put_blob.offset == BLOB_CHUNK_BYTES
    assert frames_to_relay(bob_proxy, "fetch_blob", 3)[0].fetch_blob.offset > 0
    assert received.state == FileState.RECEIVED
    assert received.path is not None
    assert received.path.read_bytes() == pair.file.read_bytes()


async def test_client_restarted_in_the_middle_of_an_upload_and_of_a_download(
    relay_url: str, pair: Pair, make_client: MakeClient
) -> None:
    url = f"{relay_url}/ws"
    await registered(pair.bob, url)
    stalled = asyncio.Event()
    alice_proxy = TamperingProxy(relay_url, to_relay=drop_at(nth("put_blob", 2), stalled))
    async with tampering_proxy(alice_proxy) as proxy_url:
        async with running(pair.alice, proxy_url) as link:
            await link.send_file(pair.bob.identity_key, pair.file)
            await asyncio.wait_for(stalled.wait(), PATIENCE_SECONDS)
        pair.alice.store.close()
        alice = make_client("alice")
        async with running(alice, proxy_url) as link:
            sent = await final_update(link)

    stalled.clear()
    bob_proxy = TamperingProxy(relay_url, to_client=drop_at(nth("blob_data", 2), stalled))
    async with tampering_proxy(bob_proxy) as proxy_url:
        async with running(pair.bob, proxy_url, received_files=pair.received):
            await asyncio.wait_for(stalled.wait(), PATIENCE_SECONDS)
        pair.bob.store.close()
        bob = make_client("bob")
        async with running(bob, proxy_url, received_files=pair.received) as link:
            received = await final_update(link)

    assert sent.state == FileState.SENT
    assert frames_to_relay(alice_proxy, "put_blob", 2)[0].put_blob.offset == BLOB_CHUNK_BYTES
    assert frames_to_relay(bob_proxy, "fetch_blob", 2)[0].fetch_blob.offset == BLOB_CHUNK_BYTES
    assert received.state == FileState.RECEIVED
    assert received.path is not None
    assert received.path.read_bytes() == pair.file.read_bytes()


@pytest.mark.parametrize(
    ("result", "quota"), [("QUOTA_FULL", 1000), ("UNKNOWN_RECIPIENT", 2**28)]
)
async def test_refused_upload_is_not_sent_and_its_blob_is_deleted(
    settings: Settings, pair: Pair, result: str, quota: int
) -> None:
    refusing = replace(settings, blob_quota_bytes=quota)
    async with running_relay(refusing) as relay_url:
        if result != "UNKNOWN_RECIPIENT":
            await registered(pair.bob, f"{relay_url}/ws")
        proxy = TamperingProxy(relay_url)
        async with tampering_proxy(proxy) as proxy_url, running(pair.alice, proxy_url) as link:
            await link.send_file(pair.bob.identity_key, pair.file)
            not_sent = await final_update(link)
            await until(lambda: "delete_blob" in proxy.kinds())

    assert (not_sent.state, not_sent.result) == (FileState.NOT_SENT, result)
    assert pair.alice.uploads() == []
    assert pair.alice.outbox() == []
    assert "send" not in proxy.kinds()
    assert messages_in(refusing) == []
    assert blobs_in(refusing) == []


async def test_file_too_large_is_not_sent_and_sends_no_blob_frame(
    settings: Settings, pair: Pair, tmp_path: Path
) -> None:
    small_blobs = replace(settings, blob_max_bytes=blob_length(FILE_SIZE) - 1)
    largest = tmp_path / "largest.bin"
    with largest.open("wb") as sparse:
        sparse.truncate(MAX_FILE_BYTES + 1)

    async with running_relay(small_blobs) as relay_url:
        await registered(pair.bob, f"{relay_url}/ws")
        proxy = TamperingProxy(relay_url)
        async with tampering_proxy(proxy) as proxy_url, running(pair.alice, proxy_url) as link:
            with pytest.raises(FileTooLargeError):
                await link.send_file(pair.bob.identity_key, pair.file)
            with pytest.raises(FileTooLargeError):
                await link.send_file(pair.bob.identity_key, largest)

    assert pair.alice.uploads() == []
    assert not {"start_blob", "put_blob", "send"} & set(proxy.kinds())


def without_blobs(frame: ServerFrame) -> None:
    frame.logged_in.blob_max_bytes = 0


async def test_relay_that_announces_no_blobs_gets_no_blob_frame(
    relay_url: str, pair: Pair
) -> None:
    url = f"{relay_url}/ws"
    await registered(pair.bob, url)
    proxy = TamperingProxy(relay_url, to_client=edit_server_frame("logged_in", without_blobs))

    async with tampering_proxy(proxy) as proxy_url, running(pair.alice, proxy_url) as link:
        with pytest.raises(FilesUnsupportedError):
            await link.send_file(pair.bob.identity_key, pair.file)

    assert pair.alice.uploads() == []
    assert not {"start_blob", "put_blob", "delete_blob"} & set(proxy.kinds())


async def test_transfers_end_when_a_later_login_announces_no_blobs(
    relay_url: str, pair: Pair
) -> None:
    url = f"{relay_url}/ws"
    await registered(pair.bob, url)
    stalled = asyncio.Event()
    alice_proxy = TamperingProxy(relay_url, to_relay=drop_at(nth("put_blob", 2), stalled))
    async with tampering_proxy(alice_proxy) as proxy_url:
        async with running(pair.alice, proxy_url) as link:
            await link.send_file(pair.bob.identity_key, pair.file)
            await asyncio.wait_for(stalled.wait(), PATIENCE_SECONDS)
        alice_proxy.to_client = edit_server_frame("logged_in", without_blobs, connection=2)
        async with running(pair.alice, proxy_url) as link:
            not_sent = await final_update(link)
    async with running(pair.alice, url) as link:
        await link.send_file(pair.bob.identity_key, pair.file)
        await final_update(link)
    stalled.clear()
    bob_proxy = TamperingProxy(relay_url, to_client=drop_at(nth("blob_data", 2), stalled))
    async with tampering_proxy(bob_proxy) as proxy_url:
        async with running(pair.bob, proxy_url, received_files=pair.received):
            await asyncio.wait_for(stalled.wait(), PATIENCE_SECONDS)
        bob_proxy.to_client = edit_server_frame("logged_in", without_blobs, connection=2)
        async with running(pair.bob, proxy_url, received_files=pair.received) as link:
            not_received = await final_update(link)

    assert (not_sent.state, not_sent.result) == (FileState.NOT_SENT, "FILES_UNSUPPORTED")
    assert pair.alice.uploads() == []
    assert not {"start_blob", "put_blob", "delete_blob"} & set(alice_proxy.kinds(2))
    assert (not_received.state, not_received.result) == (
        FileState.NOT_RECEIVED,
        "FILES_UNSUPPORTED",
    )
    assert not {"fetch_blob", "delete_blob"} & set(bob_proxy.kinds(2))
    assert pair.received_files() == []


async def test_upload_whose_blob_expired_starts_again_from_0_with_the_same_blob(
    settings: Settings, pair: Pair
) -> None:
    clock = Clock()
    expiring = replace(settings, blob_ttl_seconds=100, sweep_interval_seconds=0.05)
    stalled = asyncio.Event()
    async with running_relay(expiring, clock=clock) as relay_url:
        await registered(pair.bob, f"{relay_url}/ws")
        proxy = TamperingProxy(relay_url, to_relay=drop_at(nth("put_blob", 2), stalled))
        async with tampering_proxy(proxy) as proxy_url:
            async with running(pair.alice, proxy_url) as link:
                blob_id = await link.send_file(pair.bob.identity_key, pair.file)
                await asyncio.wait_for(stalled.wait(), PATIENCE_SECONDS)
                clock.now += 100
                await until(lambda: blobs_in(expiring) == [])
            async with running(pair.alice, proxy_url) as link:
                sent = await final_update(link)
        async with running(pair.bob, f"{relay_url}/ws", received_files=pair.received) as link:
            received = await final_update(link)

    restarted = frames_to_relay(proxy, "start_blob", 2)
    assert sent.state == FileState.SENT
    assert [start.start_blob.blob_id for start in restarted] == [blob_id]
    assert frames_to_relay(proxy, "put_blob", 2)[0].put_blob.offset == 0
    assert received.path is not None
    assert received.path.read_bytes() == pair.file.read_bytes()


async def test_put_answered_not_found_starts_the_upload_again(
    relay_url: str, pair: Pair
) -> None:
    url = f"{relay_url}/ws"
    await registered(pair.bob, url)

    def not_found(frame: ServerFrame) -> None:
        blob_id = frame.blob_stored.blob_id
        frame.error.CopyFrom(Error(code=ErrorCode.NOT_FOUND, blob_id=blob_id))

    proxy = TamperingProxy(
        relay_url, to_client=edit_server_frame("blob_stored", not_found, number=3)
    )
    async with tampering_proxy(proxy) as proxy_url, running(pair.alice, proxy_url) as link:
        await link.send_file(pair.bob.identity_key, pair.file)
        sent = await final_update(link)
    async with running(pair.bob, url, received_files=pair.received) as link:
        received = await final_update(link)

    assert proxy.kinds(1).count("start_blob") == 2
    assert sent.state == FileState.SENT
    assert received.path is not None
    assert received.path.read_bytes() == pair.file.read_bytes()


async def test_expired_blob_is_not_available_and_its_message_stays(
    settings: Settings, pair: Pair
) -> None:
    clock = Clock()
    expiring = replace(settings, blob_ttl_seconds=100, sweep_interval_seconds=0.05)
    async with running_relay(expiring, clock=clock) as relay_url:
        url = f"{relay_url}/ws"
        await registered(pair.bob, url)
        async with running(pair.alice, url) as link:
            await link.send_file(pair.bob.identity_key, pair.file, caption="gone soon")
            await final_update(link)
        clock.now += 100
        await until(lambda: blobs_in(expiring) == [])
        async with running(pair.bob, url, received_files=pair.received) as link:
            offered = await next_event(link, Incoming)
            gone = await final_update(link)

    assert offered.received.attachment is not None
    assert offered.received.attachment.caption == "gone soon"
    assert (gone.state, gone.result) == (FileState.NOT_AVAILABLE, "BLOB_GONE")
    assert [file.state for file in pair.bob.store.files()] == [FileState.NOT_AVAILABLE]
    assert pair.received_files() == []


def flip_a_byte(frame: ServerFrame) -> None:
    data = frame.blob_data.data
    frame.blob_data.data = data[:10] + bytes([data[10] ^ 1]) + data[11:]


def cut_short(frame: ServerFrame) -> None:
    frame.blob_data.data = frame.blob_data.data[:-1]


def move_the_offset(frame: ServerFrame) -> None:
    frame.blob_data.offset += 1


def name_another_blob(frame: ServerFrame) -> None:
    frame.blob_data.blob_id = bytes(16)


@pytest.mark.parametrize(
    "change", [flip_a_byte, cut_short, move_the_offset, name_another_blob]
)
async def test_altered_or_truncated_blob_could_not_be_received_and_writes_nothing(
    relay_url: str, settings: Settings, pair: Pair, change: Callable[[ServerFrame], None]
) -> None:
    url = f"{relay_url}/ws"
    await registered(pair.bob, url)
    async with running(pair.alice, url) as link:
        await link.send_file(pair.bob.identity_key, pair.file)
        await final_update(link)
    proxy = TamperingProxy(relay_url, to_client=edit_server_frame("blob_data", change))

    async with (
        tampering_proxy(proxy) as proxy_url,
        running(pair.bob, proxy_url, received_files=pair.received) as link,
    ):
        failed = await final_update(link)
        await until(lambda: "delete_blob" in proxy.kinds())
        await until(lambda: blobs_in(settings) == [])

    assert (failed.state, failed.result) == (FileState.NOT_RECEIVED, "BAD_BLOB")
    assert pair.received_files() == []
    assert pair.bob.store.connection.execute("SELECT * FROM downloads").fetchall() == []


async def test_file_that_cannot_be_written_keeps_its_bytes_for_the_next_login(
    relay_url: str, pair: Pair
) -> None:
    url = f"{relay_url}/ws"
    await registered(pair.bob, url)
    async with running(pair.alice, url) as link:
        await link.send_file(pair.bob.identity_key, pair.file)
        await final_update(link)
    pair.received.write_bytes(b"a file where the folder should be")

    async with running(pair.bob, url, received_files=pair.received) as link:
        failed = await next_event(link, TransferFailed)
    held = pair.bob.store.connection.execute("SELECT count(*) FROM downloads").fetchone()
    pair.received.unlink()
    async with running(pair.bob, url, received_files=pair.received) as link:
        received = await final_update(link)

    assert str(pair.received) in failed.reason
    assert held == (1,)
    assert received.state == FileState.RECEIVED
    assert pair.received_files() == [pair.received / "photo.jpg"]
    assert (pair.received / "photo.jpg").read_bytes() == pair.file.read_bytes()


async def test_blob_whose_chunk_does_not_open_under_its_digest_writes_nothing(
    relay_url: str, pair: Pair
) -> None:
    url = f"{relay_url}/ws"
    await registered(pair.bob, url)
    upload = pair.alice.start_upload(
        pair.bob.identity_key, b"x" * 1000, blob_max_bytes=blob_length(1000)
    )
    store = pair.alice.store
    blob = bytearray(store.read_upload(upload.blob_id, 0, upload.length))
    blob[20] ^= 1
    forged = Attachment()
    forged.CopyFrom(upload.attachment)
    forged.digest = digest_of(bytes(blob))
    with store.transaction():
        store.connection.execute(
            "UPDATE uploads SET blob = ?, attachment = ? WHERE blob_id = ?",
            (bytes(blob), forged.SerializeToString(), upload.blob_id),
        )

    async with running(pair.alice, url) as link:
        await final_update(link)
    async with running(pair.bob, url, received_files=pair.received) as link:
        failed = await final_update(link)

    assert (failed.state, failed.result) == (FileState.NOT_RECEIVED, "BAD_BLOB")
    assert pair.received_files() == []


async def test_stored_length_above_the_blob_ends_the_upload_as_bad_blob(
    relay_url: str, pair: Pair
) -> None:
    url = f"{relay_url}/ws"
    await registered(pair.bob, url)

    def beyond(frame: ServerFrame) -> None:
        frame.blob_stored.stored_length = blob_length(FILE_SIZE) + 1

    proxy = TamperingProxy(relay_url, to_client=edit_server_frame("blob_stored", beyond))
    async with tampering_proxy(proxy) as proxy_url, running(pair.alice, proxy_url) as link:
        await link.send_file(pair.bob.identity_key, pair.file)
        not_sent = await final_update(link)
        await until(lambda: "delete_blob" in proxy.kinds())

    assert (not_sent.state, not_sent.result) == (FileState.NOT_SENT, "BAD_BLOB")
    assert pair.alice.uploads() == []
    assert "send" not in proxy.kinds()


async def test_refused_message_of_a_file_deletes_its_blob(
    relay_url: str, settings: Settings, pair: Pair
) -> None:
    url = f"{relay_url}/ws"
    await registered(pair.bob, url)

    def refused(frame: ServerFrame) -> None:
        message_id = frame.stored.message_id
        frame.error.CopyFrom(Error(code=ErrorCode.UNKNOWN_RECIPIENT, message_id=message_id))

    proxy = TamperingProxy(relay_url, to_client=edit_server_frame("stored", refused))
    async with tampering_proxy(proxy) as proxy_url, running(pair.alice, proxy_url) as link:
        await link.send_file(pair.bob.identity_key, pair.file)
        not_sent = await final_update(link)
        await until(lambda: "delete_blob" in proxy.kinds())
        await until(lambda: blobs_in(settings) == [])

    assert (not_sent.state, not_sent.result) == (FileState.NOT_SENT, "UNKNOWN_RECIPIENT")
    assert pair.alice.outbox() == []
    assert [file.state for file in pair.alice.store.files()] == [FileState.NOT_SENT]


async def test_delete_blob_is_sent_again_after_a_login_until_a_later_frame_is_answered(
    relay_url: str, pair: Pair
) -> None:
    url = f"{relay_url}/ws"
    await registered(pair.bob, url)
    async with running(pair.alice, url) as link:
        await link.send_file(pair.bob.identity_key, pair.file)
        await final_update(link)
    proxy = TamperingProxy(relay_url, to_relay=cut_at(nth("delete_blob", 1)))

    async with (
        tampering_proxy(proxy) as proxy_url,
        running(pair.bob, proxy_url, received_files=pair.received) as link,
    ):
        received = await final_update(link)
        await until(lambda: proxy.connections == 2)
        pending = pair.bob.blob_deletions()
        await link.send_text(pair.alice.identity_key, "an answered frame")
        await until(lambda: pair.bob.blob_deletions() == [])

    assert received.state == FileState.RECEIVED
    assert len(pending) == 1
    assert proxy.kinds(2)[:2] == ["login", "delete_blob"]


async def test_received_name_never_picks_a_folder_or_overwrites_a_file(
    relay_url: str, pair: Pair
) -> None:
    url = f"{relay_url}/ws"
    await registered(pair.bob, url)
    pair.received.mkdir()
    (pair.received / "notes.txt").write_bytes(b"already here")
    names = ["../escape.txt", "notes.txt", "a\x1b[2Jb", "..", "notes.txt"]
    for name in names:
        pair.alice.start_upload(
            pair.bob.identity_key,
            name.encode(),
            blob_max_bytes=blob_length(100),
            file_name=name,
        )

    async with running(pair.alice, url) as link:
        for _ in names:
            await final_update(link)
    async with running(pair.bob, url, received_files=pair.received) as link:
        saved = [(await final_update(link)).path for _ in names]

    assert [path.name if path else None for path in saved] == [
        OWN_NAME,
        "notes (1).txt",
        f"{OWN_NAME} (1)",
        f"{OWN_NAME} (2)",
        "notes (2).txt",
    ]
    assert (pair.received / "notes.txt").read_bytes() == b"already here"
    assert not (pair.received.parent / "escape.txt").exists()
    assert {path.read_bytes() for path in saved if path} == {name.encode() for name in names}


STAND_FILE = hashlib.shake_256(b"sotto stand file").digest(FILE_SIZE)


@contextmanager
def stand_clients() -> Iterator[tuple[Client, Client, Path]]:
    """Alice and Bob in the folder that scripts/stand.sh keeps across the restart."""
    folder = os.environ.get("SOTTO_STAND_CLIENTS")
    if folder is None:
        pytest.skip("runs on the stand, whose script names a folder for the clients")
    stores = [Store(Path(folder) / name / "store.db") for name in ("alice", "bob")]
    try:
        yield Client(stores[0]), Client(stores[1]), Path(folder)
    finally:
        for store in stores:
            store.close()


@pytest.mark.stand
async def test_file_is_half_uploaded_before_the_restart_of_the_stand(relay_url: str) -> None:
    with stand_clients() as (alice, bob, folder):
        befriend(alice, bob)
        await registered(bob, f"{relay_url}/ws")
        photo = folder / "photo.jpg"
        photo.write_bytes(STAND_FILE)
        stalled = asyncio.Event()
        proxy = TamperingProxy(relay_url, to_relay=drop_at(nth("put_blob", 2), stalled))
        async with tampering_proxy(proxy) as proxy_url, running(alice, proxy_url) as link:
            await link.send_file(bob.identity_key, photo)
            await asyncio.wait_for(stalled.wait(), PATIENCE_SECONDS)

        assert len(alice.uploads()) == 1


@pytest.mark.stand_after_restart
async def test_file_half_uploaded_before_the_restart_is_sent_and_received_whole() -> None:
    relay_url = os.environ.get("RELAY_URL")
    if relay_url is None:
        pytest.skip("runs against the stand, after scripts/stand.sh restarted it")
    with stand_clients() as (alice, bob, folder):
        proxy = TamperingProxy(relay_url)
        async with tampering_proxy(proxy) as proxy_url, running(alice, proxy_url) as link:
            sent = await final_update(link)
        received_files = folder / "received"
        async with running(bob, f"{relay_url}/ws", received_files=received_files) as link:
            received = await final_update(link)

        assert sent.state == FileState.SENT
        assert frames_to_relay(proxy, "start_blob", 1)[0].start_blob.length > 0
        assert frames_to_relay(proxy, "put_blob", 1)[0].put_blob.offset == BLOB_CHUNK_BYTES
        assert received.path == received_files / "photo.jpg"
        assert received.path.read_bytes() == STAND_FILE


def test_checks_before_a_file_run_in_the_order_of_section_33_1(pair: Pair) -> None:
    stranger = bytes(range(32))
    large = blob_length(FILE_SIZE)
    bob = pair.bob.identity_key

    with pytest.raises(NotAContactError):
        pair.alice.check_file(stranger, MAX_FILE_BYTES + 1, blob_max_bytes=0)
    with pytest.raises(FilesUnsupportedError):
        pair.alice.check_file(bob, MAX_FILE_BYTES + 1, blob_max_bytes=0)
    with pytest.raises(FileTooLargeError):
        pair.alice.check_file(bob, MAX_FILE_BYTES + 1, blob_max_bytes=2**32 - 1)
    with pytest.raises(FileTooLargeError):
        pair.alice.check_file(bob, FILE_SIZE, blob_max_bytes=large - 1)
    pair.alice.check_file(bob, FILE_SIZE, blob_max_bytes=large)


def test_same_file_sent_twice_gets_a_new_blob_id_key_and_nonce(pair: Pair) -> None:
    bob = pair.bob.identity_key
    file = pair.file.read_bytes()

    first, second = (
        pair.alice.start_upload(bob, file, blob_max_bytes=blob_length(FILE_SIZE))
        for _ in range(2)
    )
    blobs = [pair.alice.read_upload(upload.blob_id, 0, 16) for upload in (first, second)]

    assert first.blob_id != second.blob_id
    assert first.attachment.key != second.attachment.key
    assert blobs[0] != blobs[1]
    assert first.attachment.digest != second.attachment.digest
