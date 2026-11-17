"""The profile of docs/protocol.md, part 4: who owes it, what the receiver keeps, and the
avatar between two network clients."""

import os
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from client_harness import Clients, Relay, befriend, rows, send
from relay_harness import Clock, blobs_in, running_relay
from transport_harness import MakeClient, next_event, running, until

from sotto.client.session import Client, FileState
from sotto.client.transport import FileUpdate, Incoming, TransferFailed, Transport
from sotto.crypto.blob import MAX_FILE_BYTES
from sotto.relay.settings import Settings

PICTURE = b"\xff\xd8\xff\xe0" + bytes(range(256)) * 400
OTHER_PICTURE = b"\x89PNG\r\n\x1a\n" + bytes(range(255, -1, -1)) * 300
ANY_RELAY = MAX_FILE_BYTES


@pytest.fixture
def clients(tmp_path: Path) -> Iterator[Clients]:
    clients = Clients(tmp_path)
    yield clients
    clients.close()


@pytest.fixture
def relay() -> Relay:
    return Relay()


@pytest.fixture
def alice(clients: Clients, relay: Relay) -> Client:
    alice = clients.open("alice")
    relay.publish(alice)
    return alice


@pytest.fixture
def bob(clients: Clients, relay: Relay, alice: Client) -> Client:
    bob = clients.open("bob")
    relay.publish(bob)
    befriend(alice, bob)
    return bob


def owed(client: Client) -> list[bytes]:
    return client.store.owed_profiles()


def send_owed(relay: Relay, sender: Client, *, blob_max_bytes: int = 0) -> int:
    """Puts the owed profiles of a client on the relay; an avatar upload is sent as if its
    blob were complete. Returns the number of messages."""
    sent = sender.send_owed_profiles(blob_max_bytes=blob_max_bytes)
    for upload in sender.uploads():
        sent.append(sender.send_attachment(upload))
    for outgoing in sent:
        relay.send(sender, outgoing)
    return len(sent)


def test_profile_change_is_owed_to_every_contact_with_a_session(
    clients: Clients, relay: Relay, alice: Client, bob: Client
) -> None:
    carol = clients.open("carol")
    relay.publish(carol)
    befriend(alice, carol)
    send(relay, alice, bob, "hi")
    relay.deliver(bob)

    alice.set_profile("Alice", None)
    assert owed(alice) == [bob.identity_key]
    assert send_owed(relay, alice) == 1
    assert owed(alice) == []
    (received,) = relay.deliver(bob)
    assert received.profile is not None
    assert received.profile.name == "Alice"

    alice.set_profile("Alice", PICTURE)
    assert send_owed(relay, alice, blob_max_bytes=0) == 1
    alice.set_profile("Alice", PICTURE)
    alice.send_owed_profiles(blob_max_bytes=ANY_RELAY)
    (earlier,) = alice.uploads()
    alice.set_profile("Alice A.", PICTURE)

    assert earlier.profile
    assert alice.uploads() == []
    assert alice.blob_deletions() == [(alice.identity_key, earlier.blob_id)]
    assert owed(alice) == [bob.identity_key]


def test_new_session_gets_the_profile_once_in_both_directions(
    relay: Relay, alice: Client, bob: Client
) -> None:
    alice.set_profile("Alice", None)
    bob.set_profile("Bob", None)
    assert owed(alice) == owed(bob) == []

    send(relay, alice, bob, "hi")
    assert owed(alice) == [bob.identity_key]
    send_owed(relay, alice)
    relay.deliver(bob)
    assert owed(bob) == [alice.identity_key]
    send_owed(relay, bob)
    received = relay.deliver(alice)
    send(relay, alice, bob, "again")
    relay.deliver(bob)

    assert [one.profile.name for one in received if one.profile is not None] == ["Bob"]
    assert bob.store.profile(alice.identity_key) is not None
    assert alice.store.profile(bob.identity_key) is not None
    assert owed(alice) == owed(bob) == []


def test_empty_profile_is_not_sent_into_a_new_session(
    relay: Relay, alice: Client, bob: Client
) -> None:
    alice.set_profile("Alice", None)
    alice.set_profile("", None)

    send(relay, alice, bob, "hi")
    relay.deliver(bob)

    assert owed(alice) == owed(bob) == []


def test_received_profile_replaces_the_earlier_one_and_is_no_message(
    relay: Relay, alice: Client, bob: Client
) -> None:
    send(relay, alice, bob, "hi")
    relay.deliver(bob)
    before = rows(bob.store)["messages"]

    alice.set_profile("Alice", PICTURE)
    send_owed(relay, alice, blob_max_bytes=ANY_RELAY)
    (pictured,) = relay.deliver(bob)
    first = bob.store.profile(alice.identity_key)
    (avatar_file,) = bob.store.files()
    alice.set_profile("Alice A.", None)
    send_owed(relay, alice)
    (renamed,) = relay.deliver(bob)
    second = bob.store.profile(alice.identity_key)

    assert pictured.profile is not None
    assert (pictured.text, pictured.attachment, pictured.result) == (None, None, None)
    assert first is not None
    assert (first.name, first.avatar_file) == ("Alice", avatar_file.position)
    assert avatar_file.avatar
    assert avatar_file.state == FileState.OFFERED
    assert renamed.profile is not None
    assert second is not None
    assert (second.name, second.avatar_file, second.avatar) == ("Alice A.", None, None)
    assert bob.store.files() == []
    assert bob.blob_deletions() == [(alice.identity_key, avatar_file.attachment.blob_id)]
    assert rows(bob.store)["messages"] == before


def test_cleared_profile_leaves_nothing_of_the_contact(
    relay: Relay, alice: Client, bob: Client
) -> None:
    send(relay, alice, bob, "hi")
    relay.deliver(bob)
    alice.set_profile("Alice", PICTURE)
    send_owed(relay, alice, blob_max_bytes=ANY_RELAY)
    relay.deliver(bob)

    alice.set_profile("", None)
    send_owed(relay, alice)
    (cleared,) = relay.deliver(bob)

    assert cleared.profile is not None
    assert (cleared.profile.name, cleared.profile.HasField("avatar")) == ("", False)
    assert bob.store.profile(alice.identity_key) is None
    assert bob.store.files() == []


def has_the_avatar(client: Client, contact: Client) -> bool:
    profile = client.store.profile(contact.identity_key)
    return profile is not None and profile.avatar is not None


def all_sent(client: Client) -> bool:
    """No profile is owed, no avatar is uploading and the relay stored every message."""
    return not (client.uploads() or client.store.owed_profiles() or client.outbox())


async def avatar_update(transport: Transport) -> FileUpdate:
    while True:
        update = await next_event(transport, FileUpdate)
        if update.avatar and update.state != FileState.RECEIVING:
            return update


async def test_avatar_reaches_the_contact_whole_and_its_blob_is_deleted(
    relay_url: str, settings: Settings, make_client: MakeClient
) -> None:
    url = f"{relay_url}/ws"
    alice, bob = make_client("alice"), make_client("bob")
    befriend(alice, bob)
    alice.set_profile("Alice", PICTURE)
    async with running(bob, url):
        pass

    async with running(alice, url) as link:
        await link.send_text(bob.identity_key, "hi")
        await until(lambda: all_sent(alice))
    async with running(bob, url) as link:
        texts = [(await next_event(link, Incoming)).received for _ in range(2)]
        await until(lambda: has_the_avatar(bob, alice))
        await until(lambda: blobs_in(settings) == [])

    profile = bob.store.profile(alice.identity_key)
    assert [one.text for one in texts] == ["hi", None]
    assert texts[1].profile is not None
    assert texts[1].profile.avatar.media_type == "image/jpeg"
    assert profile is not None
    assert (profile.name, profile.avatar) == ("Alice", PICTURE)
    assert [file.state for file in bob.store.files()] == [FileState.RECEIVED]


async def test_avatar_whose_blob_is_gone_is_not_available_and_the_name_stays(
    settings: Settings, make_client: MakeClient
) -> None:
    clock = Clock()
    expiring = replace(settings, blob_ttl_seconds=100, sweep_interval_seconds=0.05)
    alice, bob = make_client("alice"), make_client("bob")
    befriend(alice, bob)
    alice.set_profile("Alice", PICTURE)
    async with running_relay(expiring, clock=clock) as relay_url:
        url = f"{relay_url}/ws"
        async with running(bob, url):
            pass
        async with running(alice, url) as link:
            await link.send_text(bob.identity_key, "hi")
            await until(lambda: all_sent(alice))
        clock.now += 100
        await until(lambda: blobs_in(expiring) == [])
        async with running(bob, url) as link:
            gone = await avatar_update(link)

    profile = bob.store.profile(alice.identity_key)
    assert (gone.state, gone.result) == (FileState.NOT_AVAILABLE, "BLOB_GONE")
    assert profile is not None
    assert (profile.name, profile.avatar) == ("Alice", None)


async def test_avatar_that_is_no_image_of_its_media_type_is_not_kept(
    relay_url: str, settings: Settings, make_client: MakeClient
) -> None:
    url = f"{relay_url}/ws"
    alice, bob = make_client("alice"), make_client("bob")
    befriend(alice, bob)
    with alice.store.transaction():
        alice.store.set_own_profile("Alice", b"GIF89a" + os.urandom(100), "image/jpeg")
    async with running(bob, url):
        pass

    async with running(alice, url) as link:
        await link.send_text(bob.identity_key, "hi")
        await until(lambda: all_sent(alice))
    async with running(bob, url) as link:
        refused = await avatar_update(link)
        await until(lambda: blobs_in(settings) == [])

    profile = bob.store.profile(alice.identity_key)
    assert (refused.state, refused.result) == (FileState.NOT_RECEIVED, "NOT_AN_IMAGE")
    assert profile is not None
    assert (profile.name, profile.avatar) == ("Alice", None)


async def test_relay_without_blobs_gets_the_profile_without_the_avatar(
    settings: Settings, make_client: MakeClient
) -> None:
    small = replace(settings, blob_max_bytes=1000)
    alice, bob = make_client("alice"), make_client("bob")
    befriend(alice, bob)
    alice.set_profile("Alice", PICTURE)
    async with running_relay(small) as relay_url:
        url = f"{relay_url}/ws"
        async with running(bob, url):
            pass
        async with running(alice, url) as link:
            await link.send_text(bob.identity_key, "hi")
            await until(lambda: all_sent(alice))
        async with running(bob, url) as link:
            await next_event(link, Incoming)
            incoming = await next_event(link, Incoming)

    assert incoming.received.profile is not None
    assert incoming.received.profile.name == "Alice"
    assert not incoming.received.profile.HasField("avatar")
    assert alice.uploads() == []
    assert blobs_in(small) == []


async def test_newer_profile_takes_the_place_of_an_avatar_on_its_way(
    relay_url: str, settings: Settings, make_client: MakeClient
) -> None:
    url = f"{relay_url}/ws"
    alice, bob = make_client("alice"), make_client("bob")
    befriend(alice, bob)
    alice.set_profile("Alice", PICTURE)
    async with running(bob, url):
        pass
    async with running(alice, url) as link:
        await link.send_text(bob.identity_key, "hi")
        await until(lambda: all_sent(alice))
    alice.set_profile("Alice B.", OTHER_PICTURE)
    async with running(alice, url):
        await until(lambda: all_sent(alice))

    async with running(bob, url) as link:
        await until(lambda: has_the_avatar(bob, alice))
        await until(lambda: blobs_in(settings) == [])
        events = [link.events.get_nowait() for _ in range(link.events.qsize())]

    profile = bob.store.profile(alice.identity_key)
    assert profile is not None
    assert (profile.name, profile.avatar) == ("Alice B.", OTHER_PICTURE)
    assert [file.state for file in bob.store.files()] == [FileState.RECEIVED]
    assert not [event for event in events if isinstance(event, TransferFailed)]
