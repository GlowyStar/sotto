"""The session list of docs/protocol.md, sections 20.1, 20.5 and 20.6."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from client_harness import Clients, Relay, befriend, send, texts

from sotto.client.session import Client
from sotto.client.store import MAX_SESSIONS
from sotto.crypto.ratchet import SKIPPED_KEY_STEPS
from sotto.proto.sotto_pb2 import PeerMessage


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


def head_session_data(client: Client, contact: Client) -> bytes:
    return client.store.sessions(contact.identity_key)[0].associated_data


def session_data(client: Client, contact: Client) -> set[bytes]:
    return {session.associated_data for session in client.store.sessions(contact.identity_key)}


def reset(relay: Relay, client: Client, contact: Client) -> int:
    relay.publish(contact)
    return client.start_session(contact.identity_key, relay.fetch(contact.identity_key))


def test_both_sides_starting_at_once_send_and_receive_in_both_directions(
    alice: Client, bob: Client, relay: Relay
) -> None:
    send(relay, alice, bob, "alice starts")
    send(relay, bob, alice, "bob starts")

    assert texts(relay.deliver(bob)) == ["alice starts"]
    assert texts(relay.deliver(alice)) == ["bob starts"]
    assert len(alice.store.sessions(bob.identity_key)) == 2
    assert session_data(alice, bob) == session_data(bob, alice)

    for number in range(3):
        send(relay, alice, bob, f"crossing to bob {number}")
        send(relay, bob, alice, f"crossing to alice {number}")
        assert texts(relay.deliver(bob)) == [f"crossing to bob {number}"]
        assert texts(relay.deliver(alice)) == [f"crossing to alice {number}"]

    send(relay, alice, bob, "alone to bob")
    assert texts(relay.deliver(bob)) == ["alone to bob"]
    send(relay, bob, alice, "alone to alice")
    assert texts(relay.deliver(alice)) == ["alone to alice"]
    assert head_session_data(alice, bob) == head_session_data(bob, alice)


def test_fourth_session_drops_the_oldest_and_reports_its_missing_messages(
    alice: Client, bob: Client, relay: Relay
) -> None:
    lost = send(relay, alice, bob, "lost on the first session")
    first = send(relay, alice, bob, "first session")
    assert bob.receive(first).text == "first session"

    received = []
    for number in range(MAX_SESSIONS):
        assert reset(relay, alice, bob) == 0
        received.append(bob.receive(send(relay, alice, bob, f"session {number + 2}")))

    assert texts(received) == ["session 2", "session 3", "session 4"]
    assert [one.missing for one in received] == [0, 0, 1]
    assert len(bob.store.sessions(alice.identity_key)) == MAX_SESSIONS
    assert len(alice.store.sessions(bob.identity_key)) == MAX_SESSIONS
    assert session_data(alice, bob) == session_data(bob, alice)
    assert bob.receive(lost).result == "REPLAYED_INITIAL"


def test_reset_keeps_the_older_sessions_and_sends_on_the_new_one(
    alice: Client, bob: Client, relay: Relay
) -> None:
    send(relay, alice, bob, "before the reset")
    relay.deliver(bob)
    send(relay, bob, alice, "reply")
    relay.deliver(alice)
    on_the_way = send(relay, alice, bob, "on the way")

    reset(relay, alice, bob)
    after_reset = send(relay, alice, bob, "after the reset")

    assert PeerMessage.FromString(on_the_way.payload).HasField("initial_header") is False
    assert PeerMessage.FromString(after_reset.payload).HasField("initial_header") is True
    assert texts(relay.deliver(bob)) == ["on the way", "after the reset"]
    assert len(bob.store.sessions(alice.identity_key)) == 2


def test_purged_skipped_keys_are_reported_as_missing(
    alice: Client, bob: Client, relay: Relay
) -> None:
    skipped = send(relay, alice, bob, "skipped")
    assert bob.receive(send(relay, alice, bob, "arrives")).text == "arrives"

    missing = []
    for number in range(SKIPPED_KEY_STEPS + 1):
        send(relay, bob, alice, f"to alice {number}")
        relay.deliver(alice)
        received = bob.receive(send(relay, alice, bob, f"to bob {number}"))
        assert received.text == f"to bob {number}"
        missing.append(received.missing)

    assert sum(missing) == 1
    assert bob.receive(skipped).result == "DECRYPT_FAILED"
