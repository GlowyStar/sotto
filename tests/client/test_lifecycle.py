"""The prekey lifecycle of docs/protocol.md, section 21, with the records and seen ids of
section 20.4 and the deletion of section 22.3, on a clock that the tests move."""

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from client_harness import Clients, Relay, befriend, files_holding, rows, send

from sotto.client.session import (
    ONE_TIME_PREKEY_CAP,
    ONE_TIME_PREKEY_HELD_MAX,
    PQ_ONE_TIME_PREKEY_CAP,
    SEEN_ID_SECONDS,
    SIGNED_PREKEY_GRACE_SECONDS,
    SIGNED_PREKEY_ROTATION_SECONDS,
    Client,
    PrekeyUpload,
)
from sotto.client.store import LAST_PREKEY_ID, MAX_SESSIONS


@pytest.fixture
def clients(tmp_path: Path) -> Iterator[Clients]:
    clients = Clients(tmp_path)
    yield clients
    clients.close()


@pytest.fixture
def relay() -> Relay:
    return Relay()


@pytest.fixture
def alice(clients: Clients) -> Client:
    return clients.open("alice")


@pytest.fixture
def bob(clients: Clients, relay: Relay, alice: Client) -> Client:
    bob = clients.open("bob")
    relay.publish(bob)
    befriend(alice, bob)
    return bob


@pytest.fixture
def carol(clients: Clients) -> Client:
    return clients.open("carol")


def held_one_time_prekey_ids(client: Client) -> list[int]:
    found = client.store.connection.execute(
        "SELECT prekey_id FROM one_time_prekeys ORDER BY prekey_id"
    ).fetchall()
    return [prekey_id for (prekey_id,) in found]


def one_time_prekey_ids(upload: PrekeyUpload | None) -> list[int]:
    assert upload is not None
    return [prekey.id for prekey in upload.one_time_prekeys]


@pytest.mark.parametrize(
    ("seconds_after_the_replacement", "deleted", "result"),
    [
        (SIGNED_PREKEY_GRACE_SECONDS - 1, False, None),
        (SIGNED_PREKEY_GRACE_SECONDS, False, "UNKNOWN_SIGNED_PREKEY"),
        (SIGNED_PREKEY_GRACE_SECONDS, True, "UNKNOWN_SIGNED_PREKEY"),
    ],
)
def test_initial_message_under_a_replaced_signed_prekey_decrypts_only_in_the_grace_period(
    clients: Clients,
    alice: Client,
    bob: Client,
    relay: Relay,
    seconds_after_the_replacement: int,
    deleted: bool,
    result: str | None,
) -> None:
    initial = send(relay, alice, bob, "under the old key")
    old_private_key = bob.store.signed_prekey(1, replaced_after=0)
    assert old_private_key is not None

    clients.clock.advance(SIGNED_PREKEY_ROTATION_SECONDS)
    upload = bob.prepare_upload(
        pq_one_time_prekey_count=PQ_ONE_TIME_PREKEY_CAP, one_time_prekey_count=0
    )
    assert upload is not None
    assert upload.signed_prekey.id == 2
    clients.clock.advance(seconds_after_the_replacement)
    if deleted:
        bob.delete_expired_prekeys()
        assert files_holding(clients.folder / "bob", old_private_key) == []
    store_before = rows(bob.store)

    received = bob.receive(initial)

    assert received.result == result
    if result is None:
        assert received.text == "under the old key"
    else:
        assert received.text is None
        assert rows(bob.store) == store_before


def test_replayed_initial_message_gives_no_text_after_its_session_left_and_after_a_restart(
    clients: Clients, relay: Relay, alice: Client
) -> None:
    bob = clients.open("bob")
    relay.publish(bob, one_time_count=0)
    befriend(alice, bob)
    initial = send(relay, alice, bob, "first")
    assert bob.receive(initial).text == "first"
    for number in range(MAX_SESSIONS):
        alice.start_session(bob.identity_key, relay.fetch(bob.identity_key))
        assert bob.receive(send(relay, alice, bob, f"new {number}")).text == f"new {number}"
    clients.clock.advance(SEEN_ID_SECONDS)
    bob.forget_seen_ids()
    store_before = rows(bob.store)

    assert bob.receive(initial).result == "REPLAYED_INITIAL"
    bob.store.close()
    bob = clients.open("bob")
    assert bob.receive(initial).result == "REPLAYED_INITIAL"
    assert rows(bob.store) == store_before

    bob.prepare_upload(
        pq_one_time_prekey_count=PQ_ONE_TIME_PREKEY_CAP, one_time_prekey_count=0
    )
    clients.clock.advance(SIGNED_PREKEY_GRACE_SECONDS)
    bob.delete_expired_prekeys()
    assert bob.store.connection.execute("SELECT count(*) FROM records").fetchone() == (
        MAX_SESSIONS,
    )
    assert bob.receive(initial).result == "UNKNOWN_SIGNED_PREKEY"
    assert bob.receive(send(relay, alice, bob, "on a listed session")).text == (
        "on a listed session"
    )


def test_removed_contact_added_again_gets_no_replayed_initial_message(
    clients: Clients, alice: Client, bob: Client, relay: Relay
) -> None:
    initial = send(relay, alice, bob, "before the removal")
    assert bob.receive(initial).text == "before the removal"

    bob.remove_contact(alice.identity_key)
    bob.add_contact(alice.identity_key.hex())

    assert bob.store.sessions(alice.identity_key) == []
    assert bob.receive(initial).result == "DUPLICATE"
    clients.clock.advance(SEEN_ID_SECONDS)
    bob.forget_seen_ids()
    assert bob.receive(initial).result == "REPLAYED_INITIAL"


def test_rotation_follows_the_age_of_the_newest_signed_prekey(
    clients: Clients, carol: Client
) -> None:
    first = carol.prepare_upload(
        pq_one_time_prekey_count=PQ_ONE_TIME_PREKEY_CAP, one_time_prekey_count=0
    )
    assert first is not None
    assert first.signed_prekey.id == 1
    assert len(first.one_time_prekeys) == ONE_TIME_PREKEY_CAP

    assert carol.prepare_upload(ONE_TIME_PREKEY_CAP, PQ_ONE_TIME_PREKEY_CAP) == replace(
        first, one_time_prekeys=()
    )
    carol.confirm_upload(first)
    clients.clock.advance(SIGNED_PREKEY_ROTATION_SECONDS - 1)
    assert carol.prepare_upload(ONE_TIME_PREKEY_CAP, PQ_ONE_TIME_PREKEY_CAP) is None

    clients.clock.advance(1)
    rotated = carol.prepare_upload(ONE_TIME_PREKEY_CAP, PQ_ONE_TIME_PREKEY_CAP)
    assert rotated is not None
    assert rotated.signed_prekey.id == 2
    assert rotated.one_time_prekeys == ()
    assert rotated.identity_dh_key == first.identity_dh_key
    assert rotated.identity_dh_signature == first.identity_dh_signature


@pytest.mark.parametrize(("count", "made"), [(0, 100), (49, 51), (50, 0), (500, 0)])
def test_refill_tops_up_to_the_cap_below_the_threshold(
    carol: Client, count: int, made: int
) -> None:
    upload = carol.prepare_upload(
        pq_one_time_prekey_count=PQ_ONE_TIME_PREKEY_CAP, one_time_prekey_count=count
    )

    assert len(one_time_prekey_ids(upload)) == made


def test_held_one_time_prekeys_are_bounded_by_deleting_the_lowest_ids(
    alice: Client, bob: Client, relay: Relay
) -> None:
    bundle = relay.fetch(bob.identity_key)
    assert bundle.one_time_prekey is not None
    assert bundle.one_time_prekey.id == 1

    uploads = [
        bob.prepare_upload(
            pq_one_time_prekey_count=PQ_ONE_TIME_PREKEY_CAP, one_time_prekey_count=0
        )
        for _ in range(10)
    ]

    assert one_time_prekey_ids(uploads[-1]) == list(range(902, 1002))
    assert held_one_time_prekey_ids(bob) == list(range(2, 1002))
    assert len(held_one_time_prekey_ids(bob)) == ONE_TIME_PREKEY_HELD_MAX
    outgoing = alice.send_text(bob.identity_key, "names a deleted key", bundle=bundle)
    assert bob.receive(relay.send(alice, outgoing)).result == "UNKNOWN_ONE_TIME_PREKEY"


def test_unanswered_upload_keeps_its_keys_and_a_refused_one_deletes_them(
    carol: Client,
) -> None:
    unanswered = one_time_prekey_ids(
        carol.prepare_upload(
            pq_one_time_prekey_count=PQ_ONE_TIME_PREKEY_CAP, one_time_prekey_count=0
        )
    )
    refused_upload = carol.prepare_upload(
        pq_one_time_prekey_count=PQ_ONE_TIME_PREKEY_CAP, one_time_prekey_count=0
    )
    refused = one_time_prekey_ids(refused_upload)
    assert set(unanswered).isdisjoint(refused)

    assert refused_upload is not None
    carol.drop_refused_upload(refused_upload)

    assert held_one_time_prekey_ids(carol) == unanswered
    assert carol.store.newest_signed_prekey() is not None


def test_prekey_ids_are_never_reused_and_stop_at_the_last_id(carol: Client) -> None:
    first = carol.make_prekeys(2, 0)
    carol.drop_refused_upload(first)
    second = carol.make_prekeys(1, 0)
    assert (second.signed_prekey.id, one_time_prekey_ids(second)) == (2, [3])

    with carol.store.transaction():
        carol.store.connection.execute(
            "UPDATE identity SET last_signed_prekey_id = ?, last_one_time_prekey_id = ?",
            (LAST_PREKEY_ID - 1, LAST_PREKEY_ID - 1),
        )
    last = carol.make_prekeys(2, 0)
    after_the_last = carol.make_prekeys(1, 0)

    assert (last.signed_prekey.id, one_time_prekey_ids(last)) == (
        LAST_PREKEY_ID,
        [LAST_PREKEY_ID],
    )
    assert (after_the_last.signed_prekey.id, after_the_last.one_time_prekeys) == (
        LAST_PREKEY_ID,
        (),
    )


def test_seen_id_counts_until_it_is_forgotten_after_its_time(
    clients: Clients, alice: Client, bob: Client, relay: Relay
) -> None:
    delivered = send(relay, alice, bob, "once")
    assert bob.receive(delivered).text == "once"

    clients.clock.advance(SEEN_ID_SECONDS - 1)
    bob.forget_seen_ids()
    assert bob.receive(delivered).result == "DUPLICATE"

    clients.clock.advance(1)
    assert bob.receive(delivered).result == "DUPLICATE"
    bob.forget_seen_ids()
    received = bob.receive(delivered)
    assert (received.text, received.result) == (None, "DECRYPT_FAILED")


def test_replaced_chain_keys_are_in_no_file_of_the_store(
    clients: Clients, alice: Client, bob: Client, relay: Relay
) -> None:
    send(relay, alice, bob, "first")
    relay.deliver(bob)
    sending_chain_key = alice.store.sessions(bob.identity_key)[0].state.cks
    receiving_chain_key = bob.store.sessions(alice.identity_key)[0].state.ckr
    assert sending_chain_key is not None
    assert receiving_chain_key is not None
    assert files_holding(clients.folder / "alice", sending_chain_key) == ["store.db"]
    assert files_holding(clients.folder / "bob", receiving_chain_key) == ["store.db"]

    send(relay, alice, bob, "second")
    relay.deliver(bob)

    assert files_holding(clients.folder / "alice", sending_chain_key) == []
    assert files_holding(clients.folder / "bob", receiving_chain_key) == []
