"""Sessions by PQXDH and the transition from X3DH, docs/protocol.md, sections 41 and 42."""

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from client_harness import Clients, Relay, befriend, edit_envelope, rows, send

from sotto.client.session import (
    ONE_TIME_PREKEY_CAP,
    PQ_ONE_TIME_PREKEY_CAP,
    PQ_ONE_TIME_PREKEY_HELD_MAX,
    SIGNED_PREKEY_GRACE_SECONDS,
    SIGNED_PREKEY_ROTATION_SECONDS,
    Client,
    PrekeyUpload,
)
from sotto.client.transport import upload_frame
from sotto.crypto import ratchet, x3dh
from sotto.crypto.identity import KEY_LENGTH, PqPrekeyMissingError, sign_identity_dh_key
from sotto.crypto.pqxdh import KEM_CIPHERTEXT_LENGTH
from sotto.proto.sotto_pb2 import ClientFrame, InitialHeader, PeerMessage
from sotto.relay.frames import MAX_FRAME_BYTES


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
    relay.publish(bob, pq_one_time_count=1)
    befriend(alice, bob)
    return bob


def pq_one_time_prekey_ids(client: Client) -> list[int]:
    found = client.store.connection.execute(
        "SELECT prekey_id FROM pq_prekeys WHERE signed_prekey_id IS NULL ORDER BY prekey_id"
    ).fetchall()
    return [prekey_id for (prekey_id,) in found]


def pq_ids_of(upload: PrekeyUpload | None) -> list[int]:
    assert upload is not None
    return [prekey.id for prekey in upload.pq_one_time_prekeys]


def made_version_2(envelope: PeerMessage) -> None:
    envelope.version = 2


def make_x3dh_session(alice: Client, bob: Client, relay: Relay) -> None:
    """The session of version 1 that Alice started and Bob accepted before both moved to
    version 2: section 16 run by hand on both stores, as a client of version 1 left them."""
    bundle = replace(relay.fetch(bob.identity_key), one_time_prekey=None)
    alice_identity, bob_identity = alice.store.identity(), bob.store.identity()
    assert alice_identity is not None
    assert bob_identity is not None
    ephemeral_private_key = bytes([0x5A]) * KEY_LENGTH
    started = x3dh.initiate(
        bundle,
        identity_key=alice.identity_key,
        identity_dh_private_key=alice_identity.identity_dh_private_key,
        ephemeral_private_key=ephemeral_private_key,
        contact_identity_key=bob.identity_key,
        pinned_identity_dh_key=None,
    )
    header = InitialHeader(
        identity_dh_key=alice.identity_dh_key,
        identity_dh_signature=sign_identity_dh_key(
            alice_identity.seed, identity_dh_key=alice.identity_dh_key
        ),
        ephemeral_key=started.associated_data[-KEY_LENGTH:],
        signed_prekey_id=bundle.signed_prekey.id,
    )
    signed_prekey_private_key = bob.store.signed_prekey(
        bundle.signed_prekey.id, replaced_after=0
    )
    assert signed_prekey_private_key is not None
    accepted = x3dh.respond(
        identity_key=bob.identity_key,
        identity_dh_private_key=bob_identity.identity_dh_private_key,
        signed_prekey_private_key=signed_prekey_private_key,
        one_time_prekey_private_key=None,
        sender_identity_key=alice.identity_key,
        sender_identity_dh_key=header.identity_dh_key,
        sender_identity_dh_signature=header.identity_dh_signature,
        ephemeral_key=header.ephemeral_key,
        pinned_identity_dh_key=None,
    )

    with alice.store.transaction():
        alice.store.add_session(
            bob.identity_key,
            associated_data=started.associated_data,
            state=ratchet.init_initiator(
                shared_secret=started.shared_secret,
                signed_prekey=bundle.signed_prekey.key,
                ratchet_private_key=bytes([0x5B]) * KEY_LENGTH,
            ),
            initial_header=header.SerializeToString(),
        )
        alice.store.set_pin(bob.identity_key, bundle.identity_dh_key)
    with bob.store.transaction():
        session_id = bob.store.add_session(
            alice.identity_key,
            associated_data=accepted.associated_data,
            state=ratchet.init_responder(
                shared_secret=accepted.shared_secret,
                signed_prekey_private_key=signed_prekey_private_key,
            ),
            initial_header=None,
        )
        bob.store.add_record(
            alice.identity_key,
            header.ephemeral_key,
            session_id=session_id,
            signed_prekey_id=bundle.signed_prekey.id,
        )
        bob.store.set_pin(alice.identity_key, alice.identity_dh_key)


def test_new_session_is_pqxdh_of_version_2_and_texts_go_both_ways(
    alice: Client, bob: Client, relay: Relay
) -> None:
    delivered = send(relay, alice, bob, "hello")
    envelope = PeerMessage.FromString(delivered.payload)

    assert envelope.version == 2
    assert len(envelope.initial_header.kem_ciphertext) == KEM_CIPHERTEXT_LENGTH
    assert envelope.initial_header.pq_prekey_id == 2
    assert bob.receive(delivered).text == "hello"
    reply = send(relay, bob, alice, "hi")
    assert PeerMessage.FromString(reply.payload).version == 2
    assert alice.receive(reply).text == "hi"
    assert alice.store.sessions(bob.identity_key)[0].associated_data[0] == 2
    assert bob.store.sessions(alice.identity_key)[0].associated_data[0] == 2


def test_one_time_pq_prekey_starts_one_session_and_is_deleted_only_when_accepted(
    clients: Clients, alice: Client, bob: Client, relay: Relay
) -> None:
    carol = clients.open("carol")
    befriend(carol, bob)
    bundle = replace(relay.fetch(bob.identity_key), one_time_prekey=None)
    assert bundle.pq_prekey is not None
    assert pq_one_time_prekey_ids(bob) == [bundle.pq_prekey.id]
    from_alice = relay.send(alice, alice.send_text(bob.identity_key, "a", bundle=bundle))
    from_carol = relay.send(carol, carol.send_text(bob.identity_key, "c", bundle=bundle))

    spoiled = edit_envelope(
        from_alice,
        lambda message: setattr(
            message.initial_header, "kem_ciphertext", bytes(KEM_CIPHERTEXT_LENGTH)
        ),
    )
    assert bob.receive(spoiled).result == "DECRYPT_FAILED"
    assert pq_one_time_prekey_ids(bob) == [bundle.pq_prekey.id]
    assert bob.receive(from_alice).text == "a"
    assert pq_one_time_prekey_ids(bob) == []
    assert bob.receive(from_carol).result == "UNKNOWN_PQ_PREKEY"


def test_bundle_without_a_pq_prekey_ends_start_with_pq_prekey_missing_and_stores_nothing(
    alice: Client, bob: Client, relay: Relay
) -> None:
    stripped = replace(relay.fetch(bob.identity_key), pq_prekey=None)
    store_before = rows(alice.store)

    with pytest.raises(PqPrekeyMissingError):
        alice.send_text(bob.identity_key, "not sent", bundle=stripped)

    assert rows(alice.store) == store_before


def test_x3dh_session_made_before_keeps_working_in_both_directions(
    alice: Client, bob: Client, relay: Relay
) -> None:
    make_x3dh_session(alice, bob, relay)

    first = send(relay, alice, bob, "on the old session")
    assert PeerMessage.FromString(first.payload).version == 1
    assert bob.receive(first).text == "on the old session"
    reply = send(relay, bob, alice, "still old")
    assert PeerMessage.FromString(reply.payload).version == 1
    assert alice.receive(reply).text == "still old"
    later = send(relay, alice, bob, "later")
    assert PeerMessage.FromString(later.payload).HasField("initial_header") is False
    assert bob.receive(later).text == "later"


def test_new_session_of_version_1_is_refused_and_changes_nothing(
    clients: Clients, alice: Client, relay: Relay
) -> None:
    bob = clients.open("bob")
    relay.publish(bob)
    befriend(alice, bob)
    make_x3dh_session(alice, bob, relay)
    with bob.store.transaction():
        bob.store.connection.execute("DELETE FROM records")
        bob.store.connection.execute("DELETE FROM sessions")
    delivered = send(relay, alice, bob, "of version 1")
    store_before = rows(bob.store)

    received = bob.receive(delivered)

    assert (received.text, received.result, received.ack) == (None, "X3DH_REFUSED", True)
    assert rows(bob.store) == store_before


@pytest.mark.parametrize("resetting", ["initiator", "responder"])
def test_session_of_version_1_that_was_never_accepted_is_refused_until_a_reset(
    alice: Client, bob: Client, relay: Relay, resetting: str
) -> None:
    relay.publish(alice)
    make_x3dh_session(alice, bob, relay)
    with bob.store.transaction():
        bob.store.connection.execute("DELETE FROM records")
        bob.store.connection.execute("DELETE FROM sessions")
    refused = [send(relay, alice, bob, f"refused {number}") for number in range(2)]
    assert [bob.receive(delivered).result for delivered in refused] == ["X3DH_REFUSED"] * 2

    if resetting == "initiator":
        alice.start_session(bob.identity_key, relay.fetch(bob.identity_key))
    else:
        bob.start_session(alice.identity_key, relay.fetch(alice.identity_key))
        assert alice.receive(send(relay, bob, alice, "reset")).text == "reset"
    after = send(relay, alice, bob, "after the reset")

    assert PeerMessage.FromString(after.payload).version == 2
    assert bob.receive(after).text == "after the reset"


def test_message_of_version_1_made_version_2_is_refused_and_changes_nothing(
    alice: Client, bob: Client, relay: Relay
) -> None:
    make_x3dh_session(alice, bob, relay)
    initial = send(relay, alice, bob, "initial")
    store_before = rows(bob.store)

    assert bob.receive(edit_envelope(initial, made_version_2)).result == "BAD_ENVELOPE"
    assert rows(bob.store) == store_before
    assert bob.receive(initial).text == "initial"
    assert alice.receive(send(relay, bob, alice, "reply")).text == "reply"
    later = send(relay, alice, bob, "later")
    store_before = rows(bob.store)

    assert bob.receive(edit_envelope(later, made_version_2)).result == "DECRYPT_FAILED"
    assert rows(bob.store) == store_before
    assert bob.receive(later).text == "later"


def test_store_of_the_first_version_opens_and_rotates_to_a_pq_prekey(
    clients: Clients,
) -> None:
    carol = clients.open("carol")
    with carol.store.transaction():
        carol.store.add_signed_prekey(bytes([0x61]) * KEY_LENGTH, made_at=clients.clock.now)
        carol.store.connection.execute("DROP TABLE pq_prekeys")
        carol.store.connection.execute("DROP TABLE pq_prekey_ids")
    carol.store.close()

    carol = clients.open("carol")
    upload = carol.prepare_upload(ONE_TIME_PREKEY_CAP, PQ_ONE_TIME_PREKEY_CAP)

    assert upload is not None
    assert upload.signed_prekey.id == 2
    assert upload.pq_prekey is not None
    assert carol.store.signed_prekey(1, replaced_after=clients.clock.now - 1) is not None


def test_largest_upload_fits_one_frame(clients: Clients) -> None:
    upload = clients.open("carol").prepare_upload(0, 0)
    assert upload is not None

    frame = ClientFrame(upload_bundle=upload_frame(upload)).SerializeToString()

    assert len(upload.one_time_prekeys) == ONE_TIME_PREKEY_CAP
    assert len(upload.pq_one_time_prekeys) == PQ_ONE_TIME_PREKEY_CAP
    assert upload.pq_prekey is not None
    assert len(frame) <= MAX_FRAME_BYTES


@pytest.mark.parametrize(("count", "made"), [(0, 40), (19, 21), (20, 0), (500, 0)])
def test_pq_refill_tops_up_to_the_cap_below_the_threshold(
    clients: Clients, count: int, made: int
) -> None:
    upload = clients.open("carol").prepare_upload(ONE_TIME_PREKEY_CAP, count)

    assert len(pq_ids_of(upload)) == made


def test_held_one_time_pq_prekeys_are_bounded_and_a_refused_upload_deletes_its_own(
    clients: Clients,
) -> None:
    carol = clients.open("carol")
    uploads = [carol.prepare_upload(ONE_TIME_PREKEY_CAP, 0) for _ in range(11)]
    held = pq_one_time_prekey_ids(carol)
    refused = uploads[-1]
    assert refused is not None

    carol.drop_refused_upload(refused)

    assert len(held) == PQ_ONE_TIME_PREKEY_HELD_MAX
    assert held[-1] == pq_ids_of(uploads[-1])[-1]
    assert held[0] == pq_ids_of(uploads[1])[0]
    assert pq_one_time_prekey_ids(carol) == held[:-PQ_ONE_TIME_PREKEY_CAP]


def test_last_resort_pq_prekey_lives_and_dies_with_its_signed_prekey(
    clients: Clients, alice: Client, bob: Client, relay: Relay
) -> None:
    bundle = replace(
        relay.fetch(bob.identity_key), pq_prekey=relay.prekeys[bob.identity_key].pq_prekey
    )
    assert bundle.pq_prekey is not None
    initial = relay.send(alice, alice.send_text(bob.identity_key, "x", bundle=bundle))
    clients.clock.advance(SIGNED_PREKEY_ROTATION_SECONDS)
    rotated = bob.prepare_upload(ONE_TIME_PREKEY_CAP, PQ_ONE_TIME_PREKEY_CAP)
    assert rotated is not None
    assert rotated.pq_prekey is not None
    assert rotated.pq_prekey.id != bundle.pq_prekey.id

    clients.clock.advance(SIGNED_PREKEY_GRACE_SECONDS)
    bob.delete_expired_prekeys()

    assert bob.store.pq_prekey(bundle.pq_prekey.id, replaced_after=0) is None
    assert bob.receive(initial).result == "UNKNOWN_SIGNED_PREKEY"
