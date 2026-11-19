"""A relay that lies (threat model, "What it cannot do"): what it changes, swaps, replays
or makes up ends in no text and an unchanged store, and the real messages still arrive."""

from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from client_harness import Clients, Relay, befriend, edit_envelope, rows, send, texts
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sotto.client.session import SEEN_ID_SECONDS, Client, Delivered
from sotto.crypto.identity import (
    Bundle,
    sign_identity_dh_key,
    sign_pq_prekey,
    sign_signed_prekey,
)
from sotto.proto.sotto_pb2 import PeerMessage


@dataclass(frozen=True, slots=True, kw_only=True)
class World:
    """Bob holds sessions with Alice and Carol; two messages of Alice are on the way."""

    clients: Clients
    relay: Relay
    alice: Client
    bob: Client
    carol: Client
    accepted: Delivered
    later: Delivered
    initial: Delivered


@pytest.fixture
def world(tmp_path: Path) -> Iterator[World]:
    clients = Clients(tmp_path)
    relay = Relay()
    alice, bob, carol = (clients.open(name) for name in ("alice", "bob", "carol"))
    relay.publish(bob, one_time_count=3)
    relay.publish(carol)
    for first, second in ((alice, bob), (carol, bob), (alice, carol)):
        befriend(first, second)
    assert bob.receive(send(relay, carol, bob, "from carol")).text == "from carol"
    accepted = send(relay, alice, bob, "accepted")
    assert bob.receive(accepted).text == "accepted"
    send(relay, bob, alice, "reply")
    relay.deliver(alice)

    later = send(relay, alice, bob, "later")
    alice.start_session(bob.identity_key, relay.fetch(bob.identity_key))
    initial = send(relay, alice, bob, "initial")
    yield World(
        clients=clients,
        relay=relay,
        alice=alice,
        bob=bob,
        carol=carol,
        accepted=accepted,
        later=later,
        initial=initial,
    )
    clients.close()


def flip(data: bytes, position: int, bits: int = 1) -> bytes:
    position %= len(data)
    return data[:position] + bytes([data[position] ^ bits]) + data[position + 1 :]


def keys_of_bob_under_carols_signature(world: World) -> tuple[Client, Delivered]:
    """Alice starts a session with Carol on the X25519 keys of Bob, signed by Carol, and the
    relay hands the message to Bob."""
    bob_bundle = world.relay.fetch(world.bob.identity_key)
    assert bob_bundle.pq_prekey is not None
    carol_identity = world.carol.store.identity()
    assert carol_identity is not None
    carol_seed = carol_identity.seed
    bundle = Bundle(
        identity=world.carol.identity_key,
        identity_dh_key=bob_bundle.identity_dh_key,
        identity_dh_signature=sign_identity_dh_key(
            carol_seed, identity_dh_key=bob_bundle.identity_dh_key
        ),
        signed_prekey=replace(
            bob_bundle.signed_prekey,
            signature=sign_signed_prekey(
                carol_seed, signed_prekey=bob_bundle.signed_prekey.key
            ),
        ),
        one_time_prekey=bob_bundle.one_time_prekey,
        pq_prekey=replace(
            bob_bundle.pq_prekey,
            signature=sign_pq_prekey(carol_seed, pq_prekey=bob_bundle.pq_prekey.key),
        ),
    )
    outgoing = world.alice.send_text(world.carol.identity_key, "for carol", bundle=bundle)
    return world.bob, Delivered(
        sender=world.alice.identity_key,
        message_id=outgoing.message_id,
        payload=outgoing.payload,
    )


def flip_initial_header_field(
    field: str, position: int = 0, bits: int = 1
) -> Callable[[World], tuple[Client, Delivered]]:
    def case(world: World) -> tuple[Client, Delivered]:
        def edit(message: PeerMessage) -> None:
            header = message.initial_header
            setattr(header, field, flip(getattr(header, field), position, bits))

        return world.bob, edit_envelope(world.initial, edit)

    return case


def flip_envelope_field(
    message: str, field: str, position: int
) -> Callable[[World], tuple[Client, Delivered]]:
    def case(world: World) -> tuple[Client, Delivered]:
        def edit(envelope: PeerMessage) -> None:
            setattr(envelope, field, flip(getattr(envelope, field), position))

        return world.bob, edit_envelope(getattr(world, message), edit)

    return case


def replay_after_its_seen_id_is_forgotten(world: World) -> tuple[Client, Delivered]:
    world.clients.clock.advance(SEEN_ID_SECONDS)
    world.bob.forget_seen_ids()
    return world.bob, world.accepted


CASES: dict[str, Callable[[World], tuple[Client, Delivered]]] = {
    "x25519 keys of one identity under the signature of another": (
        keys_of_bob_under_carols_signature
    ),
    "swapped sender of a later message": lambda world: (
        world.bob,
        replace(world.later, sender=world.carol.identity_key),
    ),
    "swapped sender of an initial message": lambda world: (
        world.bob,
        replace(world.initial, sender=world.carol.identity_key),
    ),
    "initial message delivered to another recipient": lambda world: (
        world.carol,
        world.initial,
    ),
    "later message delivered to another recipient": lambda world: (world.carol, world.later),
    "changed byte in the ephemeral key": flip_initial_header_field("ephemeral_key"),
    # X25519 ignores the top bit of the last byte, so the secret stays and the data differs.
    "ephemeral key with the same diffie-hellman outputs": flip_initial_header_field(
        "ephemeral_key", -1, 0x80
    ),
    "changed byte in the x25519 identity key": flip_initial_header_field("identity_dh_key"),
    "changed byte in the signature": flip_initial_header_field("identity_dh_signature"),
    "changed byte in the ratchet key of the header": flip_envelope_field("later", "header", 0),
    "changed byte in the number of the header": flip_envelope_field("later", "header", 39),
    "changed byte in the nonce": flip_envelope_field("later", "ciphertext", 0),
    "changed byte in the nonce of an initial message": flip_envelope_field(
        "initial", "ciphertext", 0
    ),
    "changed byte in the ciphertext": flip_envelope_field("later", "ciphertext", -1),
    "changed message id": lambda world: (
        world.bob,
        replace(world.later, message_id=flip(world.later.message_id, 0)),
    ),
    "changed message id of an initial message": lambda world: (
        world.bob,
        replace(world.initial, message_id=flip(world.initial.message_id, 15)),
    ),
    "stripped one-time prekey id": lambda world: (
        world.bob,
        edit_envelope(
            world.initial,
            lambda message: message.initial_header.ClearField("one_time_prekey_id"),
        ),
    ),
    "replay": lambda world: (world.bob, world.accepted),
    "replay after its seen id is forgotten": replay_after_its_seen_id_is_forgotten,
    "changed byte in the kem ciphertext": flip_initial_header_field("kem_ciphertext", 500),
    "stripped kem ciphertext": lambda world: (
        world.bob,
        edit_envelope(
            world.initial, lambda message: message.initial_header.ClearField("kem_ciphertext")
        ),
    ),
    "changed post-quantum prekey id": lambda world: (
        world.bob,
        edit_envelope(
            world.initial, lambda message: setattr(message.initial_header, "pq_prekey_id", 99)
        ),
    ),
    "new session made version 1": lambda world: (
        world.bob,
        edit_envelope(world.initial, lambda message: setattr(message, "version", 1)),
    ),
    "later message made version 1": lambda world: (
        world.bob,
        edit_envelope(world.later, lambda message: setattr(message, "version", 1)),
    ),
}


RESULTS = {
    "x25519 keys of one identity under the signature of another": "DECRYPT_FAILED",
    "swapped sender of a later message": "DECRYPT_FAILED",
    "swapped sender of an initial message": "BAD_INITIAL_HEADER",
    "initial message delivered to another recipient": "UNKNOWN_ONE_TIME_PREKEY",
    "later message delivered to another recipient": "NO_SESSION",
    "changed byte in the ephemeral key": "DECRYPT_FAILED",
    "ephemeral key with the same diffie-hellman outputs": "DECRYPT_FAILED",
    "changed byte in the x25519 identity key": "BAD_INITIAL_HEADER",
    "changed byte in the signature": "BAD_INITIAL_HEADER",
    "changed byte in the ratchet key of the header": "DECRYPT_FAILED",
    "changed byte in the number of the header": "DECRYPT_FAILED",
    "changed byte in the nonce": "DECRYPT_FAILED",
    "changed byte in the nonce of an initial message": "DECRYPT_FAILED",
    "changed byte in the ciphertext": "DECRYPT_FAILED",
    "changed message id": "DECRYPT_FAILED",
    "changed message id of an initial message": "DECRYPT_FAILED",
    "stripped one-time prekey id": "DECRYPT_FAILED",
    "replay": "DUPLICATE",
    "replay after its seen id is forgotten": "DECRYPT_FAILED",
    "changed byte in the kem ciphertext": "DECRYPT_FAILED",
    "stripped kem ciphertext": "BAD_ENVELOPE",
    "changed post-quantum prekey id": "UNKNOWN_PQ_PREKEY",
    "new session made version 1": "X3DH_REFUSED",
    "later message made version 1": "DECRYPT_FAILED",
}


@pytest.mark.parametrize("name", CASES)
def test_lying_relay_gives_no_text_and_leaves_the_store_unchanged(
    world: World, name: str
) -> None:
    receiver, delivered = CASES[name](world)
    store_before = rows(receiver.store)

    received = receiver.receive(delivered)

    assert (received.ack, received.text, received.result) == (True, None, RESULTS[name])
    assert rows(receiver.store) == store_before
    assert world.bob.receive(world.later).text == "later"
    assert world.bob.receive(world.initial).text == "initial"


def test_changed_prekey_ids_of_a_message_with_a_record_change_nothing(world: World) -> None:
    assert world.bob.receive(world.initial).text == "initial"
    on_the_session = send(world.relay, world.alice, world.bob, "same session")

    def change_the_prekey_ids(message: PeerMessage) -> None:
        message.initial_header.signed_prekey_id = 99
        message.initial_header.ClearField("one_time_prekey_id")

    received = world.bob.receive(edit_envelope(on_the_session, change_the_prekey_ids))

    assert (received.text, received.result) == ("same session", None)


def test_reordered_messages_give_each_text_once(world: World) -> None:
    sent = [send(world.relay, world.alice, world.bob, f"text {number}") for number in range(4)]
    copy = sent[2]

    received = [world.bob.receive(delivered) for delivered in [*reversed(sent), copy]]

    assert texts(received) == ["text 3", "text 2", "text 1", "text 0", None]
    assert received[-1].result == "DUPLICATE"
    assert world.bob.receive(world.later).text == "later"


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], max_examples=50)
@given(data=st.data())
def test_arbitrary_bytes_from_any_sender_end_in_a_named_result(
    world: World, data: st.DataObject
) -> None:
    sender = data.draw(
        st.sampled_from([world.alice.identity_key, world.carol.identity_key])
        | st.binary(min_size=32, max_size=32)
    )
    real = data.draw(st.sampled_from([world.later.payload, world.initial.payload]))
    changed_byte = st.tuples(st.integers(0, len(real) - 1), st.integers(1, 255)).map(
        lambda change: (
            real[: change[0]] + bytes([real[change[0]] ^ change[1]]) + real[change[0] + 1 :]
        )
    )
    payload = data.draw(st.binary(max_size=1000) | changed_byte)
    message_id = data.draw(st.binary(min_size=16, max_size=16))
    store_before = rows(world.bob.store)

    received = world.bob.receive(
        Delivered(sender=sender, message_id=message_id, payload=payload)
    )

    assert (received.ack, received.text) == (True, None)
    assert received.result is not None
    assert rows(world.bob.store) == store_before
