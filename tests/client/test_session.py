from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from client_harness import Clients, Relay, befriend, edit_envelope, rows, send
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from sotto.client import envelope, session
from sotto.client.session import Client, Delivered, OwnIdentityError
from sotto.client.store import MAX_SESSIONS
from sotto.crypto import x3dh
from sotto.crypto.identity import (
    BadBundleError,
    IdentityKeyMismatchError,
    InvalidIdError,
    OneTimePrekey,
    SignedPrekey,
    derive_x25519_public_key,
    sign_identity_dh_key,
    sign_signed_prekey,
)
from sotto.crypto.x3dh import ZeroDhError
from sotto.proto.sotto_pb2 import Content, InitialHeader, PeerMessage

LONGEST_PAYLOAD = 65472


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


def initial_header_of(delivered: Delivered) -> InitialHeader | None:
    peer_message = PeerMessage.FromString(delivered.payload)
    return peer_message.initial_header if peer_message.HasField("initial_header") else None


def no_dh(private_key: bytes, public_key: bytes) -> bytes:
    raise AssertionError("a Diffie-Hellman value was computed")


def test_first_messages_to_an_offline_peer_decrypt_in_order_and_the_reply_ends_the_header(
    alice: Client, bob: Client, relay: Relay
) -> None:
    sent = [send(relay, alice, bob, f"text {number}") for number in range(3)]
    headers = [initial_header_of(delivered) for delivered in sent]

    assert [received.text for received in relay.deliver(bob)] == ["text 0", "text 1", "text 2"]
    assert headers[0] is not None
    assert headers[1:] == headers[:-1]
    assert headers[0].identity_dh_key == alice.identity_dh_key
    assert headers[0].signed_prekey_id == relay.prekeys[bob.identity_key].signed_prekey.id
    assert headers[0].one_time_prekey_id == 1
    assert headers[0].identity_dh_signature == sign_identity_dh_key(
        alice.store.identity().seed,  # type: ignore[union-attr]
        identity_dh_key=alice.identity_dh_key,
    )

    send(relay, bob, alice, "reply")
    assert initial_header_of(send(relay, alice, bob, "after the reply")) is not None
    assert [received.text for received in relay.deliver(alice)] == ["reply"]
    assert initial_header_of(send(relay, alice, bob, "after the decryption")) is None
    assert initial_header_of(send(relay, bob, alice, "from the responder")) is None
    assert [received.text for received in relay.deliver(bob)] == [
        "after the reply",
        "after the decryption",
    ]


def test_two_clients_exchange_texts_in_both_directions(
    alice: Client, bob: Client, relay: Relay
) -> None:
    for round_number in range(4):
        send(relay, alice, bob, f"to bob {round_number}")
        send(relay, alice, bob, f"to bob {round_number}, again")
        assert [received.text for received in relay.deliver(bob)] == [
            f"to bob {round_number}",
            f"to bob {round_number}, again",
        ]
        send(relay, bob, alice, f"to alice {round_number}")
        assert [received.text for received in relay.deliver(alice)] == [
            f"to alice {round_number}"
        ]

    logged = bob.store.connection.execute(
        "SELECT direction, count(*) FROM messages GROUP BY direction ORDER BY direction"
    ).fetchall()
    assert logged == [("in", 8), ("out", 4)]


def test_envelope_delivered_twice_gives_one_text_and_two_acks(
    alice: Client, bob: Client, relay: Relay
) -> None:
    delivered = send(relay, alice, bob, "once")
    first = bob.receive(delivered)
    store_after_first = rows(bob.store)
    second = bob.receive(delivered)

    assert (first.ack, first.text, first.result) == (True, "once", None)
    assert (second.ack, second.text, second.result) == (True, None, "DUPLICATE")
    assert rows(bob.store) == store_after_first


@pytest.mark.parametrize("one_time_count", [1, 0])
def test_replayed_initial_message_gives_no_second_text(
    clients: Clients, relay: Relay, alice: Client, one_time_count: int
) -> None:
    bob = clients.open("bob")
    relay.publish(bob, one_time_count=one_time_count)
    befriend(alice, bob)
    initial = send(relay, alice, bob, "first")
    assert bob.receive(initial).text == "first"

    with bob.store.transaction():
        bob.store.connection.execute("DELETE FROM seen_ids")
    assert bob.receive(initial).result == "DECRYPT_FAILED"

    for number in range(MAX_SESSIONS):
        relay.publish(bob, one_time_count=one_time_count)
        alice.start_session(bob.identity_key, relay.fetch(bob.identity_key))
        assert bob.receive(send(relay, alice, bob, f"new {number}")).text == f"new {number}"
    store_before = rows(bob.store)

    assert bob.receive(initial).result == "REPLAYED_INITIAL"
    assert rows(bob.store) == store_before


def test_later_message_finds_its_session_with_and_without_the_initial_header(
    alice: Client, bob: Client, relay: Relay
) -> None:
    sent = [send(relay, alice, bob, f"text {number}") for number in range(3)]
    stripped = edit_envelope(sent[2], lambda message: message.ClearField("initial_header"))

    assert bob.receive(sent[0]).text == "text 0"
    assert bob.receive(stripped).text == "text 2"
    assert bob.receive(sent[1]).text == "text 1"
    assert len(bob.store.sessions(alice.identity_key)) == 1


def test_bundle_of_another_identity_is_refused_before_any_diffie_hellman(
    clients: Clients, alice: Client, bob: Client, relay: Relay, monkeypatch: pytest.MonkeyPatch
) -> None:
    carol = clients.open("carol")
    relay.publish(carol)
    bundle = replace(relay.fetch(bob.identity_key), identity=carol.identity_key)
    store_before = rows(alice.store)
    monkeypatch.setattr(x3dh, "dh", no_dh)

    with pytest.raises(BadBundleError):
        alice.send_text(bob.identity_key, "hello", bundle=bundle)
    assert rows(alice.store) == store_before


def test_bundle_with_another_x25519_key_than_the_pin_is_refused_before_any_diffie_hellman(
    alice: Client, bob: Client, relay: Relay, monkeypatch: pytest.MonkeyPatch
) -> None:
    send(relay, alice, bob, "pins the key")
    assert alice.store.pin(bob.identity_key) == bob.identity_dh_key
    bob_seed = bob.store.identity().seed  # type: ignore[union-attr]
    other_key = derive_x25519_public_key(bytes(range(32)))
    bundle = replace(
        relay.fetch(bob.identity_key),
        identity_dh_key=other_key,
        identity_dh_signature=sign_identity_dh_key(bob_seed, identity_dh_key=other_key),
    )
    store_before = rows(alice.store)
    monkeypatch.setattr(x3dh, "dh", no_dh)

    with pytest.raises(IdentityKeyMismatchError):
        alice.start_session(bob.identity_key, bundle)
    assert rows(alice.store) == store_before


def test_key_agreement_that_fails_after_the_checks_stores_no_session_and_no_pin(
    alice: Client, bob: Client, relay: Relay
) -> None:
    bob_seed = bob.store.identity().seed  # type: ignore[union-attr]
    small_order_key = bytes(32)
    bundle = relay.fetch(bob.identity_key)
    bundle = replace(
        bundle,
        signed_prekey=SignedPrekey(
            id=bundle.signed_prekey.id,
            key=small_order_key,
            signature=sign_signed_prekey(bob_seed, signed_prekey=small_order_key),
        ),
    )
    store_before = rows(alice.store)

    with pytest.raises(ZeroDhError):
        alice.send_text(bob.identity_key, "hello", bundle=bundle)
    assert rows(alice.store) == store_before


def test_stranger_is_acked_before_a_byte_is_parsed(
    clients: Clients, alice: Client, bob: Client, relay: Relay, monkeypatch: pytest.MonkeyPatch
) -> None:
    carol = clients.open("carol")
    carol.add_contact(bob.identity_key.hex())
    delivered = send(relay, carol, bob, "from a stranger")
    store_before = rows(bob.store)
    monkeypatch.setattr(session, "parse_envelope", None)
    monkeypatch.setattr(x3dh, "dh", no_dh)

    received = bob.receive(delivered)

    assert (received.ack, received.text, received.result) == (True, None, "NOT_A_CONTACT")
    assert rows(bob.store) == store_before


def test_text_to_a_stranger_is_refused(alice: Client, clients: Clients) -> None:
    carol = clients.open("carol")
    with pytest.raises(session.NotAContactError):
        alice.send_text(carol.identity_key, "hello")


def test_invalid_id_adds_no_contact(alice: Client) -> None:
    store_before = rows(alice.store)

    with pytest.raises(InvalidIdError):
        alice.add_contact("0" * 63)
    assert rows(alice.store) == store_before


def test_own_id_is_never_a_contact(alice: Client) -> None:
    with pytest.raises(OwnIdentityError):
        alice.add_contact(alice.identity_key.hex())


def test_substituted_one_time_prekey_ends_in_a_decrypt_failure_and_keeps_the_prekey(
    alice: Client, bob: Client, relay: Relay
) -> None:
    bundle = relay.fetch(bob.identity_key)
    assert bundle.one_time_prekey is not None
    substitute = OneTimePrekey(
        id=bundle.one_time_prekey.id, key=derive_x25519_public_key(bytes(range(1, 33)))
    )
    outgoing = alice.send_text(
        bob.identity_key, "hello", bundle=replace(bundle, one_time_prekey=substitute)
    )
    store_before = rows(bob.store)

    received = bob.receive(relay.send(alice, outgoing))

    assert (received.ack, received.text, received.result) == (True, None, "DECRYPT_FAILED")
    assert rows(bob.store) == store_before
    assert bob.store.one_time_prekey(substitute.id) is not None


def test_one_time_prekey_handed_to_two_initiators_starts_one_session(
    clients: Clients, alice: Client, bob: Client, relay: Relay
) -> None:
    carol = clients.open("carol")
    befriend(carol, bob)
    bundle = relay.fetch(bob.identity_key)
    from_alice = relay.send(alice, alice.send_text(bob.identity_key, "alice", bundle=bundle))
    from_carol = relay.send(carol, carol.send_text(bob.identity_key, "carol", bundle=bundle))

    assert bob.receive(from_alice).text == "alice"
    assert bob.receive(from_carol).result == "UNKNOWN_ONE_TIME_PREKEY"
    assert bob.store.sessions(carol.identity_key) == []


def test_unknown_signed_prekey_id_is_refused(alice: Client, bob: Client, relay: Relay) -> None:
    bundle = relay.fetch(bob.identity_key)
    bundle = replace(bundle, signed_prekey=replace(bundle.signed_prekey, id=99))
    outgoing = alice.send_text(bob.identity_key, "hello", bundle=bundle)

    assert bob.receive(relay.send(alice, outgoing)).result == "UNKNOWN_SIGNED_PREKEY"


def another_key_under_a_good_signature(alice: Client) -> InitialHeader:
    seed = alice.store.identity().seed  # type: ignore[union-attr]
    other_key = derive_x25519_public_key(bytes(range(32)))
    return InitialHeader(
        identity_dh_key=other_key,
        identity_dh_signature=sign_identity_dh_key(seed, identity_dh_key=other_key),
    )


@pytest.mark.parametrize(
    ("change", "result"),
    [
        ("signature", "BAD_INITIAL_HEADER"),
        ("key under its signature", "IDENTITY_KEY_MISMATCH"),
    ],
)
def test_initial_header_that_fails_step_1_or_2_changes_nothing(
    clients: Clients,
    alice: Client,
    bob: Client,
    relay: Relay,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
    result: str,
) -> None:
    assert bob.receive(send(relay, alice, bob, "pins the key")).text == "pins the key"
    other = another_key_under_a_good_signature(alice)

    def edit(peer_message: PeerMessage) -> None:
        if change == "signature":
            peer_message.initial_header.identity_dh_signature = bytes(64)
        else:
            peer_message.initial_header.MergeFrom(other)

    delivered = edit_envelope(send(relay, alice, bob, "second"), edit)
    store_before = rows(bob.store)
    monkeypatch.setattr(x3dh, "dh", no_dh)

    assert bob.receive(delivered).result == result
    assert rows(bob.store) == store_before


def test_message_without_initial_header_from_a_contact_without_session_is_no_session(
    alice: Client, bob: Client, relay: Relay
) -> None:
    delivered = edit_envelope(
        send(relay, alice, bob, "hello"),
        lambda peer_message: peer_message.ClearField("initial_header"),
    )
    store_before = rows(bob.store)

    assert bob.receive(delivered).result == "NO_SESSION"
    assert rows(bob.store) == store_before


@pytest.mark.parametrize("version", [0, 2])
def test_other_version_is_acked_and_changes_nothing(
    alice: Client, bob: Client, relay: Relay, version: int
) -> None:
    delivered = edit_envelope(
        send(relay, alice, bob, "hello"),
        lambda peer_message: setattr(peer_message, "version", version),
    )
    store_before = rows(bob.store)

    received = bob.receive(delivered)

    assert (received.text, received.result) == (None, "UNSUPPORTED_VERSION")
    assert received.ack
    assert rows(bob.store) == store_before


@pytest.mark.parametrize("message", ["initial", "later"])
def test_crash_between_decryption_and_commit_changes_nothing_and_the_message_decrypts_again(
    alice: Client, bob: Client, relay: Relay, monkeypatch: pytest.MonkeyPatch, message: str
) -> None:
    if message == "later":
        assert bob.receive(send(relay, alice, bob, "first")).text == "first"
        send(relay, bob, alice, "reply")
        relay.deliver(alice)
    delivered = send(relay, alice, bob, "survives the crash")
    store_before = rows(bob.store)

    def crash(sender: bytes, message_id: bytes, *, seen_at: int) -> None:
        raise RuntimeError("the client stopped")

    with monkeypatch.context() as patch:
        patch.setattr(bob.store, "add_seen_id", crash)
        with pytest.raises(RuntimeError):
            bob.receive(delivered)
    assert rows(bob.store) == store_before

    assert bob.receive(delivered).text == "survives the crash"


def test_outbox_bytes_sent_again_after_a_crash_give_one_text(
    clients: Clients, alice: Client, bob: Client, relay: Relay
) -> None:
    lost = alice.send_text(bob.identity_key, "lost", bundle=relay.fetch(bob.identity_key))
    stored = alice.send_text(bob.identity_key, "stored before the crash")
    relay.send(alice, stored)
    alice.store.close()

    restarted = clients.open("alice")
    outbox = restarted.outbox()
    assert outbox == [lost, stored]
    for outgoing in outbox:
        relay.send(restarted, outgoing)

    received = relay.deliver(bob)
    assert [(r.text, r.result) for r in received] == [
        ("stored before the crash", None),
        ("lost", None),
        (None, "DUPLICATE"),
    ]
    for outgoing in outbox:
        restarted.confirm_stored(outgoing.message_id)
    assert restarted.outbox() == []


def test_text_too_long_is_refused_before_any_bundle_or_key_agreement(
    alice: Client, bob: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    store_before = rows(alice.store)
    monkeypatch.setattr(x3dh, "initiate", None)

    with pytest.raises(envelope.TextTooLongError):
        alice.send_text(bob.identity_key, "x" * (envelope.MAX_TEXT_BYTES + 1))
    assert rows(alice.store) == store_before


def test_largest_text_fits_a_payload_with_an_initial_header(
    alice: Client, bob: Client, relay: Relay
) -> None:
    text = chr(0xE9) * (envelope.MAX_TEXT_BYTES // 2) + "x"
    delivered = send(relay, alice, bob, text)
    peer_message = PeerMessage.FromString(delivered.payload)

    assert len(text.encode()) == envelope.MAX_TEXT_BYTES
    assert peer_message.HasField("initial_header")
    assert len(peer_message.ciphertext) == 65052
    assert len(delivered.payload) <= LONGEST_PAYLOAD
    assert bob.receive(delivered).text == text


def test_receiver_applies_no_limit_to_a_text(
    alice: Client, bob: Client, relay: Relay, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = "x" * (envelope.MAX_TEXT_BYTES * 2)
    with monkeypatch.context() as patch:
        patch.setattr(envelope, "MAX_TEXT_BYTES", len(text))
        delivered = send(relay, alice, bob, text)

    assert bob.receive(delivered).text == text


@pytest.mark.parametrize(
    ("plaintext", "result"),
    [
        (bytes(256), "BAD_PADDING"),
        (envelope.pad(b"\x0a\x02\xff\xfe"), "BAD_CONTENT"),
        (envelope.pad(Content().SerializeToString()), "UNKNOWN_CONTENT"),
    ],
)
def test_message_without_a_text_saves_its_state_and_seen_id_and_logs_nothing(
    alice: Client,
    bob: Client,
    relay: Relay,
    monkeypatch: pytest.MonkeyPatch,
    plaintext: bytes,
    result: str,
) -> None:
    with monkeypatch.context() as patch:
        patch.setattr(session, "encode_text", lambda text: plaintext)
        delivered = send(relay, alice, bob, "never read")

    received = bob.receive(delivered)

    assert (received.ack, received.text, received.result) == (True, None, result)
    assert bob.store.is_seen(alice.identity_key, delivered.message_id)
    assert bob.store.connection.execute("SELECT count(*) FROM messages").fetchone() == (0,)
    assert bob.receive(send(relay, alice, bob, "next")).text == "next"


def test_stored_responder_session_holds_neither_the_secret_nor_the_signed_prekey(
    alice: Client, bob: Client, relay: Relay
) -> None:
    delivered = send(relay, alice, bob, "hello")
    header = initial_header_of(delivered)
    assert header is not None
    bob_identity = bob.store.identity()
    signed_prekey_private_key = bob.store.signed_prekey(
        header.signed_prekey_id, replaced_after=0
    )
    one_time_prekey_private_key = bob.store.one_time_prekey(header.one_time_prekey_id)
    assert bob_identity is not None
    assert signed_prekey_private_key is not None
    agreement = x3dh.respond(
        identity_key=bob.identity_key,
        identity_dh_private_key=bob_identity.identity_dh_private_key,
        signed_prekey_private_key=signed_prekey_private_key,
        one_time_prekey_private_key=one_time_prekey_private_key,
        sender_identity_key=alice.identity_key,
        sender_identity_dh_key=header.identity_dh_key,
        sender_identity_dh_signature=header.identity_dh_signature,
        ephemeral_key=header.ephemeral_key,
        pinned_identity_dh_key=None,
    )

    assert bob.receive(delivered).text == "hello"
    (state,) = bob.store.connection.execute("SELECT state FROM sessions").fetchone()
    assert agreement.shared_secret.hex() not in state
    assert signed_prekey_private_key.hex() not in state
    assert bob.store.one_time_prekey(header.one_time_prekey_id) is None
    assert bob.store.pin(alice.identity_key) == alice.identity_dh_key


@pytest.fixture
def conversation(clients: Clients, relay: Relay) -> tuple[Client, Client, Delivered]:
    """Bob holds a session with Alice and a real delivered message to change."""
    alice = clients.open("alice")
    bob = clients.open("bob")
    relay.publish(bob)
    befriend(alice, bob)
    assert bob.receive(send(relay, alice, bob, "first")).text == "first"
    return alice, bob, send(relay, alice, bob, "second")


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(data=st.data())
def test_arbitrary_payload_ends_in_a_named_result_and_an_unchanged_store(
    conversation: tuple[Client, Client, Delivered], data: st.DataObject
) -> None:
    alice, bob, real = conversation
    changed_byte = st.tuples(st.integers(0, len(real.payload) - 1), st.integers(0, 255)).map(
        lambda change: _replace_byte(real.payload, *change)
    )
    payload = data.draw(st.binary(max_size=1000) | changed_byte)
    message_id = data.draw(st.binary(min_size=16, max_size=16))
    store_before = rows(bob.store)

    delivered = Delivered(sender=alice.identity_key, message_id=message_id, payload=payload)

    received = bob.receive(delivered)

    assert received.ack
    assert received.text is None
    assert received.result is not None
    assert rows(bob.store) == store_before


def _replace_byte(payload: bytes, position: int, value: int) -> bytes:
    return payload[:position] + bytes([value]) + payload[position + 1 :]


def test_store_restarts_with_the_session(
    clients: Clients, alice: Client, bob: Client, relay: Relay
) -> None:
    send(relay, alice, bob, "before")
    relay.deliver(bob)
    bob.store.close()

    restarted = clients.open("bob")
    assert restarted.identity_key == bob.identity_key
    assert restarted.receive(send(relay, alice, restarted, "after")).text == "after"
