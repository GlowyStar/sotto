import re
from dataclasses import dataclass, replace
from itertools import count
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    RuleBasedStateMachine,
    invariant,
    precondition,
    rule,
    run_state_machine_as_test,
)

from sotto.crypto import ratchet
from sotto.crypto.identity import CryptoError, derive_x25519_public_key
from sotto.crypto.ratchet import (
    MAX_SKIP,
    SKIPPED_KEY_STEPS,
    SKIPPED_KEYS_CAP,
    ChainExhaustedError,
    DecryptFailedError,
    NoSendingChainError,
    RatchetState,
    SkippedKey,
    TooManySkippedError,
    decrypt,
    encrypt,
    init_initiator,
    init_responder,
    kdf_ck,
)
from sotto.crypto.x3dh import ZeroDhError

INITIATOR = "initiator"
RESPONDER = "responder"
PEER = {INITIATOR: RESPONDER, RESPONDER: INITIATOR}
SHARED_SECRET = bytes(range(32))
SESSION_DATA = bytes([0x01]) + bytes(range(160))
SIGNED_PREKEY_SECRET = bytes([0x12]) * 32
SIGNED_PREKEY = derive_x25519_public_key(SIGNED_PREKEY_SECRET)
FIRST_RATCHET_SECRET = bytes([0x21]) * 32
NONCE = bytes(12)
LAST_NUMBER = 2**32 - 1
TOP_BIT = 0x80
X25519_ORDER_8 = bytes.fromhex(
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"
)
CONSTANT_ROW = re.compile(r"^\| (\w+) +\| (\d+) +\|", re.MULTILINE)
PARTS = ["header", "nonce", "body", "tag", "message_id"]


@dataclass(frozen=True, slots=True, kw_only=True)
class Message:
    sender: str
    message_id: bytes
    header: bytes
    ciphertext: bytes
    padded_plaintext: bytes

    def tampered(self, part: str, index: int) -> Message:
        """The message with one byte of a part changed, `index` taken modulo its length."""
        nonce, body, tag = self.ciphertext[:12], self.ciphertext[12:-16], self.ciphertext[-16:]
        parts = {
            "header": self.header,
            "nonce": nonce,
            "body": body,
            "tag": tag,
            "message_id": self.message_id,
        }
        changed = parts[part]
        position = index % len(changed)
        flipped = bytes([changed[position] ^ 0x01])
        parts[part] = changed[:position] + flipped + changed[position + 1 :]
        return replace(
            self,
            header=parts["header"],
            ciphertext=parts["nonce"] + parts["body"] + parts["tag"],
            message_id=parts["message_id"],
        )


class Session:
    """Two sides of one session that encrypt with fresh ids and random bytes from counters."""

    def __init__(self, signed_prekey: bytes = SIGNED_PREKEY) -> None:
        self.numbers = count()
        self.states = {
            INITIATOR: init_initiator(
                shared_secret=SHARED_SECRET,
                signed_prekey=signed_prekey,
                ratchet_private_key=FIRST_RATCHET_SECRET,
            ),
            RESPONDER: init_responder(
                shared_secret=SHARED_SECRET,
                signed_prekey_private_key=SIGNED_PREKEY_SECRET,
            ),
        }

    def send(self, sender: str, padded_plaintext: bytes = b"text") -> Message:
        number = next(self.numbers)
        message_id = number.to_bytes(16, "big")
        encrypted = encrypt(
            self.states[sender],
            padded_plaintext,
            associated_data=SESSION_DATA + message_id,
            nonce=number.to_bytes(12, "big"),
        )
        self.states[sender] = encrypted.state
        return Message(
            sender=sender,
            message_id=message_id,
            header=encrypted.header,
            ciphertext=encrypted.ciphertext,
            padded_plaintext=padded_plaintext,
        )

    def open(self, message: Message, state: RatchetState | None = None) -> ratchet.Decrypted:
        receiver = PEER[message.sender]
        return decrypt(
            state or self.states[receiver],
            message.header,
            message.ciphertext,
            associated_data=SESSION_DATA + message.message_id,
            ratchet_private_key=next(self.numbers).to_bytes(32, "big"),
        )

    def deliver(self, message: Message) -> ratchet.Decrypted:
        decrypted = self.open(message)
        self.states[PEER[message.sender]] = decrypted.state
        return decrypted

    def exchange(self, rounds: int) -> list[ratchet.Decrypted]:
        """Each round the responder answers and the initiator answers back: two DH steps."""
        results = []
        for _ in range(rounds):
            results.append(self.deliver(self.send(RESPONDER)))
            results.append(self.deliver(self.send(INITIATOR)))
        return results


def forbid_key_derivation(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_arguments: bytes) -> tuple[bytes, bytes]:
        raise AssertionError("a key was derived")

    for name in ("kdf_ck", "kdf_rk", "dh"):
        monkeypatch.setattr(ratchet, name, refuse)


def header_of(ratchet_key: bytes, previous_count: int, number: int) -> bytes:
    return ratchet_key + previous_count.to_bytes(4, "big") + number.to_bytes(4, "big")


class Conversation(RuleBasedStateMachine):
    """Two sides that send, deliver in any order, lose, repeat and tamper with messages."""

    def __init__(self) -> None:
        super().__init__()
        self.session = Session()
        self.in_flight: list[Message] = []
        self.delivered: list[Message] = []
        self.accepted_keys: dict[str, set[bytes]] = {INITIATOR: set(), RESPONDER: set()}

    def can_open(self, message: Message) -> bool:
        state = self.session.states[PEER[message.sender]]
        ratchet_key = message.header[:32]
        number = int.from_bytes(message.header[36:])
        has_an_entry = any(
            entry.ratchet_key == ratchet_key and entry.number == number
            for entry in state.mkskipped
        )
        if has_an_entry:
            return True
        if ratchet_key == state.dhr:
            return number >= state.nr
        return ratchet_key not in self.accepted_keys[PEER[message.sender]]

    @rule(
        sender=st.sampled_from([INITIATOR, RESPONDER]), text=st.binary(min_size=1, max_size=64)
    )
    def send(self, sender: str, text: bytes) -> None:
        if self.session.states[sender].cks is None:
            with pytest.raises(NoSendingChainError):
                self.session.send(sender, text)
            return
        self.in_flight.append(self.session.send(sender, text))

    @precondition(lambda self: self.in_flight)
    @rule(data=st.data())
    def deliver(self, data: st.DataObject) -> None:
        message = self.in_flight.pop(data.draw(st.integers(0, len(self.in_flight) - 1)))
        receiver = PEER[message.sender]
        can_open = self.can_open(message)
        before = self.session.states[receiver]

        try:
            decrypted = self.session.deliver(message)
        except DecryptFailedError:
            assert not can_open
            assert self.session.states[receiver] is before
            return
        assert can_open
        assert decrypted.padded_plaintext == message.padded_plaintext
        self.accepted_keys[receiver].add(message.header[:32])
        self.delivered.append(message)

    @precondition(lambda self: self.in_flight)
    @rule(data=st.data())
    def drop(self, data: st.DataObject) -> None:
        self.in_flight.pop(data.draw(st.integers(0, len(self.in_flight) - 1)))

    @precondition(lambda self: self.delivered)
    @rule(data=st.data())
    def duplicate(self, data: st.DataObject) -> None:
        message = data.draw(st.sampled_from(self.delivered))
        before = self.session.states[PEER[message.sender]]

        with pytest.raises(DecryptFailedError):
            self.session.deliver(message)
        assert self.session.states[PEER[message.sender]] is before

    @precondition(lambda self: self.in_flight or self.delivered)
    @rule(data=st.data(), part=st.sampled_from(PARTS), index=st.integers(0, 2**16))
    def tamper(self, data: st.DataObject, part: str, index: int) -> None:
        message = data.draw(st.sampled_from(self.in_flight + self.delivered))
        receiver = PEER[message.sender]
        before = self.session.states[receiver]
        copy = replace(before)

        with pytest.raises(CryptoError):
            self.session.deliver(message.tampered(part, index))
        assert self.session.states[receiver] is before
        assert before == copy

    @invariant()
    def skipped_keys_stay_under_the_cap(self) -> None:
        for state in self.session.states.values():
            assert len(state.mkskipped) <= SKIPPED_KEYS_CAP


def test_random_conversations_keep_the_invariants() -> None:
    run_state_machine_as_test(
        Conversation, settings=settings(max_examples=60, stateful_step_count=50)
    )


def test_failed_decryption_leaves_the_state_as_it_was() -> None:
    session = Session()
    first, second, third = (session.send(INITIATOR) for _ in range(3))
    session.deliver(third)
    session.deliver(session.send(RESPONDER))
    later = session.send(INITIATOR)
    responder = session.states[RESPONDER]
    copy = replace(responder)

    for message in (first, later):
        for part in PARTS:
            with pytest.raises(DecryptFailedError):
                session.deliver(message.tampered(part, 5))
            assert session.states[RESPONDER] is responder
            assert responder == copy
    assert session.deliver(first).padded_plaintext == first.padded_plaintext
    assert session.deliver(second).padded_plaintext == second.padded_plaintext
    assert session.deliver(later).padded_plaintext == later.padded_plaintext


def test_too_many_skipped_keys_are_refused_before_any_key_is_derived(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = Session()
    first = session.send(INITIATOR)
    session.deliver(first)
    state = session.states[RESPONDER]
    current = first.header[:32]
    new = derive_x25519_public_key(bytes([0x33]) * 32)
    headers = [
        header_of(current, 0, state.nr + MAX_SKIP + 1),
        header_of(new, state.nr + MAX_SKIP + 1, 0),
        header_of(new, 0, MAX_SKIP + 1),
    ]
    forbid_key_derivation(monkeypatch)

    for header in headers:
        with pytest.raises(TooManySkippedError):
            session.deliver(replace(first, header=header))


def test_a_header_may_skip_exactly_max_skip_keys() -> None:
    session = Session()
    messages = [session.send(INITIATOR) for _ in range(MAX_SKIP + 2)]
    session.deliver(messages[0])

    decrypted = session.deliver(messages[-1])

    assert len(decrypted.state.mkskipped) == MAX_SKIP
    assert session.deliver(messages[1]).padded_plaintext == messages[1].padded_plaintext


def test_the_cap_removes_the_oldest_entry_and_counts_it() -> None:
    session = Session()
    first, _lost, third = (session.send(INITIATOR) for _ in range(3))
    session.deliver(first)
    state = session.states[RESPONDER]
    filler = tuple(
        SkippedKey(ratchet_key=bytes(32), number=number, message_key=bytes(32), step=1)
        for number in range(SKIPPED_KEYS_CAP)
    )
    session.states[RESPONDER] = replace(state, mkskipped=filler)

    decrypted = session.deliver(third)

    assert decrypted.purged == 1
    assert decrypted.state.mkskipped[:-1] == filler[1:]
    assert decrypted.state.mkskipped[-1].number == 1


def test_entries_are_purged_with_the_fifth_dh_ratchet_step() -> None:
    session = Session()
    lost, second = session.send(INITIATOR), session.send(INITIATOR)
    session.deliver(second)
    at_the_responder = session.exchange(SKIPPED_KEY_STEPS)[1::2]
    kept = [1] * (SKIPPED_KEY_STEPS - 1)

    assert [result.state.dhsteps for result in at_the_responder] == [2, 3, 4, 5, 6]
    assert [len(result.state.mkskipped) for result in at_the_responder] == [*kept, 0]
    assert [result.purged for result in at_the_responder] == [0, 0, 0, 0, 1]
    with pytest.raises(DecryptFailedError):
        session.deliver(lost)


def test_an_entry_for_the_same_key_and_number_is_replaced_and_not_counted() -> None:
    session = Session()
    first, second, third = (session.send(INITIATOR) for _ in range(3))
    session.deliver(first)
    state = session.states[RESPONDER]
    assert state.dhr is not None
    stale = SkippedKey(ratchet_key=state.dhr, number=1, message_key=bytes(32), step=1)
    others = tuple(
        SkippedKey(ratchet_key=bytes(32), number=number, message_key=bytes(32), step=1)
        for number in range(SKIPPED_KEYS_CAP - 1)
    )
    session.states[RESPONDER] = replace(state, mkskipped=(stale, *others))

    decrypted = session.deliver(third)

    assert decrypted.purged == 0
    assert decrypted.state.mkskipped[:-1] == others
    assert decrypted.state.mkskipped[-1].number == 1
    assert decrypted.state.mkskipped[-1].message_key != stale.message_key
    assert session.deliver(second).padded_plaintext == second.padded_plaintext


def test_a_chain_ends_at_the_number_before_the_last(monkeypatch: pytest.MonkeyPatch) -> None:
    session = Session()
    first = session.send(INITIATOR)
    near_the_end = replace(session.states[INITIATOR], ns=LAST_NUMBER - 1)
    session.states[INITIATOR] = near_the_end

    last = session.send(INITIATOR)

    assert last.header[36:] == (LAST_NUMBER - 1).to_bytes(4, "big")
    with pytest.raises(ChainExhaustedError):
        session.send(INITIATOR)
    forbid_key_derivation(monkeypatch)
    with pytest.raises(ChainExhaustedError):
        session.deliver(replace(first, header=header_of(first.header[:32], 0, LAST_NUMBER)))


def test_responder_has_no_sending_chain_before_its_first_decryption() -> None:
    session = Session()

    with pytest.raises(NoSendingChainError):
        session.send(RESPONDER)


def test_a_ratchet_key_of_small_order_is_refused() -> None:
    session = Session()
    first = session.send(INITIATOR)

    with pytest.raises(ZeroDhError):
        Session(signed_prekey=X25519_ORDER_8)
    with pytest.raises(ZeroDhError):
        session.deliver(replace(first, header=header_of(X25519_ORDER_8, 0, 0)))


def test_copy_after_a_message_opens_none_of_the_messages_before() -> None:
    session = Session()
    messages = [session.send(INITIATOR) for _ in range(5)]
    for message in messages:
        session.deliver(message)
    stolen = session.states[RESPONDER]

    for message in messages:
        with pytest.raises(DecryptFailedError):
            session.open(message, stolen)


def test_copy_stops_opening_after_a_dh_ratchet_step_it_did_not_see() -> None:
    session = Session()
    session.deliver(session.send(INITIATOR))
    stolen = session.states[RESPONDER]
    session.deliver(session.send(RESPONDER))
    session.deliver(session.send(INITIATOR))

    sent_by_the_owner = session.send(RESPONDER)
    session.deliver(sent_by_the_owner)
    answer = session.send(INITIATOR)

    with pytest.raises(DecryptFailedError):
        session.open(answer, stolen)
    assert not opens_with_a_key_of(stolen, sent_by_the_owner)


def opens_with_a_key_of(state: RatchetState, message: Message) -> bool:
    """Whether a message key of the chains of the state, the first 100 of each, opens it."""
    keys = []
    for chain_key in (state.cks, state.ckr):
        if chain_key is None:
            continue
        for _ in range(100):
            message_key, chain_key = kdf_ck(chain_key)
            keys.append(message_key)
    keys += [entry.message_key for entry in state.mkskipped]

    for message_key in keys:
        try:
            ChaCha20Poly1305(message_key).decrypt(
                message.ciphertext[:12],
                message.ciphertext[12:],
                SESSION_DATA + message.message_id + message.header,
            )
        except InvalidTag:
            continue
        return True
    return False


def test_ratchet_keys_are_kept_as_the_bytes_received() -> None:
    received_bytes = SIGNED_PREKEY[:31] + bytes([SIGNED_PREKEY[31] | TOP_BIT])
    session = Session(signed_prekey=received_bytes)
    first = session.send(INITIATOR)
    session.deliver(first)
    answer = session.send(RESPONDER)
    session.deliver(answer)

    assert received_bytes != SIGNED_PREKEY
    assert session.states[RESPONDER].dhr == first.header[:32]
    assert session.states[INITIATOR].dhr == answer.header[:32]


def test_same_arguments_give_the_same_bytes() -> None:
    def run() -> list[bytes]:
        session = Session()
        messages = [session.send(INITIATOR), session.send(INITIATOR)]
        session.deliver(messages[1])
        messages.append(session.send(RESPONDER))
        return [message.header + message.ciphertext for message in messages]

    assert run() == run()


def test_arguments_of_another_length_are_refused() -> None:
    session = Session()
    message = session.send(INITIATOR)
    state = session.states[RESPONDER]

    with pytest.raises(ValueError, match="associated_data"):
        encrypt(session.states[INITIATOR], b"", associated_data=SESSION_DATA, nonce=NONCE)
    with pytest.raises(ValueError, match="nonce"):
        encrypt(
            session.states[INITIATOR],
            b"",
            associated_data=SESSION_DATA + message.message_id,
            nonce=NONCE[1:],
        )
    with pytest.raises(ValueError, match="header"):
        decrypt(
            state,
            message.header[1:],
            message.ciphertext,
            associated_data=SESSION_DATA + message.message_id,
            ratchet_private_key=bytes(32),
        )


def test_constants_are_those_of_section_24_1() -> None:
    protocol = (Path(__file__).parent.parent.parent / "docs" / "protocol.md").read_text(
        encoding="utf-8"
    )
    start = protocol.index("\n### 24.1 ")
    table = dict(CONSTANT_ROW.findall(protocol[start : protocol.index("\n### 24.2 ")]))

    assert int(table["MAX_SKIP"]) == MAX_SKIP
    assert int(table["SKIPPED_KEYS_CAP"]) == SKIPPED_KEYS_CAP
    assert int(table["SKIPPED_KEY_STEPS"]) == SKIPPED_KEY_STEPS
