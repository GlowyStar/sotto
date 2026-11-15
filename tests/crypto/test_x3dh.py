from collections.abc import Callable
from dataclasses import dataclass, fields, replace

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from sotto.crypto import x3dh
from sotto.crypto.identity import (
    BadBundleError,
    Bundle,
    CryptoError,
    IdentityKeyMismatchError,
    OneTimePrekey,
    SignedPrekey,
    derive_identity_key,
    derive_x25519_public_key,
    sign_identity_dh_key,
    sign_signed_prekey,
)
from sotto.crypto.x3dh import BadInitialHeaderError, KeyAgreement, ZeroDhError, dh

FIELD_PRIME = 2**255 - 19
TOP_BIT = 1 << 255
# The u-coordinates of small order that fit 255 bits, https://cr.yp.to/ecdh.html#validate.
SMALL_ORDER_U = [
    0,
    1,
    325606250916557431795983626356110631294008115727848805560023387167927233504,
    39382357235489614581723060781553021112529911719440698176882885853963445705823,
    FIELD_PRIME - 1,
    FIELD_PRIME,
    FIELD_PRIME + 1,
]
SMALL_ORDER = [
    (u | top_bit).to_bytes(32, "little") for u in SMALL_ORDER_U for top_bit in (0, TOP_BIT)
]
SIGNED_PREKEY_ID = 7
ONE_TIME_PREKEY_ID = 41

INITIATOR_IDENTITY_DH_KEY = slice(33, 65)
RESPONDER_IDENTITY_KEY = slice(65, 97)
RESPONDER_IDENTITY_DH_KEY = slice(97, 129)
EPHEMERAL_KEY = slice(129, 161)


@dataclass(frozen=True, slots=True, kw_only=True)
class Initiator:
    seed: bytes
    identity_dh_private_key: bytes
    ephemeral_private_key: bytes

    @property
    def identity_key(self) -> bytes:
        return derive_identity_key(self.seed)

    @property
    def identity_dh_key(self) -> bytes:
        return derive_x25519_public_key(self.identity_dh_private_key)

    @property
    def ephemeral_key(self) -> bytes:
        return derive_x25519_public_key(self.ephemeral_private_key)


@dataclass(frozen=True, slots=True, kw_only=True)
class Responder:
    seed: bytes
    identity_dh_private_key: bytes
    signed_prekey_private_key: bytes
    one_time_prekey_private_key: bytes | None

    @property
    def identity_key(self) -> bytes:
        return derive_identity_key(self.seed)


def bundle_signed_by(seed: bytes, owner: Responder) -> Bundle:
    """The X25519 keys of the owner under the signatures of the seed."""
    identity_dh_key = derive_x25519_public_key(owner.identity_dh_private_key)
    signed_prekey = derive_x25519_public_key(owner.signed_prekey_private_key)
    one_time_prekey = None
    if owner.one_time_prekey_private_key is not None:
        one_time_prekey = OneTimePrekey(
            id=ONE_TIME_PREKEY_ID,
            key=derive_x25519_public_key(owner.one_time_prekey_private_key),
        )

    return Bundle(
        identity=derive_identity_key(seed),
        identity_dh_key=identity_dh_key,
        identity_dh_signature=sign_identity_dh_key(seed, identity_dh_key=identity_dh_key),
        signed_prekey=SignedPrekey(
            id=SIGNED_PREKEY_ID,
            key=signed_prekey,
            signature=sign_signed_prekey(seed, signed_prekey=signed_prekey),
        ),
        one_time_prekey=one_time_prekey,
    )


def bundle_of(owner: Responder) -> Bundle:
    return bundle_signed_by(owner.seed, owner)


def initiate(
    initiator: Initiator, bundle: Bundle, pinned_identity_dh_key: bytes | None = None
) -> KeyAgreement:
    return x3dh.initiate(
        bundle,
        identity_key=initiator.identity_key,
        identity_dh_private_key=initiator.identity_dh_private_key,
        ephemeral_private_key=initiator.ephemeral_private_key,
        contact_identity_key=bundle.identity,
        pinned_identity_dh_key=pinned_identity_dh_key,
    )


def respond(
    responder: Responder,
    initiator: Initiator,
    *,
    identity_dh_key: bytes | None = None,
    signature: bytes | None = None,
    ephemeral_key: bytes | None = None,
    pinned_identity_dh_key: bytes | None = None,
) -> KeyAgreement:
    """The responder on the initial header of the initiator, or on other bytes in it.

    Another `identity_dh_key` comes with a valid signature of the initiator over it.
    """
    if identity_dh_key is None:
        identity_dh_key = initiator.identity_dh_key
    if signature is None:
        signature = sign_identity_dh_key(initiator.seed, identity_dh_key=identity_dh_key)
    if ephemeral_key is None:
        ephemeral_key = initiator.ephemeral_key

    return x3dh.respond(
        identity_key=responder.identity_key,
        identity_dh_private_key=responder.identity_dh_private_key,
        signed_prekey_private_key=responder.signed_prekey_private_key,
        one_time_prekey_private_key=responder.one_time_prekey_private_key,
        sender_identity_key=initiator.identity_key,
        sender_identity_dh_key=identity_dh_key,
        sender_identity_dh_signature=signature,
        ephemeral_key=ephemeral_key,
        pinned_identity_dh_key=pinned_identity_dh_key,
    )


def refuse_any_diffie_hellman(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_dh(private_key: bytes, public_key: bytes) -> bytes:
        raise AssertionError("a Diffie-Hellman value was computed")

    monkeypatch.setattr(x3dh, "dh", no_dh)


def with_top_bit(public_key: bytes) -> bytes:
    return public_key[:-1] + bytes([public_key[-1] | 0x80])


def with_inverse_u(public_key: bytes) -> bytes:
    u = int.from_bytes(public_key, "little")
    return pow(u, -1, FIELD_PRIME).to_bytes(32, "little")


keys = st.binary(min_size=32, max_size=32)
initiators = st.builds(
    Initiator,
    seed=keys,
    identity_dh_private_key=keys,
    ephemeral_private_key=keys,
)
responders_with_a_one_time_prekey = st.builds(
    Responder,
    seed=keys,
    identity_dh_private_key=keys,
    signed_prekey_private_key=keys,
    one_time_prekey_private_key=keys,
)
responders_without_a_one_time_prekey = st.builds(
    Responder,
    seed=keys,
    identity_dh_private_key=keys,
    signed_prekey_private_key=keys,
    one_time_prekey_private_key=st.none(),
)
responders = responders_with_a_one_time_prekey | responders_without_a_one_time_prekey
other_bytes = st.sampled_from([with_top_bit, with_inverse_u])

INITIATOR = Initiator(
    seed=bytes([1]) * 32,
    identity_dh_private_key=bytes([2]) * 32,
    ephemeral_private_key=bytes([3]) * 32,
)
RESPONDER = Responder(
    seed=bytes([4]) * 32,
    identity_dh_private_key=bytes([5]) * 32,
    signed_prekey_private_key=bytes([6]) * 32,
    one_time_prekey_private_key=bytes([7]) * 32,
)
WITHOUT_A_ONE_TIME_PREKEY = replace(RESPONDER, one_time_prekey_private_key=None)
RESPONDER_IDENTITY_DH = derive_x25519_public_key(RESPONDER.identity_dh_private_key)


@pytest.mark.parametrize(
    "responders_of_one_kind",
    [responders_with_a_one_time_prekey, responders_without_a_one_time_prekey],
    ids=["with-a-one-time-prekey", "without-a-one-time-prekey"],
)
@given(initiator=initiators, data=st.data())
def test_both_sides_derive_the_same_secret_and_associated_data(
    responders_of_one_kind: st.SearchStrategy[Responder],
    initiator: Initiator,
    data: st.DataObject,
) -> None:
    responder = data.draw(responders_of_one_kind)
    bundle = bundle_of(responder)

    made = initiate(initiator, bundle)
    accepted = respond(responder, initiator)

    assert accepted.shared_secret == made.shared_secret
    assert accepted.associated_data == made.associated_data
    assert made.associated_data == (
        b"\x01"
        + initiator.identity_key
        + initiator.identity_dh_key
        + responder.identity_key
        + bundle.identity_dh_key
        + initiator.ephemeral_key
    )
    assert len(made.associated_data) == 161
    assert len(made.shared_secret) == 32


@given(initiators, responders, keys)
def test_unknown_key_share_gives_the_same_secret_under_other_associated_data(
    initiator: Initiator, owner: Responder, seed_of_the_contact: bytes
) -> None:
    contact = derive_identity_key(seed_of_the_contact)
    assume(contact != owner.identity_key)

    made = initiate(initiator, bundle_signed_by(seed_of_the_contact, owner))
    accepted = respond(owner, initiator)
    of_the_initiator = made.associated_data
    of_the_owner = accepted.associated_data

    assert accepted.shared_secret == made.shared_secret
    assert of_the_initiator[RESPONDER_IDENTITY_KEY] == contact
    assert of_the_owner[RESPONDER_IDENTITY_KEY] == owner.identity_key
    assert of_the_owner[:65] == of_the_initiator[:65]
    assert of_the_owner[97:] == of_the_initiator[97:]


@given(initiators, responders_with_a_one_time_prekey, keys)
def test_replaced_one_time_prekey_gives_the_responder_another_secret(
    initiator: Initiator, responder: Responder, private_key_of_the_relay: bytes
) -> None:
    bundle = bundle_of(responder)
    assert bundle.one_time_prekey is not None
    key_of_the_relay = derive_x25519_public_key(private_key_of_the_relay)
    assume(key_of_the_relay != bundle.one_time_prekey.key)
    replaced = replace(
        bundle, one_time_prekey=OneTimePrekey(id=ONE_TIME_PREKEY_ID, key=key_of_the_relay)
    )

    made = initiate(initiator, replaced)
    accepted = respond(responder, initiator)

    assert accepted.shared_secret != made.shared_secret
    assert accepted.associated_data == made.associated_data


@given(initiators, responders, other_bytes)
def test_other_ephemeral_key_bytes_give_the_same_secret_under_other_associated_data(
    initiator: Initiator, responder: Responder, change: Callable[[bytes], bytes]
) -> None:
    received = change(initiator.ephemeral_key)
    made = initiate(initiator, bundle_of(responder))

    accepted = respond(responder, initiator, ephemeral_key=received)

    assert received != initiator.ephemeral_key
    assert accepted.shared_secret == made.shared_secret
    assert accepted.associated_data[EPHEMERAL_KEY] == received
    assert accepted.associated_data[:129] == made.associated_data[:129]


@given(initiators, responders)
def test_public_keys_enter_the_associated_data_as_the_bytes_received(
    initiator: Initiator, responder: Responder
) -> None:
    identity_dh_key = with_top_bit(initiator.identity_dh_key)
    ephemeral_key = with_top_bit(initiator.ephemeral_key)
    bundle = bundle_of(responder)
    own_key = with_top_bit(bundle.identity_dh_key)
    bundle_with_other_bytes = replace(
        bundle,
        identity_dh_key=own_key,
        identity_dh_signature=sign_identity_dh_key(responder.seed, identity_dh_key=own_key),
    )

    accepted = respond(
        responder, initiator, identity_dh_key=identity_dh_key, ephemeral_key=ephemeral_key
    )
    made = initiate(initiator, bundle_with_other_bytes)

    assert accepted.associated_data[INITIATOR_IDENTITY_DH_KEY] == identity_dh_key
    assert accepted.associated_data[EPHEMERAL_KEY] == ephemeral_key
    assert made.associated_data[RESPONDER_IDENTITY_DH_KEY] == own_key
    assert made.shared_secret == initiate(initiator, bundle).shared_secret


@given(keys, keys | st.sampled_from(SMALL_ORDER))
def test_dh_refuses_exactly_the_keys_of_small_order(
    private_key: bytes, public_key: bytes
) -> None:
    u = int.from_bytes(public_key, "little") % TOP_BIT % FIELD_PRIME
    has_small_order = u in SMALL_ORDER_U

    if has_small_order:
        with pytest.raises(ZeroDhError):
            dh(private_key, public_key)
    else:
        assert any(dh(private_key, public_key))


@pytest.mark.parametrize("small_order_key", SMALL_ORDER, ids=bytes.hex)
def test_every_small_order_key_ends_in_zero_dh(
    small_order_key: bytes,
) -> None:
    with pytest.raises(ZeroDhError) as refusal:
        dh(RESPONDER.identity_dh_private_key, small_order_key)

    assert refusal.value.result == "ZERO_DH"
    assert not isinstance(refusal.value, ValueError)


def test_zero_output_the_library_returns_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    class LibraryThatReturnsZero:
        @staticmethod
        def from_private_bytes(data: bytes) -> LibraryThatReturnsZero:
            return LibraryThatReturnsZero()

        def exchange(self, peer_public_key: object) -> bytes:
            return bytes(32)

    monkeypatch.setattr(x3dh, "X25519PrivateKey", LibraryThatReturnsZero)

    with pytest.raises(ZeroDhError):
        dh(RESPONDER.identity_dh_private_key, INITIATOR.ephemeral_key)


@pytest.mark.parametrize("small_order_key", [SMALL_ORDER[0], SMALL_ORDER[4]], ids=bytes.hex)
def test_small_order_key_in_any_place_ends_the_key_agreement(small_order_key: bytes) -> None:
    bundle = bundle_of(RESPONDER)
    seed = RESPONDER.seed
    with_identity_dh_key = replace(
        bundle,
        identity_dh_key=small_order_key,
        identity_dh_signature=sign_identity_dh_key(seed, identity_dh_key=small_order_key),
    )
    with_signed_prekey = replace(
        bundle,
        signed_prekey=SignedPrekey(
            id=SIGNED_PREKEY_ID,
            key=small_order_key,
            signature=sign_signed_prekey(seed, signed_prekey=small_order_key),
        ),
    )
    with_one_time_prekey = replace(
        bundle, one_time_prekey=OneTimePrekey(id=ONE_TIME_PREKEY_ID, key=small_order_key)
    )

    for refused in (with_identity_dh_key, with_signed_prekey, with_one_time_prekey):
        with pytest.raises(ZeroDhError):
            initiate(INITIATOR, refused)
    with pytest.raises(ZeroDhError):
        respond(RESPONDER, INITIATOR, identity_dh_key=small_order_key)
    with pytest.raises(ZeroDhError):
        respond(RESPONDER, INITIATOR, ephemeral_key=small_order_key)
    with pytest.raises(ZeroDhError):
        respond(WITHOUT_A_ONE_TIME_PREKEY, INITIATOR, ephemeral_key=small_order_key)


def test_bundle_that_fails_a_check_reaches_no_diffie_hellman_computation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = bundle_of(RESPONDER)
    with_a_bad_signature = replace(bundle, identity_dh_signature=bytes(64))
    another_key = derive_x25519_public_key(bytes([8]) * 32)
    refuse_any_diffie_hellman(monkeypatch)

    with pytest.raises(BadBundleError):
        initiate(INITIATOR, with_a_bad_signature)
    with pytest.raises(IdentityKeyMismatchError):
        initiate(INITIATOR, bundle, pinned_identity_dh_key=another_key)


def test_initial_header_that_fails_a_check_reaches_no_diffie_hellman_computation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    other_seed = bytes([9]) * 32
    signed_by_another_identity = sign_identity_dh_key(
        other_seed, identity_dh_key=INITIATOR.identity_dh_key
    )
    another_key = derive_x25519_public_key(bytes([8]) * 32)
    refuse_any_diffie_hellman(monkeypatch)

    with pytest.raises(BadInitialHeaderError) as refusal:
        respond(RESPONDER, INITIATOR, signature=signed_by_another_identity)
    assert refusal.value.result == "BAD_INITIAL_HEADER"
    with pytest.raises(BadInitialHeaderError):
        respond(RESPONDER, INITIATOR, signature=bytes(64))
    with pytest.raises(IdentityKeyMismatchError):
        respond(RESPONDER, INITIATOR, pinned_identity_dh_key=another_key)


def test_initial_header_signature_is_checked_before_the_pin() -> None:
    another_key = derive_x25519_public_key(bytes([8]) * 32)

    with pytest.raises(BadInitialHeaderError):
        respond(
            RESPONDER,
            INITIATOR,
            identity_dh_key=another_key,
            signature=sign_identity_dh_key(
                INITIATOR.seed, identity_dh_key=INITIATOR.identity_dh_key
            ),
            pinned_identity_dh_key=INITIATOR.identity_dh_key,
        )


def test_pinned_key_lets_both_sides_agree() -> None:
    made = initiate(INITIATOR, bundle_of(RESPONDER), RESPONDER_IDENTITY_DH)
    accepted = respond(RESPONDER, INITIATOR, pinned_identity_dh_key=INITIATOR.identity_dh_key)

    assert accepted == made


def test_one_time_prekey_id_taken_out_or_put_in_gives_another_secret() -> None:
    with_dh4 = initiate(INITIATOR, bundle_of(RESPONDER))
    without_dh4 = initiate(INITIATOR, bundle_of(WITHOUT_A_ONE_TIME_PREKEY))

    taken_out = respond(WITHOUT_A_ONE_TIME_PREKEY, INITIATOR)
    put_in = respond(RESPONDER, INITIATOR)

    assert taken_out.shared_secret != with_dh4.shared_secret
    assert put_in.shared_secret != without_dh4.shared_secret
    assert taken_out.associated_data == with_dh4.associated_data


def test_key_agreement_hands_back_the_secret_and_the_associated_data_only() -> None:
    made = initiate(INITIATOR, bundle_of(RESPONDER))

    assert [field.name for field in fields(made)] == ["shared_secret", "associated_data"]
    assert "shared_secret" not in repr(made)
    assert repr(made.shared_secret) not in repr(made)
    assert made.shared_secret.hex() not in repr(made)


WRONG_LENGTHS: list[Callable[[], object]] = [
    lambda: dh(bytes(31), INITIATOR.ephemeral_key),
    lambda: dh(RESPONDER.identity_dh_private_key, bytes(33)),
    lambda: x3dh.initiate(
        bundle_of(RESPONDER),
        identity_key=bytes(31),
        identity_dh_private_key=INITIATOR.identity_dh_private_key,
        ephemeral_private_key=INITIATOR.ephemeral_private_key,
        contact_identity_key=RESPONDER.identity_key,
        pinned_identity_dh_key=None,
    ),
    lambda: x3dh.initiate(
        bundle_of(RESPONDER),
        identity_key=INITIATOR.identity_key,
        identity_dh_private_key=INITIATOR.identity_dh_private_key,
        ephemeral_private_key=bytes(33),
        contact_identity_key=RESPONDER.identity_key,
        pinned_identity_dh_key=None,
    ),
    lambda: initiate(
        INITIATOR,
        replace(
            bundle_of(RESPONDER),
            one_time_prekey=OneTimePrekey(id=ONE_TIME_PREKEY_ID, key=bytes(31)),
        ),
    ),
    lambda: initiate(INITIATOR, bundle_of(RESPONDER), bytes(31)),
    lambda: respond(RESPONDER, INITIATOR, ephemeral_key=bytes(31)),
    lambda: respond(RESPONDER, INITIATOR, identity_dh_key=bytes(33)),
    lambda: respond(RESPONDER, INITIATOR, signature=bytes(63)),
    lambda: respond(RESPONDER, INITIATOR, pinned_identity_dh_key=bytes(31)),
    lambda: respond(replace(RESPONDER, signed_prekey_private_key=bytes(31)), INITIATOR),
    lambda: respond(replace(RESPONDER, one_time_prekey_private_key=bytes(33)), INITIATOR),
]


@pytest.mark.parametrize("call", WRONG_LENGTHS)
def test_wrong_length_is_a_value_error_not_a_named_result(
    call: Callable[[], object],
) -> None:
    with pytest.raises(ValueError) as error:
        call()

    assert not isinstance(error.value, CryptoError)
    assert bytes(31).hex() not in str(error.value)
