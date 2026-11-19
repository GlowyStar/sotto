import re
from collections.abc import Callable
from pathlib import Path

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

from sotto.crypto import identity
from sotto.crypto.identity import (
    BadBundleError,
    Bundle,
    CryptoError,
    IdentityKeyMismatchError,
    InvalidIdError,
    LoginRefusedError,
    OneTimePrekey,
    SignedPrekey,
    check_bundle,
    decode_user_id,
    derive_identity_key,
    derive_x25519_public_key,
    encode_user_id,
    identity_dh_string,
    login_string,
    pq_prekey_string,
    sign_identity_dh_key,
    sign_login,
    sign_signed_prekey,
    signed_prekey_string,
    verify_identity_dh_key,
    verify_login,
    verify_signed_prekey,
)

PROTOCOL = (Path(__file__).parent.parent.parent / "docs" / "protocol.md").read_text(
    encoding="utf-8"
)
DECODER_SECTION = PROTOCOL[PROTOCOL.index("### 3.3 ") : PROTOCOL.index("### 3.4 ")]
EXCLUDED_BY_STEP_4 = re.findall(r"^ +([0-9a-f]{64})$", DECODER_SECTION, re.MULTILINE)
SMALL_ORDER = [int.from_bytes(bytes.fromhex(y), "little") for y in EXCLUDED_BY_STEP_4]

FIELD_PRIME = 2**255 - 19
TOP_BIT = 1 << 255
LOWEST_BIT = 0x01
HIGHEST_BIT = 0x80
HEX_DIGITS = "0123456789abcdef"
FULLWIDTH_DIGIT_ONE = chr(0xFF11)
ARABIC_INDIC_DIGIT_ONE = chr(0x0661)
NAME_OUTSIDE_ASCII = chr(0xE9)
SIGNED_FIELD_NAMES = [
    "identity",
    "identity_dh_key",
    "identity_dh_signature",
    "signed_prekey",
    "signed_prekey_signature",
]

SEED = bytes(range(32))
IDENTITY_DH_KEY = derive_x25519_public_key(bytes([1]) * 32)
SIGNED_PREKEY_KEY = derive_x25519_public_key(bytes([2]) * 32)
NEXT_SIGNED_PREKEY_KEY = derive_x25519_public_key(bytes([3]) * 32)
OTHER_IDENTITY_DH_KEY = derive_x25519_public_key(bytes([4]) * 32)
CONTACT = derive_identity_key(SEED)
STRANGER = derive_identity_key(bytes([5]) * 32)
VALID_ID = CONTACT.hex()

NEUTRAL_POINT = (1).to_bytes(32, "little")
NON_CANONICAL_NEUTRAL_POINT = (FIELD_PRIME + 1).to_bytes(32, "little")
BASE_POINT = bytes.fromhex("58" + "66" * 31)
FORGED_SIGNATURES = [NEUTRAL_POINT + bytes(32), BASE_POINT + (1).to_bytes(32, "little")]


def id_of(y: int, top_bit: int) -> str:
    return (y | top_bit).to_bytes(32, "little").hex()


def with_changed_byte(value: bytes, index: int, mask: int) -> bytes:
    return value[:index] + bytes([value[index] ^ mask]) + value[index + 1 :]


def signed_fields_of(
    seed: bytes, identity_dh_key: bytes, signed_prekey: bytes
) -> dict[str, bytes]:
    return {
        "identity": derive_identity_key(seed),
        "identity_dh_key": identity_dh_key,
        "identity_dh_signature": sign_identity_dh_key(seed, identity_dh_key=identity_dh_key),
        "signed_prekey": signed_prekey,
        "signed_prekey_signature": sign_signed_prekey(seed, signed_prekey=signed_prekey),
    }


def bundle_of(
    fields: dict[str, bytes],
    signed_prekey_id: int = 1,
    one_time_prekey: OneTimePrekey | None = None,
) -> Bundle:
    return Bundle(
        identity=fields["identity"],
        identity_dh_key=fields["identity_dh_key"],
        identity_dh_signature=fields["identity_dh_signature"],
        signed_prekey=SignedPrekey(
            id=signed_prekey_id,
            key=fields["signed_prekey"],
            signature=fields["signed_prekey_signature"],
        ),
        one_time_prekey=one_time_prekey,
    )


VALID_FIELDS = signed_fields_of(SEED, IDENTITY_DH_KEY, SIGNED_PREKEY_KEY)
VALID_BUNDLE = bundle_of(VALID_FIELDS)

keys = st.binary(min_size=32, max_size=32)
server_names = st.text(st.characters(max_codepoint=127), min_size=1, max_size=255)
prekey_ids = st.integers(min_value=0, max_value=2**32 - 1)
one_time_prekeys = st.none() | st.builds(OneTimePrekey, id=prekey_ids, key=keys)
signed_fields = st.builds(signed_fields_of, keys, keys, keys)

ys_near_the_prime = st.integers(min_value=FIELD_PRIME - 64, max_value=TOP_BIT - 1)
ids_on_the_edge = st.builds(
    id_of, ys_near_the_prime | st.sampled_from(SMALL_ORDER), st.sampled_from([0, TOP_BIT])
)
hex_ids = st.text(HEX_DIGITS, min_size=64, max_size=64)
affixes = st.text(" \n0xg", max_size=2)
user_ids = (
    st.text(max_size=70)
    | hex_ids
    | st.text(HEX_DIGITS + "ABCDEF", min_size=64, max_size=64)
    | st.text(HEX_DIGITS + "ABCDEFg x:\n", min_size=60, max_size=68)
    | st.tuples(affixes, hex_ids, affixes).map("".join)
    | ids_on_the_edge
)


def decoded_by_the_four_steps(text: str) -> bytes | None:
    """Section 3.3 in its integer wording; the core compares bytes."""
    breaks_step_1 = len(text) != 64 or not set(text) <= set(HEX_DIGITS)
    if breaks_step_1:
        return None

    key = bytes.fromhex(text)
    y = int.from_bytes(key, "little") & (TOP_BIT - 1)
    breaks_step_3 = y >= FIELD_PRIME
    breaks_step_4 = y in SMALL_ORDER
    if breaks_step_3 or breaks_step_4:
        return None
    return key


@given(user_ids)
@example(id_of(FIELD_PRIME - 2, 0))
@example(id_of(FIELD_PRIME, 0))
@example(id_of(FIELD_PRIME, TOP_BIT))
@example(id_of(FIELD_PRIME + 1, 0))
@example(id_of(TOP_BIT - 1, TOP_BIT))
@example(VALID_ID + "\n")
@example("A" + VALID_ID[1:])
@example("g" + VALID_ID[1:])
@example(" " + VALID_ID[1:])
@example(":" + VALID_ID[1:])
@example(FULLWIDTH_DIGIT_ONE + VALID_ID[1:])
@example(ARABIC_INDIC_DIGIT_ONE + VALID_ID[1:])
def test_decoder_accepts_exactly_what_the_four_steps_allow(text: str) -> None:
    expected = decoded_by_the_four_steps(text)

    if expected is None:
        with pytest.raises(InvalidIdError):
            decode_user_id(text)
    else:
        assert decode_user_id(text) == expected
        assert encode_user_id(expected) == text


@pytest.mark.parametrize("index", range(1, 32))
def test_decoder_accepts_the_prime_with_one_byte_lowered(index: int) -> None:
    user_id = id_of(FIELD_PRIME - (1 << (8 * index)), 0)

    assert decode_user_id(user_id) == bytes.fromhex(user_id)


def test_small_order_list_is_the_list_of_step_4() -> None:
    assert {bytes.fromhex(y) for y in EXCLUDED_BY_STEP_4} == identity.SMALL_ORDER


@given(server_names, keys, keys, keys, keys, keys, keys)
@example("a" * 5, bytes(32), bytes(32), bytes(32), bytes(32), bytes(32), bytes(32))
@example("a" * 7, bytes(32), bytes(32), bytes(32), bytes(32), bytes(32), bytes(32))
def test_signed_strings_of_two_purposes_never_coincide(
    server_name: str,
    server_nonce: bytes,
    client_nonce: bytes,
    identity_key: bytes,
    identity_dh_key: bytes,
    other_identity_key: bytes,
    signed_prekey: bytes,
) -> None:
    strings = [
        login_string(
            server_name=server_name, server_nonce=server_nonce, client_nonce=client_nonce
        ),
        identity_dh_string(identity_key=identity_key, identity_dh_key=identity_dh_key),
        signed_prekey_string(identity_key=other_identity_key, signed_prekey=signed_prekey),
        pq_prekey_string(identity_key=identity_key, pq_prekey=signed_prekey * 37),
    ]
    prefixes = [string.split(b"\x00", 1)[0] for string in strings]

    assert len(set(strings)) == 4
    assert prefixes == [
        b"sotto/1 login",
        b"sotto/1 identity-dh",
        b"sotto/1 signed-prekey",
        b"sotto/1 ml-kem-768-prekey",
    ]
    assert strings[0].endswith(server_name.encode("ascii") + server_nonce + client_nonce)


@given(keys, server_names, keys, keys, keys, keys)
def test_signatures_made_by_the_core_verify(
    seed: bytes,
    server_name: str,
    server_nonce: bytes,
    client_nonce: bytes,
    identity_dh_private_key: bytes,
    signed_prekey_private_key: bytes,
) -> None:
    identity_key = derive_identity_key(seed)
    identity_dh_key = derive_x25519_public_key(identity_dh_private_key)
    signed_prekey = derive_x25519_public_key(signed_prekey_private_key)

    login = sign_login(
        seed, server_name=server_name, server_nonce=server_nonce, client_nonce=client_nonce
    )
    identity_dh = sign_identity_dh_key(seed, identity_dh_key=identity_dh_key)
    prekey = sign_signed_prekey(seed, signed_prekey=signed_prekey)

    verify_login(
        identity_key,
        signature=login,
        server_name=server_name,
        server_nonce=server_nonce,
        client_nonce=client_nonce,
    )
    verify_identity_dh_key(
        identity_key, identity_dh_key=identity_dh_key, signature=identity_dh
    )
    verify_signed_prekey(identity_key, signed_prekey=signed_prekey, signature=prekey)


@given(signed_fields, st.sampled_from(SIGNED_FIELD_NAMES), st.data())
def test_changed_signed_field_fails_the_bundle_check(
    fields: dict[str, bytes], field: str, data: st.DataObject
) -> None:
    value = fields[field]
    index = data.draw(st.integers(min_value=0, max_value=len(value) - 1))
    mask = data.draw(st.integers(min_value=1, max_value=255))
    pinned = data.draw(st.sampled_from([None, fields["identity_dh_key"]]))
    changed = bundle_of(
        {**fields, field: with_changed_byte(value, index, mask)},
        one_time_prekey=data.draw(one_time_prekeys),
    )

    with pytest.raises(BadBundleError):
        check_bundle(
            changed, contact_identity_key=fields["identity"], pinned_identity_dh_key=pinned
        )


@given(signed_fields, prekey_ids, one_time_prekeys)
def test_changed_unsigned_field_passes_the_bundle_check(
    fields: dict[str, bytes], signed_prekey_id: int, one_time_prekey: OneTimePrekey | None
) -> None:
    bundle = bundle_of(fields, signed_prekey_id, one_time_prekey)

    check_bundle(
        bundle,
        contact_identity_key=fields["identity"],
        pinned_identity_dh_key=fields["identity_dh_key"],
    )


def test_pinned_x25519_identity_key_refuses_another_one() -> None:
    rotated = bundle_of(signed_fields_of(SEED, IDENTITY_DH_KEY, NEXT_SIGNED_PREKEY_KEY), 2)
    replaced = bundle_of(signed_fields_of(SEED, OTHER_IDENTITY_DH_KEY, SIGNED_PREKEY_KEY))

    check_bundle(VALID_BUNDLE, contact_identity_key=CONTACT, pinned_identity_dh_key=None)
    pinned = VALID_BUNDLE.identity_dh_key

    check_bundle(rotated, contact_identity_key=CONTACT, pinned_identity_dh_key=pinned)
    with pytest.raises(IdentityKeyMismatchError):
        check_bundle(replaced, contact_identity_key=CONTACT, pinned_identity_dh_key=pinned)
    with pytest.raises(IdentityKeyMismatchError):
        check_bundle(
            VALID_BUNDLE, contact_identity_key=CONTACT, pinned_identity_dh_key=bytes(32)
        )


@pytest.mark.parametrize("mask", [LOWEST_BIT, HIGHEST_BIT])
@pytest.mark.parametrize("index", range(32))
def test_bundle_checks_compare_keys_in_all_their_bytes(index: int, mask: int) -> None:
    other_contact = with_changed_byte(CONTACT, index, mask)
    other_pin = with_changed_byte(IDENTITY_DH_KEY, index, mask)

    with pytest.raises(BadBundleError, match="contact id"):
        check_bundle(
            VALID_BUNDLE, contact_identity_key=other_contact, pinned_identity_dh_key=None
        )
    with pytest.raises(IdentityKeyMismatchError):
        check_bundle(
            VALID_BUNDLE, contact_identity_key=CONTACT, pinned_identity_dh_key=other_pin
        )


def test_bundle_checks_stop_at_the_first_failure() -> None:
    bad_identity_dh_signature = bundle_of({**VALID_FIELDS, "identity_dh_signature": bytes(64)})
    bad_signed_prekey_signature = bundle_of(
        {**VALID_FIELDS, "signed_prekey_signature": bytes(64)}
    )
    other_pin = OTHER_IDENTITY_DH_KEY

    with pytest.raises(BadBundleError, match="contact id"):
        check_bundle(
            bad_identity_dh_signature,
            contact_identity_key=STRANGER,
            pinned_identity_dh_key=other_pin,
        )
    with pytest.raises(BadBundleError, match="X25519 identity key does not verify"):
        check_bundle(
            bad_identity_dh_signature,
            contact_identity_key=CONTACT,
            pinned_identity_dh_key=other_pin,
        )
    with pytest.raises(IdentityKeyMismatchError):
        check_bundle(
            bad_signed_prekey_signature,
            contact_identity_key=CONTACT,
            pinned_identity_dh_key=other_pin,
        )
    with pytest.raises(BadBundleError, match="signed prekey does not verify"):
        check_bundle(
            bad_signed_prekey_signature,
            contact_identity_key=CONTACT,
            pinned_identity_dh_key=None,
        )


def test_signature_bytes_are_not_an_identifier() -> None:
    signed_again = bundle_of(
        {
            **VALID_FIELDS,
            "identity_dh_signature": bytes(64),
            "signed_prekey_signature": bytes(64),
        }
    )
    with_another_key = bundle_of({**VALID_FIELDS, "identity_dh_key": OTHER_IDENTITY_DH_KEY})

    assert signed_again == VALID_BUNDLE
    assert hash(signed_again) == hash(VALID_BUNDLE)
    assert with_another_key != VALID_BUNDLE


@pytest.mark.parametrize("forged_signature", FORGED_SIGNATURES, ids=["neutral-0", "base-1"])
@pytest.mark.parametrize(
    "excluded_key",
    [
        NEUTRAL_POINT,
        NON_CANONICAL_NEUTRAL_POINT,
        bytes.fromhex(id_of(1, TOP_BIT)),
        bytes.fromhex(id_of(FIELD_PRIME + 1, TOP_BIT)),
    ],
    ids=["small-order", "non-canonical", "small-order-top-bit", "non-canonical-top-bit"],
)
def test_excluded_key_verifies_nothing(excluded_key: bytes, forged_signature: bytes) -> None:
    forged = bundle_of(
        {
            "identity": excluded_key,
            "identity_dh_key": IDENTITY_DH_KEY,
            "identity_dh_signature": forged_signature,
            "signed_prekey": SIGNED_PREKEY_KEY,
            "signed_prekey_signature": forged_signature,
        }
    )

    with pytest.raises(BadBundleError):
        verify_identity_dh_key(
            excluded_key, signature=forged_signature, identity_dh_key=IDENTITY_DH_KEY
        )
    with pytest.raises(BadBundleError):
        verify_signed_prekey(
            excluded_key, signature=forged_signature, signed_prekey=SIGNED_PREKEY_KEY
        )
    with pytest.raises(BadBundleError):
        check_bundle(forged, contact_identity_key=excluded_key, pinned_identity_dh_key=None)
    with pytest.raises(LoginRefusedError):
        verify_login(
            excluded_key,
            signature=forged_signature,
            server_name="a",
            server_nonce=bytes(32),
            client_nonce=bytes(32),
        )


def test_key_the_library_refuses_to_load_counts_as_a_failed_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RefusingLibrary:
        @staticmethod
        def from_public_bytes(data: bytes) -> None:
            raise ValueError("not a point of the curve")

    login = sign_login(SEED, server_name="a", server_nonce=bytes(32), client_nonce=bytes(32))
    monkeypatch.setattr(identity, "Ed25519PublicKey", RefusingLibrary)

    with pytest.raises(BadBundleError):
        check_bundle(VALID_BUNDLE, contact_identity_key=CONTACT, pinned_identity_dh_key=None)
    with pytest.raises(LoginRefusedError):
        verify_login(
            CONTACT,
            signature=login,
            server_name="a",
            server_nonce=bytes(32),
            client_nonce=bytes(32),
        )


WRONG_LENGTHS: list[Callable[[], object]] = [
    lambda: login_string(server_name="", server_nonce=bytes(32), client_nonce=bytes(32)),
    lambda: login_string(
        server_name="a" * 256, server_nonce=bytes(32), client_nonce=bytes(32)
    ),
    lambda: login_string(
        server_name="a" + NAME_OUTSIDE_ASCII, server_nonce=bytes(32), client_nonce=bytes(32)
    ),
    lambda: login_string(server_name="a", server_nonce=bytes(31), client_nonce=bytes(32)),
    lambda: login_string(server_name="a", server_nonce=bytes(32), client_nonce=bytes(33)),
    lambda: identity_dh_string(identity_key=bytes(31), identity_dh_key=bytes(32)),
    lambda: identity_dh_string(identity_key=bytes(32), identity_dh_key=bytes(33)),
    lambda: signed_prekey_string(identity_key=bytes(33), signed_prekey=bytes(32)),
    lambda: signed_prekey_string(identity_key=bytes(32), signed_prekey=bytes(31)),
    lambda: encode_user_id(bytes(31)),
    lambda: derive_identity_key(bytes(31)),
    lambda: derive_identity_key(bytes(33)),
    lambda: sign_login(
        bytes(33), server_name="a", server_nonce=bytes(32), client_nonce=bytes(32)
    ),
    lambda: derive_x25519_public_key(bytes(33)),
    lambda: verify_login(
        bytes(31),
        signature=bytes(64),
        server_name="a",
        server_nonce=bytes(32),
        client_nonce=bytes(32),
    ),
    lambda: verify_login(
        CONTACT,
        signature=bytes(63),
        server_name="a",
        server_nonce=bytes(32),
        client_nonce=bytes(32),
    ),
    lambda: verify_login(
        CONTACT,
        signature=bytes(64),
        server_name="a",
        server_nonce=bytes(31),
        client_nonce=bytes(32),
    ),
    lambda: verify_identity_dh_key(
        CONTACT, signature=bytes(65), identity_dh_key=IDENTITY_DH_KEY
    ),
    lambda: verify_signed_prekey(
        CONTACT, signature=bytes(63), signed_prekey=SIGNED_PREKEY_KEY
    ),
    lambda: check_bundle(
        VALID_BUNDLE, contact_identity_key=bytes(31), pinned_identity_dh_key=None
    ),
    lambda: check_bundle(
        VALID_BUNDLE, contact_identity_key=CONTACT, pinned_identity_dh_key=b""
    ),
]


@pytest.mark.parametrize("call", WRONG_LENGTHS)
def test_wrong_length_is_a_value_error_not_a_named_result(
    call: Callable[[], object],
) -> None:
    with pytest.raises(ValueError) as error:
        call()

    assert not isinstance(error.value, CryptoError)
    assert not issubclass(CryptoError, ValueError)


def test_hypothesis_profile_is_randomized_with_a_blob_and_no_deadline() -> None:
    profile = settings()

    assert profile.derandomize is False
    assert profile.print_blob is True
    assert profile.deadline is None
