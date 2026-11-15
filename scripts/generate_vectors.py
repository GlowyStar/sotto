"""Writes the shared test vectors of docs/protocol.md, section 15, from fixed inputs.

Run by hand after a change of a layout or of a vector:

    uv run python scripts/generate_vectors.py

The written file is committed with that change. From the first tag that holds a vector
file, a vector is only ever added, at the end of its list (section 15.4).
"""

import json
from pathlib import Path

from sotto.crypto.identity import (
    Bundle,
    OneTimePrekey,
    SignedPrekey,
    derive_identity_key,
    derive_x25519_public_key,
    encode_user_id,
    identity_dh_string,
    login_string,
    sign_identity_dh_key,
    sign_login,
    sign_signed_prekey,
    signed_prekey_string,
)
from sotto.crypto.x3dh import KeyAgreement, dh, initiate, respond

type Fields = dict[str, str | int]
type Vector = dict[str, str | Fields]

VECTORS = Path(__file__).parent.parent / "vectors"
SCHEMA = 1

RFC_8032_TEST_1_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
RFC_7748_ALICE_PRIVATE_KEY = bytes.fromhex(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
)

ALICE_SEED = bytes([0x01]) * 32
MALLORY_SEED = bytes([0x02]) * 32
ALICE = derive_identity_key(ALICE_SEED)
MALLORY = derive_identity_key(MALLORY_SEED)

ALICE_IDENTITY_DH_PRIVATE_KEY = bytes([0x11]) * 32
ALICE_IDENTITY_DH = derive_x25519_public_key(ALICE_IDENTITY_DH_PRIVATE_KEY)
ALICE_SIGNED_PREKEY_PRIVATE_KEY = bytes([0x12]) * 32
ALICE_SIGNED_PREKEY = derive_x25519_public_key(ALICE_SIGNED_PREKEY_PRIVATE_KEY)
ALICE_ONE_TIME_PREKEY_PRIVATE_KEY = bytes([0x13]) * 32
ALICE_ONE_TIME_PREKEY = derive_x25519_public_key(ALICE_ONE_TIME_PREKEY_PRIVATE_KEY)
ALICE_OTHER_IDENTITY_DH = derive_x25519_public_key(bytes([0x14]) * 32)
ALICE_NEXT_SIGNED_PREKEY = derive_x25519_public_key(bytes([0x15]) * 32)
ALICE_OTHER_ONE_TIME_PREKEY = derive_x25519_public_key(bytes([0x16]) * 32)
MALLORY_IDENTITY_DH = derive_x25519_public_key(bytes([0x21]) * 32)
MALLORY_SIGNED_PREKEY = derive_x25519_public_key(bytes([0x22]) * 32)

BOB_SEED = bytes([0x03]) * 32
BOB = derive_identity_key(BOB_SEED)
BOB_IDENTITY_DH_PRIVATE_KEY = bytes([0x31]) * 32
BOB_IDENTITY_DH = derive_x25519_public_key(BOB_IDENTITY_DH_PRIVATE_KEY)
EPHEMERAL_PRIVATE_KEY = bytes([0x32]) * 32
EPHEMERAL_PRIVATE_KEY_AFTER_A_REPLACEMENT = bytes([0x33]) * 32
EPHEMERAL_PRIVATE_KEY_FOR_MALLORY = bytes([0x34]) * 32

EXAMPLE_NAME = "127.0.0.1"
HOST_NAME = "relay.example.org"
SERVER_NONCE = bytes(range(0x00, 0x20))
CLIENT_NONCE = bytes(range(0x20, 0x40))
OTHER_SERVER_NONCE = bytes(range(0x40, 0x60))
OTHER_CLIENT_NONCE = bytes(range(0x60, 0x80))

TOP_BIT = 0x80
FULLWIDTH_OFFSET = 0xFEE0
ARABIC_INDIC_DIGIT_ONE = chr(0x0661)

FIELD_PRIME = "ed" + "ff" * 30 + "7f"
FIELD_PRIME_PLUS_1 = "ee" + "ff" * 30 + "7f"
FIELD_PRIME_MINUS_2 = "eb" + "ff" * 30 + "7f"
LARGEST_Y = "ff" * 31 + "7f"
SMALL_ORDER = {
    "4": "0000000000000000000000000000000000000000000000000000000000000000",
    "1": "0100000000000000000000000000000000000000000000000000000000000000",
    "2": "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "8-a": "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "8-b": "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
}
NEUTRAL_POINT = SMALL_ORDER["1"]
NOT_A_POINT = "02" + "00" * 31
FORGED_SIGNATURE = bytes.fromhex(NEUTRAL_POINT) + bytes(32)

X25519_PRIME = 2**255 - 19
# The u-coordinates of https://cr.yp.to/ecdh.html#validate: 0 has order 2, the other one
# order 8.
X25519_ORDER_2 = bytes(32)
X25519_ORDER_8 = bytes.fromhex(
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"
)
KEY_MATERIAL_PREFIX = b"\xff" * 32


def passes(
    name: str,
    operation: str,
    inputs: Fields,
    outputs: Fields | None = None,
    *,
    intermediates: Fields | None = None,
) -> Vector:
    return {
        "name": name,
        "operation": operation,
        "inputs": inputs,
        "intermediates": intermediates or {},
        "outputs": outputs or {},
    }


def fails(
    name: str,
    operation: str,
    inputs: Fields,
    error: str,
    *,
    intermediates: Fields | None = None,
) -> Vector:
    return {
        "name": name,
        "operation": operation,
        "inputs": inputs,
        "intermediates": intermediates or {},
        "error": error,
    }


def with_top_bit(encoding: str) -> str:
    key = bytes.fromhex(encoding)
    return (key[:-1] + bytes([key[-1] | TOP_BIT])).hex()


def with_flipped_s(signature: bytes) -> bytes:
    """Changes the lowest bit of S, which no verifier accepts, cofactored or not."""
    return signature[:32] + bytes([signature[32] ^ 0x01]) + signature[33:]


def key_vectors() -> list[Vector]:
    seeds = {
        "rfc-8032-test-1": RFC_8032_TEST_1_SEED,
        "alice": ALICE_SEED,
        "mallory": MALLORY_SEED,
    }
    private_keys = {
        "rfc-7748-alice": RFC_7748_ALICE_PRIVATE_KEY,
        "repeated-byte": ALICE_IDENTITY_DH_PRIVATE_KEY,
    }

    vectors = []
    for case, seed in seeds.items():
        identity_key = derive_identity_key(seed)
        outputs: Fields = {
            "identity_key": identity_key.hex(),
            "user_id": encode_user_id(identity_key),
        }
        vectors.append(
            passes(f"identity-key-{case}", "identity-key", {"seed": seed.hex()}, outputs)
        )
    for case, private_key in private_keys.items():
        public_key = derive_x25519_public_key(private_key)
        vectors.append(
            passes(
                f"x25519-public-key-{case}",
                "x25519-public-key",
                {"private_key": private_key.hex()},
                {"public_key": public_key.hex()},
            )
        )
    return vectors


def decode_vectors() -> list[Vector]:
    rfc = encode_user_id(derive_identity_key(RFC_8032_TEST_1_SEED))
    accepted = {
        "rfc-8032-test-1": rfc,
        "top-bit-set": encode_user_id(MALLORY),
        "not-a-point": NOT_A_POINT,
        "y-is-p-minus-2": FIELD_PRIME_MINUS_2,
        "y-is-p-minus-2-top-bit-set": with_top_bit(FIELD_PRIME_MINUS_2),
        "byte-1-below-the-prime": "ff" + "fe" + "ff" * 29 + "7f",
        "one-middle-byte-below-the-prime": "ff" * 15 + "fe" + "ff" * 15 + "7f",
        "byte-30-below-the-prime": "ff" * 30 + "fe" + "7f",
        "last-byte-below-the-prime": "ff" * 31 + "7e",
        "last-byte-below-the-prime-top-bit-set": "ff" * 31 + "fe",
    }
    refused = {
        "empty": "",
        "63-characters": rfc[:63],
        "65-characters": rfc + "0",
        "uppercase": rfc.upper(),
        "one-uppercase-letter": rfc.replace("d", "D", 1),
        "0x-prefix": "0x" + rfc,
        "0x-prefix-in-64-characters": "0x" + rfc[:62],
        "leading-space": " " + rfc,
        "trailing-space": rfc + " ",
        "trailing-newline": rfc + "\n",
        "two-spaces-in-64-characters": rfc[:30] + "  " + rfc[32:],
        "colons": ":".join(rfc[index : index + 2] for index in range(0, 64, 2)),
        "letter-g": rfc[:63] + "g",
        "fullwidth-digits": "".join(chr(ord(digit) + FULLWIDTH_OFFSET) for digit in rfc),
        "arabic-indic-digit": rfc.replace("1", ARABIC_INDIC_DIGIT_ONE, 1),
        "field-prime": FIELD_PRIME,
        "field-prime-top-bit-set": with_top_bit(FIELD_PRIME),
        "field-prime-plus-1": FIELD_PRIME_PLUS_1,
        "largest-y": LARGEST_Y,
        "largest-y-top-bit-set": with_top_bit(LARGEST_Y),
    }
    for order, encoding in SMALL_ORDER.items():
        refused[f"small-order-{order}"] = encoding
        refused[f"small-order-{order}-top-bit-set"] = with_top_bit(encoding)

    vectors = []
    for case, user_id in accepted.items():
        inputs: Fields = {"user_id": user_id}
        outputs: Fields = {"identity_key": user_id}
        vectors.append(passes(f"decode-user-id-{case}", "decode-user-id", inputs, outputs))
    for case, user_id in refused.items():
        inputs = {"user_id": user_id}
        vectors.append(fails(f"decode-user-id-{case}", "decode-user-id", inputs, "INVALID_ID"))
    return vectors


def login_vector(
    case: str,
    identity_key: bytes,
    signature: bytes,
    server_name: str = HOST_NAME,
    *,
    error: str | None = None,
) -> Vector:
    name = f"verify-login-{case}"
    inputs: Fields = {
        "identity_key": identity_key.hex(),
        "client_nonce": CLIENT_NONCE.hex(),
        "signature": signature.hex(),
        "server_name": server_name,
        "server_nonce": SERVER_NONCE.hex(),
    }
    signed_string = login_string(
        server_name=server_name, server_nonce=SERVER_NONCE, client_nonce=CLIENT_NONCE
    )
    intermediates: Fields = {"login_string": signed_string.hex()}

    if error is None:
        return passes(name, "verify-login", inputs, intermediates=intermediates)
    return fails(name, "verify-login", inputs, error, intermediates=intermediates)


def signed_login(
    seed: bytes,
    server_name: str = HOST_NAME,
    server_nonce: bytes = SERVER_NONCE,
    client_nonce: bytes = CLIENT_NONCE,
) -> bytes:
    return sign_login(
        seed, server_name=server_name, server_nonce=server_nonce, client_nonce=client_nonce
    )


def login_vectors() -> list[Vector]:
    rfc = derive_identity_key(RFC_8032_TEST_1_SEED)
    valid = signed_login(ALICE_SEED)
    refused = {
        "flipped-signature-bit": (ALICE, with_flipped_s(valid)),
        "signed-for-another-server-name": (
            ALICE,
            signed_login(ALICE_SEED, "other.example.org"),
        ),
        "signed-for-another-server-nonce": (
            ALICE,
            signed_login(ALICE_SEED, server_nonce=OTHER_SERVER_NONCE),
        ),
        "signed-for-another-client-nonce": (
            ALICE,
            signed_login(ALICE_SEED, client_nonce=OTHER_CLIENT_NONCE),
        ),
        "signed-by-another-identity": (ALICE, signed_login(MALLORY_SEED)),
        "small-order-key": (bytes.fromhex(NEUTRAL_POINT), FORGED_SIGNATURE),
        "non-canonical-key": (bytes.fromhex(FIELD_PRIME_PLUS_1), FORGED_SIGNATURE),
        "key-not-a-point": (bytes.fromhex(NOT_A_POINT), valid),
    }

    vectors = [
        login_vector(
            "example-of-section-4-2",
            rfc,
            signed_login(RFC_8032_TEST_1_SEED, EXAMPLE_NAME),
            EXAMPLE_NAME,
        ),
        login_vector("host-name", ALICE, valid),
        login_vector("name-of-1-byte", ALICE, signed_login(ALICE_SEED, "a"), "a"),
        login_vector(
            "name-of-255-bytes", ALICE, signed_login(ALICE_SEED, "a" * 255), "a" * 255
        ),
    ]
    for case, (identity_key, signature) in refused.items():
        vectors.append(login_vector(case, identity_key, signature, error="LOGIN_REFUSED"))
    return vectors


def valid_bundle(
    seed: bytes,
    identity_dh_key: bytes = ALICE_IDENTITY_DH,
    signed_prekey: bytes = ALICE_SIGNED_PREKEY,
) -> Fields:
    return {
        "identity": derive_identity_key(seed).hex(),
        "identity_dh_key": identity_dh_key.hex(),
        "identity_dh_signature": sign_identity_dh_key(
            seed, identity_dh_key=identity_dh_key
        ).hex(),
        "signed_prekey_id": 7,
        "signed_prekey_key": signed_prekey.hex(),
        "signed_prekey_signature": sign_signed_prekey(seed, signed_prekey=signed_prekey).hex(),
        "one_time_prekey_id": 41,
        "one_time_prekey_key": ALICE_ONE_TIME_PREKEY.hex(),
    }


def with_flipped_signature(bundle: Fields, field: str) -> Fields:
    signature = bytes.fromhex(str(bundle[field]))
    return bundle | {field: with_flipped_s(signature).hex()}


def bundle_vector(
    case: str,
    bundle: Fields,
    contact: bytes = ALICE,
    pinned: bytes | None = None,
    *,
    error: str | None = None,
) -> Vector:
    name = f"check-bundle-{case}"
    inputs: Fields = {"contact_id": contact.hex()}
    if pinned is not None:
        inputs["pinned_identity_dh_key"] = pinned.hex()
    inputs |= bundle

    identity = bytes.fromhex(str(bundle["identity"]))
    intermediates: Fields = {
        "identity_dh_string": identity_dh_string(
            identity_key=identity,
            identity_dh_key=bytes.fromhex(str(bundle["identity_dh_key"])),
        ).hex(),
        "signed_prekey_string": signed_prekey_string(
            identity_key=identity,
            signed_prekey=bytes.fromhex(str(bundle["signed_prekey_key"])),
        ).hex(),
    }

    if error is None:
        return passes(name, "check-bundle", inputs, intermediates=intermediates)
    return fails(name, "check-bundle", inputs, error, intermediates=intermediates)


def bundle_vectors() -> list[Vector]:
    good = valid_bundle(ALICE_SEED)
    without_one_time_prekey = dict(good)
    del without_one_time_prekey["one_time_prekey_id"]
    del without_one_time_prekey["one_time_prekey_key"]
    rotated = valid_bundle(ALICE_SEED, signed_prekey=ALICE_NEXT_SIGNED_PREKEY)
    replaced = valid_bundle(ALICE_SEED, identity_dh_key=ALICE_OTHER_IDENTITY_DH)
    of_mallory = valid_bundle(MALLORY_SEED, MALLORY_IDENTITY_DH, MALLORY_SIGNED_PREKEY)

    as_a_signed_prekey = sign_signed_prekey(ALICE_SEED, signed_prekey=ALICE_IDENTITY_DH).hex()
    as_an_identity_dh_key = sign_identity_dh_key(
        ALICE_SEED, identity_dh_key=ALICE_SIGNED_PREKEY
    ).hex()
    forged: Fields = {
        "identity_dh_signature": FORGED_SIGNATURE.hex(),
        "signed_prekey_signature": FORGED_SIGNATURE.hex(),
    }

    accepted = [
        bundle_vector("first-fetch", good),
        bundle_vector("without-a-one-time-prekey", without_one_time_prekey),
        bundle_vector("pinned-key", good, pinned=ALICE_IDENTITY_DH),
        bundle_vector(
            "pinned-key-and-a-new-signed-prekey",
            rotated | {"signed_prekey_id": 8},
            pinned=ALICE_IDENTITY_DH,
        ),
        bundle_vector(
            "another-one-time-prekey",
            good
            | {
                "one_time_prekey_id": 42,
                "one_time_prekey_key": ALICE_OTHER_ONE_TIME_PREKEY.hex(),
            },
        ),
        bundle_vector(
            "other-prekey-ids", good | {"signed_prekey_id": 0, "one_time_prekey_id": 2**32 - 1}
        ),
    ]
    refused = [
        bundle_vector("of-another-identity", of_mallory, error="BAD_BUNDLE"),
        bundle_vector(
            "flipped-identity-dh-signature-bit",
            with_flipped_signature(good, "identity_dh_signature"),
            error="BAD_BUNDLE",
        ),
        bundle_vector(
            "changed-identity-dh-key",
            good | {"identity_dh_key": ALICE_OTHER_IDENTITY_DH.hex()},
            error="BAD_BUNDLE",
        ),
        bundle_vector(
            "identity-dh-key-signed-by-another-identity",
            good
            | {
                "identity_dh_key": of_mallory["identity_dh_key"],
                "identity_dh_signature": of_mallory["identity_dh_signature"],
            },
            error="BAD_BUNDLE",
        ),
        bundle_vector(
            "identity-dh-signature-over-the-signed-prekey-string",
            good | {"identity_dh_signature": as_a_signed_prekey},
            error="BAD_BUNDLE",
        ),
        bundle_vector(
            "flipped-signed-prekey-signature-bit",
            with_flipped_signature(good, "signed_prekey_signature"),
            error="BAD_BUNDLE",
        ),
        bundle_vector(
            "changed-signed-prekey",
            good | {"signed_prekey_key": ALICE_NEXT_SIGNED_PREKEY.hex()},
            error="BAD_BUNDLE",
        ),
        bundle_vector(
            "signed-prekey-signed-by-another-identity",
            good
            | {
                "signed_prekey_key": of_mallory["signed_prekey_key"],
                "signed_prekey_signature": of_mallory["signed_prekey_signature"],
            },
            error="BAD_BUNDLE",
        ),
        bundle_vector(
            "signed-prekey-signature-over-the-identity-dh-string",
            good | {"signed_prekey_signature": as_an_identity_dh_key},
            error="BAD_BUNDLE",
        ),
        bundle_vector(
            "another-key-than-the-pinned-one",
            replaced,
            pinned=ALICE_IDENTITY_DH,
            error="IDENTITY_KEY_MISMATCH",
        ),
        bundle_vector(
            "wrong-identity-before-the-pin",
            of_mallory,
            pinned=ALICE_IDENTITY_DH,
            error="BAD_BUNDLE",
        ),
        bundle_vector(
            "bad-identity-dh-signature-before-the-pin",
            with_flipped_signature(replaced, "identity_dh_signature"),
            pinned=ALICE_IDENTITY_DH,
            error="BAD_BUNDLE",
        ),
        bundle_vector(
            "the-pin-before-a-bad-signed-prekey-signature",
            with_flipped_signature(replaced, "signed_prekey_signature"),
            pinned=ALICE_IDENTITY_DH,
            error="IDENTITY_KEY_MISMATCH",
        ),
        bundle_vector(
            "contact-id-of-small-order",
            good | forged | {"identity": NEUTRAL_POINT},
            contact=bytes.fromhex(NEUTRAL_POINT),
            error="INVALID_ID",
        ),
        bundle_vector(
            "contact-id-non-canonical",
            good | forged | {"identity": FIELD_PRIME_PLUS_1},
            contact=bytes.fromhex(FIELD_PRIME_PLUS_1),
            error="INVALID_ID",
        ),
        bundle_vector(
            "identity-not-a-point",
            good | {"identity": NOT_A_POINT},
            contact=bytes.fromhex(NOT_A_POINT),
            error="BAD_BUNDLE",
        ),
    ]
    return accepted + refused


def identity_vectors() -> list[Vector]:
    return key_vectors() + decode_vectors() + login_vectors() + bundle_vectors()


def bundle_of(fields: Fields) -> Bundle:
    one_time_prekey = None
    if "one_time_prekey_id" in fields:
        one_time_prekey = OneTimePrekey(
            id=int(fields["one_time_prekey_id"]),
            key=bytes.fromhex(str(fields["one_time_prekey_key"])),
        )

    return Bundle(
        identity=bytes.fromhex(str(fields["identity"])),
        identity_dh_key=bytes.fromhex(str(fields["identity_dh_key"])),
        identity_dh_signature=bytes.fromhex(str(fields["identity_dh_signature"])),
        signed_prekey=SignedPrekey(
            id=int(fields["signed_prekey_id"]),
            key=bytes.fromhex(str(fields["signed_prekey_key"])),
            signature=bytes.fromhex(str(fields["signed_prekey_signature"])),
        ),
        one_time_prekey=one_time_prekey,
    )


def with_inverse_u(public_key: bytes) -> bytes:
    """The key plus the point of order 2: the u-coordinate 1/u, the same X25519 output."""
    u = int.from_bytes(public_key, "little")
    return pow(u, -1, X25519_PRIME).to_bytes(32, "little")


def key_schedule(dh_outputs: list[bytes]) -> Fields:
    recorded: Fields = {
        f"dh{number}": output.hex() for number, output in enumerate(dh_outputs, 1)
    }
    recorded["input_key_material"] = (KEY_MATERIAL_PREFIX + b"".join(dh_outputs)).hex()
    return recorded


def outputs_of(agreement: KeyAgreement) -> Fields:
    return {
        "sk": agreement.shared_secret.hex(),
        "session_associated_data": agreement.associated_data.hex(),
    }


def initiate_vector(
    case: str,
    bundle: Fields,
    ephemeral_private_key: bytes = EPHEMERAL_PRIVATE_KEY,
    contact: bytes = ALICE,
    *,
    error: str | None = None,
) -> Vector:
    name = f"x3dh-initiate-{case}"
    inputs: Fields = {
        "identity_key": BOB.hex(),
        "identity_dh_private_key": BOB_IDENTITY_DH_PRIVATE_KEY.hex(),
        "ephemeral_private_key": ephemeral_private_key.hex(),
        "contact_id": contact.hex(),
    }
    inputs |= bundle

    fetched = bundle_of(bundle)
    intermediates: Fields = {
        "identity_dh_string": identity_dh_string(
            identity_key=fetched.identity, identity_dh_key=fetched.identity_dh_key
        ).hex(),
        "signed_prekey_string": signed_prekey_string(
            identity_key=fetched.identity, signed_prekey=fetched.signed_prekey.key
        ).hex(),
    }
    if error is not None:
        return fails(name, "x3dh-initiate", inputs, error, intermediates=intermediates)

    dh_outputs = [
        dh(BOB_IDENTITY_DH_PRIVATE_KEY, fetched.signed_prekey.key),
        dh(ephemeral_private_key, fetched.identity_dh_key),
        dh(ephemeral_private_key, fetched.signed_prekey.key),
    ]
    if fetched.one_time_prekey is not None:
        dh_outputs.append(dh(ephemeral_private_key, fetched.one_time_prekey.key))
    agreement = initiate(
        fetched,
        identity_key=BOB,
        identity_dh_private_key=BOB_IDENTITY_DH_PRIVATE_KEY,
        ephemeral_private_key=ephemeral_private_key,
        contact_identity_key=contact,
        pinned_identity_dh_key=None,
    )
    intermediates |= key_schedule(dh_outputs)
    return passes(
        name, "x3dh-initiate", inputs, outputs_of(agreement), intermediates=intermediates
    )


def respond_vector(
    case: str,
    ephemeral_key: bytes,
    one_time_prekey_private_key: bytes | None = ALICE_ONE_TIME_PREKEY_PRIVATE_KEY,
    *,
    error: str | None = None,
) -> Vector:
    name = f"x3dh-respond-{case}"
    signature = sign_identity_dh_key(BOB_SEED, identity_dh_key=BOB_IDENTITY_DH)
    inputs: Fields = {
        "identity_key": ALICE.hex(),
        "identity_dh_private_key": ALICE_IDENTITY_DH_PRIVATE_KEY.hex(),
        "signed_prekey_private_key": ALICE_SIGNED_PREKEY_PRIVATE_KEY.hex(),
    }
    if one_time_prekey_private_key is not None:
        inputs["one_time_prekey_private_key"] = one_time_prekey_private_key.hex()
    inputs |= {
        "sender": BOB.hex(),
        "identity_dh_key": BOB_IDENTITY_DH.hex(),
        "identity_dh_signature": signature.hex(),
        "ephemeral_key": ephemeral_key.hex(),
        "signed_prekey_id": 7,
    }
    if one_time_prekey_private_key is not None:
        inputs["one_time_prekey_id"] = 41

    intermediates: Fields = {
        "identity_dh_string": identity_dh_string(
            identity_key=BOB, identity_dh_key=BOB_IDENTITY_DH
        ).hex(),
    }
    if error is not None:
        return fails(name, "x3dh-respond", inputs, error, intermediates=intermediates)

    dh_outputs = [
        dh(ALICE_SIGNED_PREKEY_PRIVATE_KEY, BOB_IDENTITY_DH),
        dh(ALICE_IDENTITY_DH_PRIVATE_KEY, ephemeral_key),
        dh(ALICE_SIGNED_PREKEY_PRIVATE_KEY, ephemeral_key),
    ]
    if one_time_prekey_private_key is not None:
        dh_outputs.append(dh(one_time_prekey_private_key, ephemeral_key))
    agreement = respond(
        identity_key=ALICE,
        identity_dh_private_key=ALICE_IDENTITY_DH_PRIVATE_KEY,
        signed_prekey_private_key=ALICE_SIGNED_PREKEY_PRIVATE_KEY,
        one_time_prekey_private_key=one_time_prekey_private_key,
        sender_identity_key=BOB,
        sender_identity_dh_key=BOB_IDENTITY_DH,
        sender_identity_dh_signature=signature,
        ephemeral_key=ephemeral_key,
        pinned_identity_dh_key=None,
    )
    intermediates |= key_schedule(dh_outputs)
    return passes(
        name, "x3dh-respond", inputs, outputs_of(agreement), intermediates=intermediates
    )


def x3dh_vectors() -> list[Vector]:
    good = valid_bundle(ALICE_SEED)
    without_one_time_prekey = dict(good)
    del without_one_time_prekey["one_time_prekey_id"]
    del without_one_time_prekey["one_time_prekey_key"]
    replaced = good | {"one_time_prekey_key": ALICE_OTHER_ONE_TIME_PREKEY.hex()}
    under_the_signature_of_mallory = valid_bundle(MALLORY_SEED)
    of_small_order = good | {"one_time_prekey_key": X25519_ORDER_2.hex()}

    ephemeral_key = derive_x25519_public_key(EPHEMERAL_PRIVATE_KEY)
    after_a_replacement = derive_x25519_public_key(EPHEMERAL_PRIVATE_KEY_AFTER_A_REPLACEMENT)
    for_mallory = derive_x25519_public_key(EPHEMERAL_PRIVATE_KEY_FOR_MALLORY)

    return [
        initiate_vector("with-a-one-time-prekey", good),
        respond_vector("with-a-one-time-prekey", ephemeral_key),
        initiate_vector("without-a-one-time-prekey", without_one_time_prekey),
        respond_vector("without-a-one-time-prekey", ephemeral_key, None),
        initiate_vector(
            "replaced-one-time-prekey", replaced, EPHEMERAL_PRIVATE_KEY_AFTER_A_REPLACEMENT
        ),
        respond_vector("replaced-one-time-prekey", after_a_replacement),
        initiate_vector(
            "unknown-key-share",
            under_the_signature_of_mallory,
            EPHEMERAL_PRIVATE_KEY_FOR_MALLORY,
            contact=MALLORY,
        ),
        respond_vector("unknown-key-share", for_mallory),
        respond_vector(
            "ephemeral-key-top-bit-set", bytes.fromhex(with_top_bit(ephemeral_key.hex()))
        ),
        respond_vector("ephemeral-key-inverse", with_inverse_u(ephemeral_key)),
        initiate_vector("one-time-prekey-of-small-order", of_small_order, error="ZERO_DH"),
        respond_vector("ephemeral-key-of-small-order", X25519_ORDER_8, error="ZERO_DH"),
    ]


FILES = {"identity.json": identity_vectors, "x3dh.json": x3dh_vectors}


def main() -> None:
    for file_name, make_vectors in FILES.items():
        vectors = make_vectors()
        text = json.dumps({"schema": SCHEMA, "vectors": vectors}, indent=2) + "\n"

        (VECTORS / file_name).write_text(text, encoding="utf-8")
        print(f"{file_name}: {len(vectors)} vectors")


if __name__ == "__main__":
    main()
