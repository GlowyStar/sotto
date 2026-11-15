"""Writes the shared test vectors of docs/protocol.md, section 15, from fixed inputs.

Run by hand after a change of a layout or of a vector:

    uv run python scripts/generate_vectors.py

The written file is committed with that change. From the first tag that holds a vector
file, a vector is only ever added, at the end of its list (section 15.4).
"""

import json
from pathlib import Path

from sotto.crypto.identity import (
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
ALICE_SIGNED_PREKEY = derive_x25519_public_key(bytes([0x12]) * 32)
ALICE_ONE_TIME_PREKEY = derive_x25519_public_key(bytes([0x13]) * 32)
ALICE_OTHER_IDENTITY_DH = derive_x25519_public_key(bytes([0x14]) * 32)
ALICE_NEXT_SIGNED_PREKEY = derive_x25519_public_key(bytes([0x15]) * 32)
ALICE_OTHER_ONE_TIME_PREKEY = derive_x25519_public_key(bytes([0x16]) * 32)
MALLORY_IDENTITY_DH = derive_x25519_public_key(bytes([0x21]) * 32)
MALLORY_SIGNED_PREKEY = derive_x25519_public_key(bytes([0x22]) * 32)

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


def main() -> None:
    vectors = identity_vectors()
    text = json.dumps({"schema": SCHEMA, "vectors": vectors}, indent=2) + "\n"

    (VECTORS / "identity.json").write_text(text, encoding="utf-8")
    print(f"identity.json: {len(vectors)} vectors")


if __name__ == "__main__":
    main()
