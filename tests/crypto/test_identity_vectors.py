import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NotRequired, TypedDict

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sotto.crypto.identity import (
    Bundle,
    CryptoError,
    OneTimePrekey,
    SignedPrekey,
    check_bundle,
    decode_user_id,
    derive_identity_key,
    derive_x25519_public_key,
    encode_user_id,
    identity_dh_string,
    login_string,
    signed_prekey_string,
    verify_login,
)

type Fields = dict[str, Any]


class Vector(TypedDict):
    name: str
    operation: str
    inputs: Fields
    intermediates: dict[str, str]
    outputs: NotRequired[Fields]
    error: NotRequired[str]


@dataclass(frozen=True, slots=True, kw_only=True)
class Operation:
    inputs: frozenset[str]
    intermediates: frozenset[str]
    outputs: frozenset[str]
    errors: frozenset[str]


ROOT = Path(__file__).parent.parent.parent
PROTOCOL = (ROOT / "docs" / "protocol.md").read_text(encoding="utf-8")
VECTOR_FILE = (ROOT / "vectors" / "identity.json").read_text(encoding="utf-8")
DOCUMENT = json.loads(VECTOR_FILE)
VECTORS: list[Vector] = DOCUMENT["vectors"]
POSITIVE = [vector for vector in VECTORS if "outputs" in vector]
NEGATIVE = [vector for vector in VECTORS if "error" in vector]
WITH_SIGNED_STRINGS = [vector for vector in VECTORS if vector.get("intermediates")]

SCHEMA = 1
ALWAYS = {"name", "operation", "inputs", "intermediates"}
VECTOR_NAME = re.compile(r"[a-z0-9-]+")
LOCAL_RESULTS = {"INVALID_ID", "BAD_BUNDLE", "IDENTITY_KEY_MISMATCH", "LOGIN_REFUSED"}
TEXT_KEYS = {"user_id", "contact_id", "server_name"}
PREKEY_ID_KEYS = {"signed_prekey_id", "one_time_prekey_id"}
LARGEST_PREKEY_ID = 2**32 - 1
LOWERCASE_HEX = re.compile(r"(?:[0-9a-f]{2})*")

OPERATION_ROW = re.compile(r"^\| `([a-z0-9-]+)` \|(.*)\|$", re.MULTILINE)
KEY_IN_A_CELL = re.compile(r"`(\w+)`")
RESULT_IN_A_CELL = re.compile(r"[A-Z_]+")
EXAMPLE_KEY = re.compile(r"^(seed|identity key) +([0-9a-f]{64})$", re.MULTILINE)
EXAMPLE_FIELD = re.compile(r"^[0-9a-f]+$", re.MULTILINE)
LISTED_ENCODING = re.compile(r"^ +([0-9a-f]{64})$", re.MULTILINE)

PREFIX_IN_THE_SPEC = re.compile(r"ASCII `(sotto/1 [a-z-]+)`, hex `([0-9a-f]+)`")
PREFIXES = dict(PREFIX_IN_THE_SPEC.findall(PROTOCOL))
TERMINATOR = "00"
SIGNER_AND_SIGNATURE = {
    "login_string": ("identity_key", "signature"),
    "identity_dh_string": ("identity", "identity_dh_signature"),
    "signed_prekey_string": ("identity", "signed_prekey_signature"),
}


def name_of(vector: Vector) -> str:
    return vector["name"]


def section(number: str) -> str:
    start = PROTOCOL.index(f"\n### {number} ")
    end = PROTOCOL.index("\n##", start + 1)
    return PROTOCOL[start:end]


def bundle_of(inputs: Fields) -> Bundle:
    one_time_prekey = None
    if "one_time_prekey_id" in inputs:
        one_time_prekey = OneTimePrekey(
            id=inputs["one_time_prekey_id"], key=bytes.fromhex(inputs["one_time_prekey_key"])
        )

    return Bundle(
        identity=bytes.fromhex(inputs["identity"]),
        identity_dh_key=bytes.fromhex(inputs["identity_dh_key"]),
        identity_dh_signature=bytes.fromhex(inputs["identity_dh_signature"]),
        signed_prekey=SignedPrekey(
            id=inputs["signed_prekey_id"],
            key=bytes.fromhex(inputs["signed_prekey_key"]),
            signature=bytes.fromhex(inputs["signed_prekey_signature"]),
        ),
        one_time_prekey=one_time_prekey,
    )


def replay(vector: Vector) -> Fields:
    inputs = vector["inputs"]
    match vector["operation"]:
        case "identity-key":
            identity_key = derive_identity_key(bytes.fromhex(inputs["seed"]))
            return {
                "identity_key": identity_key.hex(),
                "user_id": encode_user_id(identity_key),
            }
        case "x25519-public-key":
            public_key = derive_x25519_public_key(bytes.fromhex(inputs["private_key"]))
            return {"public_key": public_key.hex()}
        case "decode-user-id":
            return {"identity_key": decode_user_id(inputs["user_id"]).hex()}
        case "verify-login":
            verify_login(
                bytes.fromhex(inputs["identity_key"]),
                signature=bytes.fromhex(inputs["signature"]),
                server_name=inputs["server_name"],
                server_nonce=bytes.fromhex(inputs["server_nonce"]),
                client_nonce=bytes.fromhex(inputs["client_nonce"]),
            )
            return {}
        case "check-bundle":
            pinned = inputs.get("pinned_identity_dh_key")
            check_bundle(
                bundle_of(inputs),
                contact_identity_key=decode_user_id(inputs["contact_id"]),
                pinned_identity_dh_key=None if pinned is None else bytes.fromhex(pinned),
            )
            return {}
        case operation:
            raise NotImplementedError(f"{vector['name']}: no operation {operation!r}")


def strings_of_the_builders(vector: Vector) -> dict[str, str]:
    inputs = vector["inputs"]
    match vector["operation"]:
        case "verify-login":
            signed_string = login_string(
                server_name=inputs["server_name"],
                server_nonce=bytes.fromhex(inputs["server_nonce"]),
                client_nonce=bytes.fromhex(inputs["client_nonce"]),
            )
            return {"login_string": signed_string.hex()}
        case "check-bundle":
            identity = bytes.fromhex(inputs["identity"])
            identity_dh_key = bytes.fromhex(inputs["identity_dh_key"])
            signed_prekey = bytes.fromhex(inputs["signed_prekey_key"])
            return {
                "identity_dh_string": identity_dh_string(
                    identity_key=identity, identity_dh_key=identity_dh_key
                ).hex(),
                "signed_prekey_string": signed_prekey_string(
                    identity_key=identity, signed_prekey=signed_prekey
                ).hex(),
            }
        case operation:
            raise NotImplementedError(f"{vector['name']}: no signed string of {operation!r}")


def strings_by_hand(vector: Vector) -> dict[str, str]:
    inputs = vector["inputs"]
    match vector["operation"]:
        case "verify-login":
            name = inputs["server_name"].encode("ascii")
            name_length = f"{len(name):02x}"
            nonces = inputs["server_nonce"] + inputs["client_nonce"]
            prefix = PREFIXES["sotto/1 login"] + TERMINATOR
            return {"login_string": prefix + name_length + name.hex() + nonces}
        case "check-bundle":
            identity_dh = PREFIXES["sotto/1 identity-dh"] + TERMINATOR + inputs["identity"]
            signed_prekey = PREFIXES["sotto/1 signed-prekey"] + TERMINATOR + inputs["identity"]
            return {
                "identity_dh_string": identity_dh + inputs["identity_dh_key"],
                "signed_prekey_string": signed_prekey + inputs["signed_prekey_key"],
            }
        case operation:
            raise NotImplementedError(f"{vector['name']}: no signed string of {operation!r}")


def operations_of_the_spec() -> dict[str, Operation]:
    operations = {}
    for name, cells in OPERATION_ROW.findall(section("15.5")):
        _rule, inputs, intermediates, outputs, errors = cells.split("|")
        operations[name] = Operation(
            inputs=frozenset(KEY_IN_A_CELL.findall(inputs)),
            intermediates=frozenset(KEY_IN_A_CELL.findall(intermediates)),
            outputs=frozenset(KEY_IN_A_CELL.findall(outputs)),
            errors=frozenset(RESULT_IN_A_CELL.findall(errors)),
        )
    return operations


def has_the_type_of_its_key(key: str, value: object) -> bool:
    if key in TEXT_KEYS:
        return type(value) is str
    if key in PREKEY_ID_KEYS:
        return type(value) is int and 0 <= value <= LARGEST_PREKEY_ID
    return type(value) is str and LOWERCASE_HEX.fullmatch(value) is not None


def test_vector_file_follows_the_schema() -> None:
    names = [vector["name"] for vector in VECTORS]

    assert VECTOR_FILE.isascii()
    assert DOCUMENT.keys() == {"schema", "vectors"}
    assert DOCUMENT["schema"] == SCHEMA
    assert len(set(names)) == len(names)
    for vector in VECTORS:
        assert VECTOR_NAME.fullmatch(vector["name"])
        assert vector.keys() in (ALWAYS | {"outputs"}, ALWAYS | {"error"}), vector["name"]
    assert {vector["error"] for vector in NEGATIVE} <= LOCAL_RESULTS


def test_vector_values_are_text_numbers_and_lowercase_hex() -> None:
    for vector in VECTORS:
        fields = vector["inputs"] | vector["intermediates"] | vector.get("outputs", {})
        for key, value in fields.items():
            assert has_the_type_of_its_key(key, value), f"{vector['name']}: {key}"


def test_vectors_use_the_operations_and_keys_of_the_document() -> None:
    operations = operations_of_the_spec()

    assert operations.keys() == {vector["operation"] for vector in VECTORS}
    for vector in VECTORS:
        operation = operations[vector["operation"]]
        assert vector["intermediates"].keys() == operation.intermediates, vector["name"]
        if "outputs" in vector:
            assert vector["outputs"].keys() == operation.outputs, vector["name"]
    for name, operation in operations.items():
        vectors = [vector for vector in VECTORS if vector["operation"] == name]
        inputs = {key for vector in vectors for key in vector["inputs"]}
        errors = {vector["error"] for vector in vectors if "error" in vector}
        assert inputs == operation.inputs, name
        assert errors == operation.errors, name


@pytest.mark.parametrize("vector", POSITIVE, ids=name_of)
def test_positive_vectors_replay_byte_for_byte(vector: Vector) -> None:
    assert replay(vector) == vector["outputs"]


@pytest.mark.parametrize("vector", NEGATIVE, ids=name_of)
def test_negative_vectors_raise_their_named_error(vector: Vector) -> None:
    with pytest.raises(CryptoError) as refusal:
        replay(vector)

    assert refusal.value.result == vector["error"]


@pytest.mark.parametrize("vector", WITH_SIGNED_STRINGS, ids=name_of)
def test_intermediates_are_the_strings_of_the_builders(vector: Vector) -> None:
    assert strings_of_the_builders(vector) == vector["intermediates"]


@pytest.mark.parametrize("vector", WITH_SIGNED_STRINGS, ids=name_of)
def test_signed_strings_rebuilt_by_hand_from_spec_prefixes(vector: Vector) -> None:
    rebuilt = strings_by_hand(vector)
    inputs = vector["inputs"]

    assert rebuilt == vector["intermediates"]
    if "error" in vector:
        return
    for string, signed_string in rebuilt.items():
        signer, signature = SIGNER_AND_SIGNATURE[string]
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(inputs[signer]))
        public_key.verify(bytes.fromhex(inputs[signature]), bytes.fromhex(signed_string))


def test_prefixes_of_the_spec_are_three_ascii_texts() -> None:
    assert sorted(PREFIXES) == [
        "sotto/1 identity-dh",
        "sotto/1 login",
        "sotto/1 signed-prekey",
    ]
    for text, prefix in PREFIXES.items():
        assert bytes.fromhex(prefix) == text.encode("ascii")
        assert 0x00 not in bytes.fromhex(prefix)


def test_first_vector_is_rfc_8032_test_1() -> None:
    example = dict(EXAMPLE_KEY.findall(section("3.1")))
    first = VECTORS[0]

    assert first["operation"] == "identity-key"
    assert first["inputs"] == {"seed": example["seed"]}
    assert first["outputs"]["identity_key"] == example["identity key"]
    assert first["outputs"]["user_id"] in section("3.2")


def test_examples_of_the_spec_are_vectors() -> None:
    login_example = "".join(EXAMPLE_FIELD.findall(section("4.2")))
    small_order = LISTED_ENCODING.findall(section("3.3"))
    recorded_strings = [vector["intermediates"].get("login_string") for vector in VECTORS]
    refused_ids = [vector["inputs"].get("user_id") for vector in NEGATIVE]

    assert len(login_example) == 2 * 88
    assert login_example in recorded_strings
    assert len(small_order) == 5
    assert set(small_order) <= set(refused_ids)
