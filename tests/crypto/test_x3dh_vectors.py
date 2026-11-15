import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NotRequired, TypedDict

import pytest

from sotto.crypto.identity import (
    Bundle,
    CryptoError,
    OneTimePrekey,
    SignedPrekey,
    decode_user_id,
    derive_x25519_public_key,
    identity_dh_string,
    signed_prekey_string,
)
from sotto.crypto.x3dh import KeyAgreement, dh, initiate, respond

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
DOCUMENT = json.loads((ROOT / "vectors" / "x3dh.json").read_text(encoding="utf-8"))
VECTORS: list[Vector] = DOCUMENT["vectors"]
BY_NAME = {vector["name"]: vector for vector in VECTORS}
POSITIVE = [vector for vector in VECTORS if "outputs" in vector]
NEGATIVE = [vector for vector in VECTORS if "error" in vector]

SCHEMA = 1
ALWAYS = {"name", "operation", "inputs", "intermediates"}
VECTOR_NAME = re.compile(r"[a-z0-9-]+")
LOWERCASE_HEX = re.compile(r"(?:[0-9a-f]{2})*")
OPERATION_ROW = re.compile(r"^\| `([a-z0-9-]+)` \|(.*)\|$", re.MULTILINE)
KEY_IN_A_CELL = re.compile(r"`(\w+)`")
RESULT_IN_A_CELL = re.compile(r"[A-Z_]+")

TEXT_KEYS = {"contact_id"}
PREKEY_ID_KEYS = {"signed_prekey_id", "one_time_prekey_id"}
LARGEST_PREKEY_ID = 2**32 - 1
SIGNED_STRINGS = {"identity_dh_string", "signed_prekey_string"}
ONLY_WITH_A_ONE_TIME_PREKEY = {
    "one_time_prekey_id",
    "one_time_prekey_key",
    "one_time_prekey_private_key",
    "dh4",
}
LENGTHS = {
    "identity_dh_signature": (64,),
    "signed_prekey_signature": (64,),
    "identity_dh_string": (84,),
    "signed_prekey_string": (86,),
    "input_key_material": (128, 160),
    "session_associated_data": (161,),
}
KEY_LENGTH = (32,)

FIELD_PRIME = 2**255 - 19
KEY_MATERIAL_PREFIX = b"\xff" * 32
TOP_BIT = 0x80
NOWHERE = slice(0, 0)
RESPONDER_IDENTITY_KEY = slice(65, 97)
EPHEMERAL_KEY = slice(129, 161)
PAIRS = [
    "with-a-one-time-prekey",
    "without-a-one-time-prekey",
    "replaced-one-time-prekey",
    "unknown-key-share",
]
# The initiator, the responder, whether SK is equal, where the associated data differs.
RELATIONS = [
    ("with-a-one-time-prekey", "with-a-one-time-prekey", True, NOWHERE),
    ("without-a-one-time-prekey", "without-a-one-time-prekey", True, NOWHERE),
    ("replaced-one-time-prekey", "replaced-one-time-prekey", False, NOWHERE),
    ("unknown-key-share", "unknown-key-share", True, RESPONDER_IDENTITY_KEY),
    ("with-a-one-time-prekey", "ephemeral-key-top-bit-set", True, EPHEMERAL_KEY),
    ("with-a-one-time-prekey", "ephemeral-key-inverse", True, EPHEMERAL_KEY),
]
ZERO_DH = {
    "x3dh-initiate-one-time-prekey-of-small-order": (
        "x3dh-initiate-with-a-one-time-prekey",
        "one_time_prekey_key",
    ),
    "x3dh-respond-ephemeral-key-of-small-order": (
        "x3dh-respond-with-a-one-time-prekey",
        "ephemeral_key",
    ),
}


def name_of(vector: Vector) -> str:
    return vector["name"]


def section(number: str) -> str:
    start = PROTOCOL.index(f"\n### {number} ")
    end = PROTOCOL.index("\n##", start + 1)
    return PROTOCOL[start:end]


def initiator(case: str) -> Vector:
    return BY_NAME[f"x3dh-initiate-{case}"]


def responder(case: str) -> Vector:
    return BY_NAME[f"x3dh-respond-{case}"]


def associated_data_of(vector: Vector) -> bytes:
    return bytes.fromhex(vector["outputs"]["session_associated_data"])


def public_key_of(inputs: Fields, private_key: str) -> str:
    return derive_x25519_public_key(bytes.fromhex(inputs[private_key])).hex()


def keys_of(vector: Vector, documented: frozenset[str]) -> frozenset[str]:
    """The keys of section 15.6 that are present in this vector."""
    if "one_time_prekey_id" in vector["inputs"]:
        return documented
    return documented - ONLY_WITH_A_ONE_TIME_PREKEY


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


def optional_key(inputs: Fields, key: str) -> bytes | None:
    return bytes.fromhex(inputs[key]) if key in inputs else None


def outputs_of(agreement: KeyAgreement) -> Fields:
    return {
        "sk": agreement.shared_secret.hex(),
        "session_associated_data": agreement.associated_data.hex(),
    }


def replay(vector: Vector) -> Fields:
    inputs = vector["inputs"]
    match vector["operation"]:
        case "x3dh-initiate":
            agreement = initiate(
                bundle_of(inputs),
                identity_key=bytes.fromhex(inputs["identity_key"]),
                identity_dh_private_key=bytes.fromhex(inputs["identity_dh_private_key"]),
                ephemeral_private_key=bytes.fromhex(inputs["ephemeral_private_key"]),
                contact_identity_key=decode_user_id(inputs["contact_id"]),
                pinned_identity_dh_key=None,
            )
        case "x3dh-respond":
            agreement = respond(
                identity_key=bytes.fromhex(inputs["identity_key"]),
                identity_dh_private_key=bytes.fromhex(inputs["identity_dh_private_key"]),
                signed_prekey_private_key=bytes.fromhex(inputs["signed_prekey_private_key"]),
                one_time_prekey_private_key=optional_key(
                    inputs, "one_time_prekey_private_key"
                ),
                sender_identity_key=bytes.fromhex(inputs["sender"]),
                sender_identity_dh_key=bytes.fromhex(inputs["identity_dh_key"]),
                sender_identity_dh_signature=bytes.fromhex(inputs["identity_dh_signature"]),
                ephemeral_key=bytes.fromhex(inputs["ephemeral_key"]),
                pinned_identity_dh_key=None,
            )
        case operation:
            raise NotImplementedError(f"{vector['name']}: no operation {operation!r}")
    return outputs_of(agreement)


def strings_of_the_builders(vector: Vector) -> dict[str, str]:
    inputs = vector["inputs"]
    identity_dh_key = bytes.fromhex(inputs["identity_dh_key"])
    match vector["operation"]:
        case "x3dh-initiate":
            identity = bytes.fromhex(inputs["identity"])
            return {
                "identity_dh_string": identity_dh_string(
                    identity_key=identity, identity_dh_key=identity_dh_key
                ).hex(),
                "signed_prekey_string": signed_prekey_string(
                    identity_key=identity,
                    signed_prekey=bytes.fromhex(inputs["signed_prekey_key"]),
                ).hex(),
            }
        case "x3dh-respond":
            return {
                "identity_dh_string": identity_dh_string(
                    identity_key=bytes.fromhex(inputs["sender"]),
                    identity_dh_key=identity_dh_key,
                ).hex(),
            }
        case operation:
            raise NotImplementedError(f"{vector['name']}: no signed string of {operation!r}")


def dh_outputs_of_the_core(vector: Vector) -> list[bytes]:
    """DH1 to DH4 by the `dh` of the core, in the order of sections 16.6 and 16.8."""
    keys = {
        key: bytes.fromhex(value)
        for key, value in vector["inputs"].items()
        if key not in PREKEY_ID_KEYS
    }
    match vector["operation"]:
        case "x3dh-initiate":
            pairs = [
                ("identity_dh_private_key", "signed_prekey_key"),
                ("ephemeral_private_key", "identity_dh_key"),
                ("ephemeral_private_key", "signed_prekey_key"),
                ("ephemeral_private_key", "one_time_prekey_key"),
            ]
        case "x3dh-respond":
            pairs = [
                ("signed_prekey_private_key", "identity_dh_key"),
                ("identity_dh_private_key", "ephemeral_key"),
                ("signed_prekey_private_key", "ephemeral_key"),
                ("one_time_prekey_private_key", "ephemeral_key"),
            ]
        case operation:
            raise NotImplementedError(f"{vector['name']}: no operation {operation!r}")
    return [
        dh(keys[private_key], keys[public_key])
        for private_key, public_key in pairs
        if private_key in keys and public_key in keys
    ]


def operations_of_the_spec() -> dict[str, Operation]:
    operations = {}
    for name, cells in OPERATION_ROW.findall(section("15.6")):
        _rule, inputs, intermediates, outputs, errors = cells.split("|")
        operations[name] = Operation(
            inputs=frozenset(KEY_IN_A_CELL.findall(inputs)),
            intermediates=frozenset(KEY_IN_A_CELL.findall(intermediates)),
            outputs=frozenset(KEY_IN_A_CELL.findall(outputs)),
            errors=frozenset(RESULT_IN_A_CELL.findall(errors)),
        )
    return operations


def has_the_type_of_its_key(key: str, value: object) -> bool:
    if key in PREKEY_ID_KEYS:
        return type(value) is int and 0 <= value <= LARGEST_PREKEY_ID
    if type(value) is not str or LOWERCASE_HEX.fullmatch(value) is None:
        return False
    return key in TEXT_KEYS or len(value) // 2 in LENGTHS.get(key, KEY_LENGTH)


def test_vector_file_follows_the_schema() -> None:
    names = [vector["name"] for vector in VECTORS]

    assert DOCUMENT.keys() == {"schema", "vectors"}
    assert DOCUMENT["schema"] == SCHEMA
    assert len(set(names)) == len(names)
    for vector in VECTORS:
        assert VECTOR_NAME.fullmatch(vector["name"])
        assert vector["name"].startswith(vector["operation"] + "-")
        assert vector.keys() in (ALWAYS | {"outputs"}, ALWAYS | {"error"}), vector["name"]


def test_vector_values_are_numbers_and_hex_of_the_length_of_their_field() -> None:
    for vector in VECTORS:
        fields = vector["inputs"] | vector["intermediates"] | vector.get("outputs", {})
        for key, value in fields.items():
            assert has_the_type_of_its_key(key, value), f"{vector['name']}: {key}"


def test_vectors_use_the_operations_and_keys_of_the_document() -> None:
    operations = operations_of_the_spec()

    assert operations.keys() == {vector["operation"] for vector in VECTORS}
    for vector in VECTORS:
        operation = operations[vector["operation"]]
        intermediates = keys_of(vector, operation.intermediates)
        if "error" in vector:
            intermediates &= SIGNED_STRINGS
        assert vector["inputs"].keys() == keys_of(vector, operation.inputs), vector["name"]
        assert vector["intermediates"].keys() == intermediates, vector["name"]
        if "outputs" in vector:
            assert vector["outputs"].keys() == operation.outputs, vector["name"]
    for name, operation in operations.items():
        errors = {vector["error"] for vector in NEGATIVE if vector["operation"] == name}
        assert errors == operation.errors, name


@pytest.mark.parametrize("vector", POSITIVE, ids=name_of)
def test_positive_vectors_replay_byte_for_byte(vector: Vector) -> None:
    assert replay(vector) == vector["outputs"]


@pytest.mark.parametrize("vector", NEGATIVE, ids=name_of)
def test_negative_vectors_raise_their_named_error(vector: Vector) -> None:
    with pytest.raises(CryptoError) as refusal:
        replay(vector)

    assert refusal.value.result == vector["error"]


@pytest.mark.parametrize("vector", VECTORS, ids=name_of)
def test_intermediates_are_the_values_of_the_core(vector: Vector) -> None:
    computed = strings_of_the_builders(vector)
    if "outputs" in vector:
        dh_outputs = dh_outputs_of_the_core(vector)
        for number, output in enumerate(dh_outputs, 1):
            computed[f"dh{number}"] = output.hex()
        computed["input_key_material"] = (KEY_MATERIAL_PREFIX + b"".join(dh_outputs)).hex()

    assert computed == vector["intermediates"]


@pytest.mark.parametrize("case", PAIRS)
def test_vectors_of_one_name_are_the_two_sides_of_one_key_agreement(case: str) -> None:
    sent = initiator(case)["inputs"]
    received = responder(case)["inputs"]

    assert received["sender"] == sent["identity_key"]
    assert received["identity_dh_key"] == public_key_of(sent, "identity_dh_private_key")
    assert received["ephemeral_key"] == public_key_of(sent, "ephemeral_private_key")
    assert sent["identity_dh_key"] == public_key_of(received, "identity_dh_private_key")
    assert sent["signed_prekey_key"] == public_key_of(received, "signed_prekey_private_key")
    assert received["signed_prekey_id"] == sent["signed_prekey_id"]
    assert received.get("one_time_prekey_id") == sent.get("one_time_prekey_id")


@pytest.mark.parametrize(("sending", "receiving", "same_sk", "differing"), RELATIONS)
def test_outputs_of_the_two_sides_differ_as_section_24_3_states(
    sending: str, receiving: str, same_sk: bool, differing: slice
) -> None:
    sent = initiator(sending)
    received = responder(receiving)
    of_the_initiator = associated_data_of(sent)
    of_the_responder = associated_data_of(received)
    differs_there = of_the_initiator[differing] != of_the_responder[differing]

    assert (sent["outputs"]["sk"] == received["outputs"]["sk"]) is same_sk
    assert differs_there is (differing != NOWHERE)
    assert of_the_initiator[: differing.start] == of_the_responder[: differing.start]
    assert of_the_initiator[differing.stop :] == of_the_responder[differing.stop :]


def test_replaced_one_time_prekey_is_another_key_than_the_one_the_responder_holds() -> None:
    sent = initiator("replaced-one-time-prekey")
    received = responder("replaced-one-time-prekey")
    held = public_key_of(received["inputs"], "one_time_prekey_private_key")

    assert sent["inputs"]["one_time_prekey_key"] != held
    assert sent["intermediates"]["dh4"] != received["intermediates"]["dh4"]


def test_unknown_key_share_names_two_identities_for_one_set_of_x25519_keys() -> None:
    sent = initiator("unknown-key-share")
    received = responder("unknown-key-share")
    contact = bytes.fromhex(sent["inputs"]["contact_id"])
    owner_of_the_keys = bytes.fromhex(received["inputs"]["identity_key"])

    assert contact != owner_of_the_keys
    assert associated_data_of(sent)[RESPONDER_IDENTITY_KEY] == contact
    assert associated_data_of(received)[RESPONDER_IDENTITY_KEY] == owner_of_the_keys


def test_other_bytes_of_the_ephemeral_key_are_the_two_of_section_16_5() -> None:
    plain = responder("with-a-one-time-prekey")
    sent = bytes.fromhex(plain["inputs"]["ephemeral_key"])
    with_top_bit = responder("ephemeral-key-top-bit-set")
    with_inverse = responder("ephemeral-key-inverse")
    top_bit_set = bytes.fromhex(with_top_bit["inputs"]["ephemeral_key"])
    inverse = bytes.fromhex(with_inverse["inputs"]["ephemeral_key"])
    product = int.from_bytes(sent, "little") * int.from_bytes(inverse, "little")

    assert top_bit_set == sent[:31] + bytes([sent[31] | TOP_BIT]) != sent
    assert product % FIELD_PRIME == 1
    assert inverse != sent
    for changed in (with_top_bit, with_inverse):
        received = bytes.fromhex(changed["inputs"]["ephemeral_key"])
        assert changed["inputs"] == plain["inputs"] | {"ephemeral_key": received.hex()}
        assert changed["intermediates"] == plain["intermediates"]
        assert associated_data_of(changed)[EPHEMERAL_KEY] == received


def test_zero_dh_vectors_differ_from_a_positive_vector_in_one_key() -> None:
    assert ZERO_DH.keys() == {vector["name"] for vector in NEGATIVE}
    for name, (positive, key) in ZERO_DH.items():
        refused = BY_NAME[name]["inputs"]
        accepted = BY_NAME[positive]["inputs"]
        assert refused == accepted | {key: refused[key]}, name
        assert refused[key] != accepted[key], name
