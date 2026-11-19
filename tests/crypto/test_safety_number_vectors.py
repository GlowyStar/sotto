import hashlib
import json
import re
from pathlib import Path
from typing import Any, TypedDict

import pytest

from sotto.crypto.safety_number import (
    CHUNKS,
    FINGERPRINT_VERSION,
    SCANNED_BYTES,
    digits,
    fingerprint,
    identity_fingerprint,
    qr_payload,
    safety_number,
)

type Fields = dict[str, Any]


class Vector(TypedDict):
    name: str
    operation: str
    inputs: Fields
    intermediates: Fields
    outputs: Fields


ROOT = Path(__file__).parent.parent.parent
PROTOCOL = (ROOT / "docs" / "protocol.md").read_text(encoding="utf-8")
DOCUMENT = json.loads((ROOT / "vectors" / "safety-number.json").read_text(encoding="utf-8"))
VECTORS: list[Vector] = DOCUMENT["vectors"]
BY_NAME = {vector["name"]: vector for vector in VECTORS}

SCHEMA = 1
KEYS = {"name", "operation", "inputs", "intermediates", "outputs"}
VECTOR_NAME = re.compile(r"safety-number-([a-z0-9]+)-([a-z0-9]+)")
OPERATION_ROW = re.compile(r"^\| `([a-z-]+)` +\|(.*)\|$", re.MULTILINE)
KEY_IN_A_CELL = re.compile(r"`(\w+)`")
PAYLOAD = re.compile(r"sotto-safety-number-1 [0-9a-f]{64} [0-9a-f]{64}")
ROUNDS_AFTER_THE_FIRST = 5199

# libsignal, rust/protocol/src/fingerprint.rs, test fingerprint_test_v1, at commit
# 956e1cab1d68291c92f2fcca3c29ec6c3b367e28: keys of 33 bytes, phone numbers as identifiers.
LIBSIGNAL_ALICE_KEY = (
    "0506863bc66d02b40d27b8d49ca7c09e9239236f9d7d25d6fcca5ce13c7064d868"  # gitleaks:allow
)
LIBSIGNAL_BOB_KEY = (
    "05f781b6fb32fed9ba1cf2de978d4d5da28dc34046ae814402b5c0dbd96fda907b"  # gitleaks:allow
)
LIBSIGNAL_ALICE_ID = b"+14152222222"
LIBSIGNAL_BOB_ID = b"+14153333333"
LIBSIGNAL_DISPLAY = "300354477692869396892869876765458257569162576843440918079131"
LIBSIGNAL_ALICE_SCANNED = "1e301a0353dce3dbe7684cb8336e85136cdc0ee96219494ada305d62a7bd61df"
LIBSIGNAL_BOB_SCANNED = "d62cbf73a11592015b6b9f1682ac306fea3aaf3885b84d12bca631e9d4fb3a4d"


def name_of(vector: Vector) -> str:
    return vector["name"]


def documented_keys() -> dict[str, list[set[str]]]:
    """The keys of inputs, intermediates and outputs of each operation of section 46."""
    start = PROTOCOL.index("\n## 46. ")
    section = PROTOCOL[start : PROTOCOL.index("\n## ", start + 1)]
    operations = {}
    for name, cells in OPERATION_ROW.findall(section):
        _rule, inputs, intermediates, outputs, _errors = cells.split("|")
        operations[name] = [
            set(KEY_IN_A_CELL.findall(cell)) for cell in (inputs, intermediates, outputs)
        ]
    return operations


def side(key: str) -> tuple[bytes, bytes]:
    """The first input of the hash chain of a key in hex, and its fingerprint."""
    identity_key = bytes.fromhex(key)
    first_input = FINGERPRINT_VERSION + identity_key + key.encode("ascii") + identity_key
    return first_input, identity_fingerprint(identity_key)


def chained(first_input: str, key: str) -> str:
    """The fingerprint from a recorded first input, by section 44.2 and nothing of the core."""
    digest = hashlib.sha512(bytes.fromhex(first_input)).digest()
    for _ in range(ROUNDS_AFTER_THE_FIRST):
        digest = hashlib.sha512(digest + bytes.fromhex(key)).digest()
    return digest.hex()


def replay(vector: Vector) -> tuple[Fields, Fields]:
    """The intermediates and the outputs of a vector, computed from its inputs."""
    key, contact = vector["inputs"]["identity_key"], vector["inputs"]["contact_identity_key"]
    first_input, own = side(key)
    contact_first_input, theirs = side(contact)
    intermediates = {
        "fingerprint_input": first_input.hex(),
        "contact_fingerprint_input": contact_first_input.hex(),
        "fingerprint": own.hex(),
        "contact_fingerprint": theirs.hex(),
        "digits": digits(own),
        "contact_digits": digits(theirs),
    }
    outputs = {
        "safety_number": safety_number(bytes.fromhex(key), bytes.fromhex(contact)),
        "qr_payload": qr_payload(bytes.fromhex(key), bytes.fromhex(contact)),
    }
    return intermediates, outputs


def test_file_has_the_schema_and_unique_names() -> None:
    assert DOCUMENT["schema"] == SCHEMA
    assert len(BY_NAME) == len(VECTORS)
    for vector in VECTORS:
        assert VECTOR_NAME.fullmatch(vector["name"]), vector["name"]
        assert vector.keys() == KEYS, vector["name"]


def test_vectors_use_the_operations_and_keys_of_the_document() -> None:
    documented = documented_keys()

    assert documented.keys() == {vector["operation"] for vector in VECTORS}
    for vector in VECTORS:
        inputs, intermediates, outputs = documented[vector["operation"]]
        assert vector["inputs"].keys() == inputs, vector["name"]
        assert vector["intermediates"].keys() == intermediates, vector["name"]
        assert vector["outputs"].keys() == outputs, vector["name"]


@pytest.mark.parametrize("vector", VECTORS, ids=name_of)
def test_positive_vectors_replay_byte_for_byte(vector: Vector) -> None:
    inputs, intermediates = vector["inputs"], vector["intermediates"]
    own = chained(intermediates["fingerprint_input"], inputs["identity_key"])
    contact = chained(
        intermediates["contact_fingerprint_input"], inputs["contact_identity_key"]
    )

    assert replay(vector) == (intermediates, vector["outputs"])
    assert own == intermediates["fingerprint"]
    assert contact == intermediates["contact_fingerprint"]


def test_vectors_of_one_pair_are_the_two_sides_of_one_comparison() -> None:
    for vector in VECTORS:
        match = VECTOR_NAME.fullmatch(vector["name"])
        assert match is not None
        other = BY_NAME[f"safety-number-{match[2]}-{match[1]}"]
        payload = vector["outputs"]["qr_payload"]
        prefix, own_half, contact_half = payload.split(" ")

        assert vector["outputs"]["safety_number"] == other["outputs"]["safety_number"]
        assert PAYLOAD.fullmatch(payload)
        assert other["outputs"]["qr_payload"] == f"{prefix} {contact_half} {own_half}"


def test_vectors_cover_both_orders_and_a_digit_group_with_a_leading_zero() -> None:
    orders = set()
    groups = []
    for vector in VECTORS:
        own_digits = vector["intermediates"]["digits"]
        orders.add(vector["outputs"]["safety_number"].startswith(own_digits))
        width = len(own_digits) // CHUNKS
        for start in range(0, len(own_digits), width):
            groups.append(own_digits[start : start + width])

    assert orders == {True, False}
    assert any(group.startswith("0") for group in groups)


def test_example_of_section_44_3_is_the_number_of_its_vector() -> None:
    start = PROTOCOL.index("\n### 44.3 ")
    example = PROTOCOL[start:].split("```\n")[1]

    number = BY_NAME["safety-number-alice-bob"]["outputs"]["safety_number"]
    assert example.replace(" ", "").replace("\n", "") == number


def test_an_id_substituted_on_its_way_gives_another_number() -> None:
    bob_holds_alice = BY_NAME["safety-number-bob-alice"]["outputs"]["safety_number"]
    alice_holds_mallory_as_bob = BY_NAME["safety-number-alice-mallory"]["outputs"]

    assert alice_holds_mallory_as_bob["safety_number"] != bob_holds_alice


def test_fingerprint_replays_the_test_vector_of_libsignal() -> None:
    alice = fingerprint(bytes.fromhex(LIBSIGNAL_ALICE_KEY), LIBSIGNAL_ALICE_ID)
    bob = fingerprint(bytes.fromhex(LIBSIGNAL_BOB_KEY), LIBSIGNAL_BOB_ID)

    assert "".join(sorted([digits(alice), digits(bob)])) == LIBSIGNAL_DISPLAY
    assert alice[:SCANNED_BYTES].hex() == LIBSIGNAL_ALICE_SCANNED
    assert bob[:SCANNED_BYTES].hex() == LIBSIGNAL_BOB_SCANNED
