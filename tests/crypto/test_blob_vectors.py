import hashlib
import json
import re
from pathlib import Path
from typing import Any, NotRequired, TypedDict

import pytest

from sotto.crypto.blob import (
    BadBlobError,
    blob_length,
    chunk_count,
    chunk_nonces,
    digest_of,
    encrypt_blob,
    open_blob,
    padded_length,
    payload_key,
)

type Fields = dict[str, Any]


class Vector(TypedDict):
    name: str
    operation: str
    inputs: Fields
    intermediates: Fields
    outputs: NotRequired[Fields]
    error: NotRequired[str]


ROOT = Path(__file__).parent.parent.parent
PROTOCOL = (ROOT / "docs" / "protocol.md").read_text(encoding="utf-8")
DOCUMENT = json.loads((ROOT / "vectors" / "blob.json").read_text(encoding="utf-8"))
VECTORS: list[Vector] = DOCUMENT["vectors"]
BY_NAME = {vector["name"]: vector for vector in VECTORS}
POSITIVE = [vector for vector in VECTORS if "outputs" in vector]
NEGATIVE = [vector for vector in VECTORS if "error" in vector]

SCHEMA = 1
ALWAYS = {"name", "operation", "inputs", "intermediates"}
VECTOR_NAME = re.compile(r"[a-z0-9-]+")
LOWERCASE_HEX = re.compile(r"(?:[0-9a-f]{2})*")
OPERATION_ROW = re.compile(r"^\| `(blob-[a-z-]+)` +\|(.*)\|$", re.MULTILINE)
KEY_IN_A_CELL = re.compile(r"`(\w+)`")
NUMBER_KEYS = {"size", "padded_length", "blob_length"}
LIST_KEYS = {"chunk_nonces"}
LENGTHS = {"file_key": 16, "nonce": 16, "payload_key": 32, "digest": 32}
AT_THE_CHUNKS = {
    "nonce-changed",
    "ciphertext-changed",
    "tag-changed",
    "chunks-swapped",
    "first-chunk-sealed-as-the-last",
    "padding-not-zero",
    "last-chunk-left-out",
}
BEFORE_THE_CHUNKS = {
    "byte-appended",
    "digest-of-another-blob",
    "size-of-another-padded-length",
}


def name_of(vector: Vector) -> str:
    return vector["name"]


def section(number: str) -> str:
    start = PROTOCOL.index(f"\n## {number}. ")
    end = PROTOCOL.index("\n## ", start + 1)
    return PROTOCOL[start:end]


def documented_operations() -> dict[str, list[set[str]]]:
    """The keys of inputs, intermediates and outputs of each row of section 34."""
    operations = {}
    for name, cells in OPERATION_ROW.findall(section("34")):
        _rule, inputs, intermediates, outputs, _error = cells.split("|")
        operations[name] = [
            set(KEY_IN_A_CELL.findall(cell)) for cell in (inputs, intermediates, outputs)
        ]
    return operations


def opened(inputs: Fields) -> bytes:
    return open_blob(
        bytes.fromhex(inputs["blob"]),
        file_key=bytes.fromhex(inputs["file_key"]),
        size=inputs["size"],
        digest=bytes.fromhex(inputs["digest"]),
    )


def replay(vector: Vector) -> Fields:
    inputs = vector["inputs"]
    match vector["operation"]:
        case "blob-length":
            size = inputs["size"]
            return {"padded_length": padded_length(size), "blob_length": blob_length(size)}
        case "blob-encrypt":
            blob = encrypt_blob(
                bytes.fromhex(inputs["file"]),
                file_key=bytes.fromhex(inputs["file_key"]),
                nonce=bytes.fromhex(inputs["nonce"]),
            )
            return {"blob": blob.hex(), "digest": digest_of(blob).hex()}
        case "blob-open":
            return {"file": opened(inputs).hex()}
        case operation:
            raise AssertionError(f"the operation {operation} is not implemented")


def intermediates_of(vector: Vector) -> Fields:
    inputs = vector["inputs"]
    match vector["operation"]:
        case "blob-encrypt":
            size = len(bytes.fromhex(inputs["file"]))
            key = payload_key(
                bytes.fromhex(inputs["file_key"]), bytes.fromhex(inputs["nonce"])
            )
            return {
                "padded_length": padded_length(size),
                "payload_key": key.hex(),
                "chunk_nonces": [nonce.hex() for nonce in chunk_nonces(chunk_count(size))],
            }
        case "blob-open" if "outputs" in vector:
            blob = bytes.fromhex(inputs["blob"])
            key = payload_key(bytes.fromhex(inputs["file_key"]), blob[:16])
            return {"payload_key": key.hex()}
        case _:
            return {}


def test_vector_file_follows_the_schema() -> None:
    assert DOCUMENT["schema"] == SCHEMA
    assert len(BY_NAME) == len(VECTORS)
    for vector in VECTORS:
        assert VECTOR_NAME.fullmatch(vector["name"]), vector["name"]
        has_outputs, has_error = "outputs" in vector, "error" in vector
        assert has_outputs != has_error, vector["name"]
        assert vector.keys() == ALWAYS | ({"outputs"} if has_outputs else {"error"})


def test_vector_values_are_numbers_hex_and_lists_of_hex() -> None:
    for vector in VECTORS:
        for fields in (vector["inputs"], vector["intermediates"], vector.get("outputs", {})):
            for key, value in fields.items():
                if key in NUMBER_KEYS:
                    assert isinstance(value, int), (vector["name"], key)
                    continue
                values = value if key in LIST_KEYS else [value]
                for one in values:
                    assert isinstance(one, str), (vector["name"], key)
                    assert LOWERCASE_HEX.fullmatch(one), (vector["name"], key)
                    if key in LENGTHS:
                        assert len(one) == 2 * LENGTHS[key], (vector["name"], key)


def test_vectors_use_the_operations_and_keys_of_the_document() -> None:
    documented = documented_operations()

    assert documented.keys() == {vector["operation"] for vector in VECTORS}
    for vector in VECTORS:
        inputs, intermediates, outputs = documented[vector["operation"]]
        assert vector["inputs"].keys() == inputs, vector["name"]
        if "outputs" in vector:
            assert vector["intermediates"].keys() == intermediates, vector["name"]
            assert vector["outputs"].keys() == outputs, vector["name"]
        else:
            assert vector["intermediates"] == {}, vector["name"]
            assert vector["error"] == "BAD_BLOB", vector["name"]


@pytest.mark.parametrize("vector", POSITIVE, ids=name_of)
def test_positive_vectors_replay_byte_for_byte(vector: Vector) -> None:
    assert replay(vector) == vector["outputs"]


@pytest.mark.parametrize("vector", NEGATIVE, ids=name_of)
def test_negative_vectors_raise_their_named_error(vector: Vector) -> None:
    with pytest.raises(BadBlobError) as refusal:
        opened(vector["inputs"])

    assert refusal.value.result == vector["error"]


@pytest.mark.parametrize("vector", VECTORS, ids=name_of)
def test_intermediates_are_the_values_of_the_core(vector: Vector) -> None:
    assert intermediates_of(vector) == vector["intermediates"]


def test_vectors_cover_the_sizes_files_and_cases_of_section_34() -> None:
    sizes = {
        vector["inputs"]["size"] for vector in VECTORS if vector["operation"] == "blob-length"
    }
    files = [
        bytes.fromhex(vector["inputs"]["file"])
        for vector in VECTORS
        if vector["operation"] == "blob-encrypt"
    ]
    refused = {vector["name"].removeprefix("blob-open-") for vector in NEGATIVE}

    assert sizes >= {0, 255, 256, 257, 65536, 65537, 104857600, 104857601}
    assert sizes >= {2**exponent + 1 for exponent in range(8, 27)}
    assert {chunk_count(len(file)) for file in files} == {1, 2}
    assert b"" in files
    assert any(padded_length(len(file)) == 65536 for file in files)
    assert refused == AT_THE_CHUNKS | BEFORE_THE_CHUNKS


def test_each_positive_open_opens_the_blob_of_its_encryption() -> None:
    for vector in POSITIVE:
        if vector["operation"] != "blob-open":
            continue
        encrypted = BY_NAME[vector["name"].replace("blob-open-", "blob-encrypt-")]
        assert vector["inputs"]["blob"] == encrypted["outputs"]["blob"]
        assert vector["inputs"]["digest"] == encrypted["outputs"]["digest"]
        assert vector["outputs"]["file"] == encrypted["inputs"]["file"]


@pytest.mark.parametrize("case", sorted(AT_THE_CHUNKS))
def test_negative_vector_at_the_chunks_has_its_length_and_its_own_digest(case: str) -> None:
    inputs = BY_NAME[f"blob-open-{case}"]["inputs"]
    blob = bytes.fromhex(inputs["blob"])

    assert len(blob) == blob_length(inputs["size"])
    assert hashlib.sha256(blob).hexdigest() == inputs["digest"]
