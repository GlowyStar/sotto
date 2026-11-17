import json
import re
from pathlib import Path
from typing import Any, NotRequired, TypedDict

import pytest

from sotto.client.envelope import (
    avatar_media_type,
    decode_content,
    encode_profile,
    unpad,
)
from sotto.crypto.identity import CryptoError
from sotto.proto.sotto_pb2 import Attachment, Profile

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
DOCUMENT = json.loads((ROOT / "vectors" / "profile.json").read_text(encoding="utf-8"))
VECTORS: list[Vector] = DOCUMENT["vectors"]
BY_NAME = {vector["name"]: vector for vector in VECTORS}
POSITIVE = [vector for vector in VECTORS if "outputs" in vector]
NEGATIVE = [vector for vector in VECTORS if "error" in vector]

SCHEMA = 1
ALWAYS = {"name", "operation", "inputs", "intermediates"}
OPTIONAL_KEYS = {"avatar"}
BYTES_FIELDS = {"blob_id", "key", "digest", "thumbnail"}
VECTOR_NAME = re.compile(r"[a-z0-9-]+")
OPERATION_ROW = re.compile(r"^\| `([a-z-]+)` +\|(.*)\|$", re.MULTILINE)
KEY_IN_A_CELL = re.compile(r"`(\w+)`")
ERROR_IN_A_CELL = re.compile(r"[A-Z_]{4,}")
DECODE_REFUSALS = {
    "name-too-long",
    "name-not-utf-8",
    "name-with-u0000",
    "name-with-u007f",
    "name-with-u0085",
    "name-with-u202e",
    "name-with-u2028",
    "avatar-blob-id-of-15-bytes",
    "avatar-key-of-17-bytes",
    "avatar-digest-of-31-bytes",
    "avatar-too-large",
    "avatar-gif",
    "avatar-media-type-in-capitals",
    "avatar-media-type-with-a-parameter",
    "avatar-without-a-media-type",
}
ENCODE_CASES = {
    "name-alone",
    "name-and-jpeg-avatar",
    "png-avatar-without-a-name",
    "empty",
    "longest-name",
    "longest",
}


def name_of(vector: Vector) -> str:
    return vector["name"]


def section(number: str) -> str:
    start = PROTOCOL.index(f"\n## {number}. ")
    end = PROTOCOL.index("\n## ", start + 1)
    return PROTOCOL[start:end]


def documented_operations() -> dict[str, tuple[list[set[str]], set[str]]]:
    """The keys of inputs, intermediates and outputs and the errors of each row of 37."""
    operations = {}
    for name, cells in OPERATION_ROW.findall(section("37")):
        _rule, inputs, intermediates, outputs, errors = cells.split("|")
        keys = [set(KEY_IN_A_CELL.findall(cell)) for cell in (inputs, intermediates, outputs)]
        operations[name] = (keys, set(ERROR_IN_A_CELL.findall(errors)))
    return operations


def attachment_of(fields: Fields) -> Attachment:
    values: Fields = {
        key: bytes.fromhex(value) if key in BYTES_FIELDS else value
        for key, value in fields.items()
    }
    return Attachment(**values)


def fields_of(attachment: Attachment) -> Fields:
    return {
        descriptor.name: value.hex() if isinstance(value, bytes) else value
        for descriptor, value in attachment.ListFields()
    }


def decoded(plaintext: str) -> Profile:
    content = decode_content(bytes.fromhex(plaintext))
    assert isinstance(content, Profile)
    return content


def replay(vector: Vector) -> Fields:
    inputs = vector["inputs"]
    match vector["operation"]:
        case "profile-encode":
            avatar = attachment_of(inputs["avatar"]) if "avatar" in inputs else None
            return {"plaintext": encode_profile(inputs["name"], avatar).hex()}
        case "profile-decode":
            profile = decoded(inputs["plaintext"])
            outputs: Fields = {"name": profile.name}
            if profile.HasField("avatar"):
                outputs["avatar"] = fields_of(profile.avatar)
            return outputs
        case "avatar-media-type":
            return {"media_type": avatar_media_type(bytes.fromhex(inputs["image"]))}
        case operation:
            raise AssertionError(f"the operation {operation} is not implemented")


def test_vector_file_follows_the_schema() -> None:
    assert DOCUMENT["schema"] == SCHEMA
    assert len(BY_NAME) == len(VECTORS)
    for vector in VECTORS:
        assert VECTOR_NAME.fullmatch(vector["name"]), vector["name"]
        has_outputs, has_error = "outputs" in vector, "error" in vector
        assert has_outputs != has_error, vector["name"]
        assert vector.keys() == ALWAYS | ({"outputs"} if has_outputs else {"error"})
        if has_error:
            assert vector["intermediates"] == {}, vector["name"]


def test_vectors_use_the_operations_and_keys_of_the_document() -> None:
    documented = documented_operations()

    assert documented.keys() == {vector["operation"] for vector in VECTORS}
    for vector in VECTORS:
        (inputs, intermediates, outputs), errors = documented[vector["operation"]]
        assert inputs - OPTIONAL_KEYS <= vector["inputs"].keys() <= inputs, vector["name"]
        if "outputs" in vector:
            assert vector["intermediates"].keys() == intermediates, vector["name"]
            assert outputs - OPTIONAL_KEYS <= vector["outputs"].keys() <= outputs
        else:
            assert vector["error"] in errors, vector["name"]


@pytest.mark.parametrize("vector", POSITIVE, ids=name_of)
def test_positive_vectors_replay_byte_for_byte(vector: Vector) -> None:
    assert replay(vector) == vector["outputs"]


@pytest.mark.parametrize("vector", POSITIVE, ids=name_of)
def test_intermediates_are_the_content_in_front_of_the_padding(vector: Vector) -> None:
    if vector["operation"] == "avatar-media-type":
        return
    plaintext = vector["inputs"].get("plaintext") or vector["outputs"]["plaintext"]

    assert unpad(bytes.fromhex(plaintext)).hex() == vector["intermediates"]["content"]


@pytest.mark.parametrize("vector", NEGATIVE, ids=name_of)
def test_negative_vectors_raise_their_named_error(vector: Vector) -> None:
    with pytest.raises(CryptoError) as refusal:
        replay(vector)

    assert refusal.value.result == vector["error"]


def test_vectors_cover_the_cases_of_section_37() -> None:
    encoded = {
        vector["name"].removeprefix("profile-encode-")
        for vector in POSITIVE
        if vector["operation"] == "profile-encode"
    }
    refused = {
        vector["name"].removeprefix("profile-decode-")
        for vector in NEGATIVE
        if vector["operation"] == "profile-decode"
    }

    assert encoded == ENCODE_CASES
    assert refused == DECODE_REFUSALS
    for case in ENCODE_CASES:
        decoded_vector = BY_NAME[f"profile-decode-{case}"]
        encoded_vector = BY_NAME[f"profile-encode-{case}"]
        assert decoded_vector["inputs"]["plaintext"] == encoded_vector["outputs"]["plaintext"]
    assert "profile-decode-unknown-field" in BY_NAME
    longest = BY_NAME["profile-encode-longest"]["intermediates"]["content"]
    assert len(longest) // 2 == 16753
