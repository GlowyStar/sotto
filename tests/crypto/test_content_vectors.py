import json
import re
from pathlib import Path
from typing import Any, NotRequired, TypedDict

import pytest
from google.protobuf.message import Message

from sotto.client.envelope import (
    MAX_CONTENT_BYTES,
    encode_attachment,
    encode_deletion,
    encode_edit,
    encode_receipt,
    encode_text,
    encode_timer,
    open_content,
    unpad,
)
from sotto.crypto.identity import CryptoError
from sotto.proto.sotto_pb2 import Attachment, Quote

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
DOCUMENT = json.loads((ROOT / "vectors" / "content.json").read_text(encoding="utf-8"))
VECTORS: list[Vector] = DOCUMENT["vectors"]
BY_NAME = {vector["name"]: vector for vector in VECTORS}
POSITIVE = [vector for vector in VECTORS if "outputs" in vector]
NEGATIVE = [vector for vector in VECTORS if "error" in vector]

SCHEMA = 1
ALWAYS = {"name", "operation", "inputs", "intermediates"}
MEMBERS = {"text", "attachment", "edit", "deletion", "receipt", "timer"}
OPTIONAL_KEYS = MEMBERS | {"quote", "expires_after"}
BYTES_FIELDS = {"blob_id", "key", "digest", "thumbnail", "message_id"}
VECTOR_NAME = re.compile(r"[a-z0-9-]+")
OPERATION_ROW = re.compile(r"^\| `([a-z-]+)` +\|(.*)\|$", re.MULTILINE)
KEY_IN_A_CELL = re.compile(r"`(\w+)`")
ERROR_IN_A_CELL = re.compile(r"[A-Z_]{4,}")
ENCODE_CASES = {
    "text-with-a-timer",
    "reply-to-an-own-message",
    "reply-to-a-message-of-the-receiver",
    "reply-with-the-longest-quote",
    "reply-with-a-timer",
    "file-reply-with-a-timer",
    "edit",
    "edit-to-an-empty-text",
    "longest-edit",
    "deletion",
    "delivery-receipt",
    "read-receipt",
    "timer-off",
    "timer-of-an-hour",
    "longest-timer",
}
ENCODE_REFUSALS = {
    "longest-text-with-a-quote",
    "edit-too-long",
    "timer-too-long",
    "text-with-a-timer-too-long",
}
DECODE_REFUSALS = {
    "quote-id-of-15-bytes",
    "edit-id-of-17-bytes",
    "deletion-without-an-id",
    "receipt-with-an-id-of-15-bytes",
    "timer-too-long",
    "text-with-a-timer-too-long",
    "edit-text-not-utf-8",
    "quote-text-not-utf-8",
    "unknown-member",
    "quote-without-a-member",
}


def name_of(vector: Vector) -> str:
    return vector["name"]


def section(number: str) -> str:
    start = PROTOCOL.index(f"\n## {number}. ")
    end = PROTOCOL.index("\n## ", start + 1)
    return PROTOCOL[start:end]


def documented_operations() -> dict[str, tuple[list[set[str]], set[str]]]:
    """The keys of inputs, intermediates and outputs and the errors of each row of 40."""
    operations = {}
    for name, cells in OPERATION_ROW.findall(section("40")):
        _rule, inputs, intermediates, outputs, errors = cells.split("|")
        keys = [set(KEY_IN_A_CELL.findall(cell)) for cell in (inputs, intermediates, outputs)]
        operations[name] = (keys, set(ERROR_IN_A_CELL.findall(errors)))
    return operations


def proto_values(fields: Fields) -> Fields:
    """The keyword arguments of a message of the schema from the fields of a vector."""
    values: Fields = {}
    for key, value in fields.items():
        if key in BYTES_FIELDS:
            values[key] = bytes.fromhex(value)
        elif key == "message_ids":
            values[key] = [bytes.fromhex(one) for one in value]
        else:
            values[key] = value
    return values


def json_fields(message: Message) -> Fields:
    fields: Fields = {}
    for descriptor, value in message.ListFields():
        if isinstance(value, Message):
            fields[descriptor.name] = json_fields(value)
        elif isinstance(value, bytes):
            fields[descriptor.name] = value.hex()
        elif isinstance(value, str | int):
            fields[descriptor.name] = value
        else:
            fields[descriptor.name] = [item.hex() for item in value]
    return fields


def encode(inputs: Fields) -> bytes:
    """Calls the encoder of section 38.2 of the member that the inputs set."""
    quote = Quote(**proto_values(inputs["quote"])) if "quote" in inputs else None
    expires_after = inputs.get("expires_after", 0)
    if "text" in inputs:
        return encode_text(inputs["text"], quote=quote, expires_after=expires_after)
    if "attachment" in inputs:
        attachment = Attachment(**proto_values(inputs["attachment"]))
        return encode_attachment(attachment, quote=quote, expires_after=expires_after)
    if "edit" in inputs:
        edit = proto_values(inputs["edit"])
        return encode_edit(edit["message_id"], edit.get("text", ""))
    if "deletion" in inputs:
        return encode_deletion(proto_values(inputs["deletion"])["message_id"])
    if "receipt" in inputs:
        receipt = proto_values(inputs["receipt"])
        return encode_receipt(receipt.get("message_ids", []), read=receipt.get("read", False))
    return encode_timer(inputs["timer"].get("seconds", 0))


def replay(vector: Vector) -> Fields:
    inputs = vector["inputs"]
    match vector["operation"]:
        case "content-encode":
            return {"plaintext": encode(inputs).hex()}
        case "content-decode":
            return json_fields(open_content(bytes.fromhex(inputs["plaintext"])))
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
    plaintext = vector["inputs"].get("plaintext") or vector["outputs"]["plaintext"]

    assert unpad(bytes.fromhex(plaintext)).hex() == vector["intermediates"]["content"]


@pytest.mark.parametrize("vector", NEGATIVE, ids=name_of)
def test_negative_vectors_raise_their_named_error(vector: Vector) -> None:
    with pytest.raises(CryptoError) as refusal:
        replay(vector)

    assert refusal.value.result == vector["error"]


def test_vectors_cover_the_cases_of_section_40() -> None:
    def cases(operation: str, vectors: list[Vector]) -> set[str]:
        prefix = f"{operation}-"
        return {
            vector["name"].removeprefix(prefix)
            for vector in vectors
            if vector["operation"] == operation
        }

    assert cases("content-encode", POSITIVE) == ENCODE_CASES
    assert cases("content-encode", NEGATIVE) == ENCODE_REFUSALS
    assert cases("content-decode", NEGATIVE) == DECODE_REFUSALS
    for case in ENCODE_CASES:
        decoded = BY_NAME[f"content-decode-{case}"]
        encoded = BY_NAME[f"content-encode-{case}"]
        assert decoded["inputs"]["plaintext"] == encoded["outputs"]["plaintext"]
        assert decoded["outputs"] == encoded["inputs"]
    assert BY_NAME["content-decode-edit-with-a-quote-and-a-timer"]["outputs"].keys() == {
        "edit"
    }
    assert {"edit-with-an-unknown-field", "receipt-without-an-id"} <= cases(
        "content-decode", POSITIVE
    )
    longest = BY_NAME["content-encode-longest-edit"]["intermediates"]["content"]
    assert len(longest) // 2 == MAX_CONTENT_BYTES
