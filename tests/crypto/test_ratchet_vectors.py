import json
import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any, NotRequired, TypedDict

import pytest

from sotto.crypto.identity import CryptoError, derive_x25519_public_key
from sotto.crypto.ratchet import (
    RatchetState,
    SkippedKey,
    decrypt,
    encrypt,
    init_initiator,
    init_responder,
    kdf_ck,
    kdf_rk,
)
from sotto.crypto.x3dh import dh

type Fields = dict[str, Any]


class Vector(TypedDict):
    name: str
    operation: str
    inputs: Fields
    intermediates: Fields
    outputs: NotRequired[Fields]
    error: NotRequired[str]


@dataclass(frozen=True, slots=True, kw_only=True)
class Operation:
    inputs: frozenset[str]
    intermediates: frozenset[str]
    outputs: frozenset[str]
    errors: frozenset[str]


@dataclass(frozen=True, slots=True, kw_only=True)
class Step:
    """A vector run by the core: the state of its party before and after it."""

    before: RatchetState | None
    after: RatchetState | None
    outputs: Fields
    header: bytes = b""
    error: str | None = None


ROOT = Path(__file__).parent.parent.parent
PROTOCOL = (ROOT / "docs" / "protocol.md").read_text(encoding="utf-8")
DOCUMENT = json.loads((ROOT / "vectors" / "ratchet.json").read_text(encoding="utf-8"))
VECTORS: list[Vector] = DOCUMENT["vectors"]
BY_NAME = {vector["name"]: vector for vector in VECTORS}
POSITIVE = [vector for vector in VECTORS if "outputs" in vector]
NEGATIVE = [vector for vector in VECTORS if "error" in vector]
X3DH = {
    vector["name"]: vector
    for vector in json.loads((ROOT / "vectors" / "x3dh.json").read_text(encoding="utf-8"))[
        "vectors"
    ]
}

SCHEMA = 1
ALWAYS = {"name", "operation", "inputs", "intermediates"}
VECTOR_NAME = re.compile(r"[a-z0-9-]+")
LOWERCASE_HEX = re.compile(r"(?:[0-9a-f]{2})*")
OPERATION_ROW = re.compile(r"^\| `([a-z0-9-]+)` \|(.*)\|$", re.MULTILINE)
KEY_IN_A_CELL = re.compile(r"`(\w+)`")
RESULT_IN_A_CELL = re.compile(r"[A-Z_]+")
APPENDIX_BLOCK = re.compile(r"^```\n(.*?)^```$", re.DOTALL | re.MULTILINE)

PARTIES = {"initiator", "responder"}
UNUSED_RANDOM_BYTES = bytes(32)
DH_RATCHET_STEP = frozenset(
    {
        "dh_receiving",
        "root_key_receiving",
        "chain_key_receiving",
        "ratchet_key",
        "dh_sending",
        "root_key_sending",
        "chain_key_sending",
    }
)
OPTIONAL = DH_RATCHET_STEP | {"ratchet_private_key", "chain_key"}
ENTRY_KEYS = {"ratchet_key", "number", "message_key", "step"}
ENTRY_LISTS = {"stored_skipped_keys", "purged_skipped_keys"}
NUMBER_KEYS = {"purged_count"}
LENGTHS = {
    "session_associated_data": 161,
    "message_id": 16,
    "nonce": 12,
    "header": 40,
    "associated_data": 217,
}
KEY_LENGTH = 32
PADDING_BLOCK = 256
CIPHERTEXT_OVERHEAD = 28
HEX_PER_LINE = 64
SESSION = "with-a-one-time-prekey"

APPENDIX = [
    [
        (f"x3dh-initiate-{SESSION}", "inputs", "identity_key"),
        (f"x3dh-initiate-{SESSION}", "inputs", "identity_dh_private_key"),
        (f"x3dh-respond-{SESSION}", "inputs", "identity_dh_key"),
        (f"x3dh-initiate-{SESSION}", "inputs", "ephemeral_private_key"),
        (f"x3dh-respond-{SESSION}", "inputs", "ephemeral_key"),
        (f"x3dh-respond-{SESSION}", "inputs", "identity_key"),
        (f"x3dh-respond-{SESSION}", "inputs", "identity_dh_private_key"),
        (f"x3dh-initiate-{SESSION}", "inputs", "identity_dh_key"),
        (f"x3dh-initiate-{SESSION}", "inputs", "identity_dh_signature"),
        (f"x3dh-respond-{SESSION}", "inputs", "signed_prekey_private_key"),
        (f"x3dh-initiate-{SESSION}", "inputs", "signed_prekey_key"),
        (f"x3dh-initiate-{SESSION}", "inputs", "signed_prekey_signature"),
        (f"x3dh-respond-{SESSION}", "inputs", "one_time_prekey_private_key"),
        (f"x3dh-initiate-{SESSION}", "inputs", "one_time_prekey_key"),
        (f"x3dh-initiate-{SESSION}", "intermediates", "identity_dh_string"),
        (f"x3dh-initiate-{SESSION}", "intermediates", "signed_prekey_string"),
        (f"x3dh-initiate-{SESSION}", "intermediates", "dh1"),
        (f"x3dh-initiate-{SESSION}", "intermediates", "dh2"),
        (f"x3dh-initiate-{SESSION}", "intermediates", "dh3"),
        (f"x3dh-initiate-{SESSION}", "intermediates", "dh4"),
        (f"x3dh-initiate-{SESSION}", "intermediates", "input_key_material"),
        (f"x3dh-initiate-{SESSION}", "outputs", "sk"),
        (f"x3dh-initiate-{SESSION}", "outputs", "session_associated_data"),
    ],
    [
        (f"ratchet-init-initiator-{SESSION}", "inputs", "ratchet_private_key"),
        (f"ratchet-init-initiator-{SESSION}", "intermediates", "ratchet_key"),
        (f"ratchet-init-initiator-{SESSION}", "intermediates", "dh"),
        (f"ratchet-init-initiator-{SESSION}", "intermediates", "root_key"),
        (f"ratchet-init-initiator-{SESSION}", "intermediates", "chain_key"),
        ("ratchet-encrypt-i0", "intermediates", "message_key"),
        ("ratchet-encrypt-i0", "intermediates", "header"),
        ("ratchet-encrypt-i0", "inputs", "message_id"),
        ("ratchet-encrypt-i0", "inputs", "nonce"),
        ("ratchet-encrypt-i0", "inputs", "padded_plaintext"),
        ("ratchet-encrypt-i0", "intermediates", "associated_data"),
        ("ratchet-encrypt-i0", "outputs", "ciphertext"),
        (f"x3dh-respond-{SESSION}", "inputs", "identity_dh_key"),
        (f"x3dh-respond-{SESSION}", "inputs", "identity_dh_signature"),
        (f"x3dh-respond-{SESSION}", "inputs", "ephemeral_key"),
        (f"x3dh-respond-{SESSION}", "inputs", "signed_prekey_id"),
        (f"x3dh-respond-{SESSION}", "inputs", "one_time_prekey_id"),
    ],
    [
        ("ratchet-decrypt-i0-first-message", "inputs", "ratchet_private_key"),
        ("ratchet-decrypt-i0-first-message", "intermediates", "dh_receiving"),
        ("ratchet-decrypt-i0-first-message", "intermediates", "root_key_receiving"),
        ("ratchet-decrypt-i0-first-message", "intermediates", "chain_key_receiving"),
        ("ratchet-decrypt-i0-first-message", "intermediates", "ratchet_key"),
        ("ratchet-decrypt-i0-first-message", "intermediates", "dh_sending"),
        ("ratchet-decrypt-i0-first-message", "intermediates", "root_key_sending"),
        ("ratchet-decrypt-i0-first-message", "intermediates", "chain_key_sending"),
        ("ratchet-encrypt-r0", "intermediates", "message_key"),
        ("ratchet-encrypt-r0", "intermediates", "header"),
        ("ratchet-encrypt-r0", "inputs", "message_id"),
        ("ratchet-encrypt-r0", "inputs", "nonce"),
        ("ratchet-encrypt-r0", "inputs", "padded_plaintext"),
        ("ratchet-encrypt-r0", "intermediates", "associated_data"),
        ("ratchet-encrypt-r0", "outputs", "ciphertext"),
    ],
]


def name_of(vector: Vector) -> str:
    return vector["name"]


def section(number: str) -> str:
    start = PROTOCOL.index(f"\n### {number} ")
    end = PROTOCOL.index("\n##", start + 1)
    return PROTOCOL[start:end]


def hex_of(vector: Vector, key: str) -> bytes:
    return bytes.fromhex(vector["inputs"][key])


def entry_of(entry: SkippedKey) -> Fields:
    return {
        "ratchet_key": entry.ratchet_key.hex(),
        "number": entry.number,
        "message_key": entry.message_key.hex(),
        "step": entry.step,
    }


@cache
def conversation() -> dict[str, Step]:
    """Runs every vector through the core in the order of the file."""
    states: dict[str, RatchetState] = {}
    session_data: dict[str, bytes] = {}
    steps = {}
    for vector in VECTORS:
        inputs = vector["inputs"]
        match vector["operation"]:
            case "ratchet-init-initiator":
                states["initiator"] = init_initiator(
                    shared_secret=hex_of(vector, "sk"),
                    signed_prekey=hex_of(vector, "signed_prekey_key"),
                    ratchet_private_key=hex_of(vector, "ratchet_private_key"),
                )
                session_data["initiator"] = hex_of(vector, "session_associated_data")
                steps[vector["name"]] = Step(
                    before=None, after=states["initiator"], outputs={}
                )
            case "ratchet-init-responder":
                states["responder"] = init_responder(
                    shared_secret=hex_of(vector, "sk"),
                    signed_prekey_private_key=hex_of(vector, "signed_prekey_private_key"),
                )
                session_data["responder"] = hex_of(vector, "session_associated_data")
                steps[vector["name"]] = Step(
                    before=None, after=states["responder"], outputs={}
                )
            case "ratchet-encrypt" | "ratchet-decrypt":
                party = inputs["party"]
                before = states[party]
                associated_data = session_data[party] + hex_of(vector, "message_id")
                try:
                    step = run(vector, before, associated_data)
                except CryptoError as error:
                    step = Step(before=before, after=None, outputs={}, error=error.result)
                if step.after is not None:
                    states[party] = step.after
                steps[vector["name"]] = step
            case operation:
                raise NotImplementedError(f"{vector['name']}: no operation {operation!r}")
    return steps


def run(vector: Vector, before: RatchetState, associated_data: bytes) -> Step:
    inputs = vector["inputs"]
    if vector["operation"] == "ratchet-encrypt":
        encrypted = encrypt(
            before,
            hex_of(vector, "padded_plaintext"),
            associated_data=associated_data,
            nonce=hex_of(vector, "nonce"),
        )
        outputs: Fields = {"ciphertext": encrypted.ciphertext.hex()}
        return Step(
            before=before, after=encrypted.state, outputs=outputs, header=encrypted.header
        )

    random_bytes = inputs.get("ratchet_private_key", UNUSED_RANDOM_BYTES.hex())
    decrypted = decrypt(
        before,
        hex_of(vector, "header"),
        hex_of(vector, "ciphertext"),
        associated_data=associated_data,
        ratchet_private_key=bytes.fromhex(random_bytes),
    )
    outputs = {
        "padded_plaintext": decrypted.padded_plaintext.hex(),
        "purged_count": decrypted.purged,
    }
    return Step(
        before=before,
        after=decrypted.state,
        outputs=outputs,
        header=hex_of(vector, "header"),
    )


def operations_of_the_spec() -> dict[str, Operation]:
    operations = {}
    for name, cells in OPERATION_ROW.findall(section("15.7")):
        _rule, inputs, intermediates, outputs, errors = cells.split("|")
        operations[name] = Operation(
            inputs=frozenset(KEY_IN_A_CELL.findall(inputs)),
            intermediates=frozenset(KEY_IN_A_CELL.findall(intermediates)),
            outputs=frozenset(KEY_IN_A_CELL.findall(outputs)),
            errors=frozenset(RESULT_IN_A_CELL.findall(errors)),
        )
    return operations


def has_the_type_of_its_key(key: str, value: object) -> bool:
    if key == "party":
        return value in PARTIES
    if key in NUMBER_KEYS:
        return type(value) is int and value >= 0
    if key in ENTRY_LISTS:
        return type(value) is list and all(is_an_entry(entry) for entry in value)
    if type(value) is not str or LOWERCASE_HEX.fullmatch(value) is None:
        return False
    length = len(value) // 2
    if key == "padded_plaintext":
        return length > 0 and length % PADDING_BLOCK == 0
    if key == "ciphertext":
        return length > CIPHERTEXT_OVERHEAD
    return length == LENGTHS.get(key, KEY_LENGTH)


def is_an_entry(entry: object) -> bool:
    if type(entry) is not dict or entry.keys() != ENTRY_KEYS:
        return False
    has_numbers = type(entry["number"]) is int and type(entry["step"]) is int
    has_keys = all(
        has_the_type_of_its_key(key, entry[key]) for key in ("ratchet_key", "message_key")
    )
    return has_numbers and has_keys


def render_appendix_part(values: list[tuple[str, str, str]]) -> str:
    lines = []
    for name, part, key in values:
        vector = (X3DH | BY_NAME)[name]
        value = vector[part][key]
        lines.append(f"{name} {part}.{key}")
        if type(value) is int:
            lines.append(f"  {value}")
            continue
        lines += [
            f"  {value[start : start + HEX_PER_LINE]}"
            for start in range(0, len(value), HEX_PER_LINE)
        ]
    return "\n".join(lines) + "\n"


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
        inputs = vector["inputs"].keys()
        intermediates = vector["intermediates"].keys()
        assert operation.inputs - OPTIONAL <= inputs <= operation.inputs, vector["name"]
        if "error" in vector:
            assert not intermediates, vector["name"]
            continue
        takes_a_step = "ratchet_private_key" in inputs
        is_a_decryption = vector["operation"] == "ratchet-decrypt"
        assert operation.intermediates - OPTIONAL <= intermediates, vector["name"]
        assert intermediates <= operation.intermediates, vector["name"]
        assert vector["outputs"].keys() == operation.outputs, vector["name"]
        if is_a_decryption:
            assert (intermediates >= DH_RATCHET_STEP) is takes_a_step, vector["name"]
            assert DH_RATCHET_STEP.isdisjoint(intermediates) is not takes_a_step
    for name, operation in operations.items():
        errors = {vector["error"] for vector in NEGATIVE if vector["operation"] == name}
        assert errors == operation.errors, name


@pytest.mark.parametrize("vector", POSITIVE, ids=name_of)
def test_positive_vectors_replay_byte_for_byte(vector: Vector) -> None:
    step = conversation()[vector["name"]]

    assert step.error is None
    assert step.outputs == vector["outputs"]


@pytest.mark.parametrize("vector", NEGATIVE, ids=name_of)
def test_negative_vectors_raise_their_named_error(vector: Vector) -> None:
    assert conversation()[vector["name"]].error == vector["error"]


@pytest.mark.parametrize("vector", POSITIVE, ids=name_of)
def test_intermediates_are_the_values_of_the_core(vector: Vector) -> None:
    step = conversation()[vector["name"]]
    recorded = vector["intermediates"]
    assert step.after is not None
    computed: Fields = {}
    match vector["operation"]:
        case "ratchet-init-initiator":
            dh_output = dh(hex_of(vector, "ratchet_private_key"), step.after.dhr or b"")
            root_key, chain_key = kdf_rk(hex_of(vector, "sk"), dh_output)
            computed = {
                "ratchet_key": step.after.dhs_public_key.hex(),
                "dh": dh_output.hex(),
                "root_key": root_key.hex(),
                "chain_key": chain_key.hex(),
            }
            assert (root_key, chain_key) == (step.after.rk, step.after.cks)
        case "ratchet-init-responder":
            computed = {"ratchet_key": step.after.dhs_public_key.hex()}
        case "ratchet-encrypt":
            assert step.before is not None and step.before.cks is not None
            computed = {
                "chain_key": step.before.cks.hex(),
                "message_key": kdf_ck(step.before.cks)[0].hex(),
                "header": step.header.hex(),
                "associated_data": recorded["associated_data"],
            }
            assert bytes.fromhex(recorded["associated_data"])[177:] == step.header
        case "ratchet-decrypt":
            computed = intermediates_of_a_decryption(vector, step)

    assert computed == recorded


def intermediates_of_a_decryption(vector: Vector, step: Step) -> Fields:
    before, after, recorded = step.before, step.after, vector["intermediates"]
    assert before is not None and after is not None
    ratchet_key = step.header[:32]
    computed: Fields = {}
    if "ratchet_private_key" in vector["inputs"]:
        dh_receiving = dh(before.dhs_private_key, ratchet_key)
        root_key, chain_key = kdf_rk(before.rk, dh_receiving)
        dh_sending = dh(hex_of(vector, "ratchet_private_key"), ratchet_key)
        assert kdf_rk(root_key, dh_sending) == (after.rk, after.cks)
        computed = {
            "dh_receiving": dh_receiving.hex(),
            "root_key_receiving": root_key.hex(),
            "chain_key_receiving": chain_key.hex(),
            "ratchet_key": after.dhs_public_key.hex(),
            "dh_sending": dh_sending.hex(),
            "root_key_sending": after.rk.hex(),
            "chain_key_sending": (after.cks or b"").hex(),
        }

    removed = [entry for entry in before.mkskipped if entry not in after.mkskipped]
    used = [entry for entry in removed if entry.ratchet_key == ratchet_key]
    used = [entry for entry in used if entry.number == int.from_bytes(step.header[36:])]
    if used:
        message_key = used[0].message_key
    else:
        message_key, next_chain_key = kdf_ck(bytes.fromhex(recorded["chain_key"]))
        assert next_chain_key == after.ckr
        computed["chain_key"] = recorded["chain_key"]
    stored = [entry for entry in after.mkskipped if entry not in before.mkskipped]
    purged = [entry for entry in removed if entry not in used]
    return computed | {
        "message_key": message_key.hex(),
        "associated_data": recorded["associated_data"],
        "stored_skipped_keys": [entry_of(entry) for entry in stored],
        "purged_skipped_keys": [entry_of(entry) for entry in purged],
    }


def test_conversation_runs_on_the_session_of_the_x3dh_vectors() -> None:
    initiator = BY_NAME[f"ratchet-init-initiator-{SESSION}"]["inputs"]
    responder = BY_NAME[f"ratchet-init-responder-{SESSION}"]["inputs"]
    sent = X3DH[f"x3dh-initiate-{SESSION}"]
    received = X3DH[f"x3dh-respond-{SESSION}"]
    signed_prekey = derive_x25519_public_key(
        bytes.fromhex(responder["signed_prekey_private_key"])
    )

    assert initiator["sk"] == sent["outputs"]["sk"] == responder["sk"]
    for ratchet, agreement in ((initiator, sent), (responder, received)):
        session_data = agreement["outputs"]["session_associated_data"]
        assert ratchet["session_associated_data"] == session_data
    assert initiator["signed_prekey_key"] == signed_prekey.hex()
    held = received["inputs"]["signed_prekey_private_key"]
    assert responder["signed_prekey_private_key"] == held


def test_associated_data_is_the_session_data_the_message_id_and_the_header() -> None:
    session_data = {
        "initiator": BY_NAME[f"ratchet-init-initiator-{SESSION}"]["inputs"],
        "responder": BY_NAME[f"ratchet-init-responder-{SESSION}"]["inputs"],
    }
    for vector in POSITIVE:
        if vector["operation"] not in {"ratchet-encrypt", "ratchet-decrypt"}:
            continue
        inputs = vector["inputs"]
        header = inputs.get("header", vector["intermediates"].get("header"))
        expected = (
            session_data[inputs["party"]]["session_associated_data"]
            + inputs["message_id"]
            + header
        )
        assert vector["intermediates"]["associated_data"] == expected, vector["name"]


def test_appendix_a_is_taken_from_the_vector_files() -> None:
    appendix = PROTOCOL[PROTOCOL.index("\n## Appendix A.") :]

    assert APPENDIX_BLOCK.findall(appendix) == [
        render_appendix_part(part) for part in APPENDIX
    ]
