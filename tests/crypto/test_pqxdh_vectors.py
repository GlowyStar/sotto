"""Replays vectors/pqxdh.json through the core and recomputes it from the primitives alone
(docs/protocol.md, section 43)."""

import json
import re
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from sotto.crypto.identity import (
    Bundle,
    CryptoError,
    OneTimePrekey,
    SignedPrekey,
    decode_user_id,
    derive_x25519_public_key,
)
from sotto.crypto.pqxdh import Encapsulation, initiate, kem_public_key, respond

type Vector = dict[str, Any]

ROOT = Path(__file__).parent.parent.parent
PROTOCOL = (ROOT / "docs" / "protocol.md").read_text(encoding="utf-8")
DOCUMENT = json.loads((ROOT / "vectors" / "pqxdh.json").read_text(encoding="utf-8"))
VECTORS: list[Vector] = DOCUMENT["vectors"]
BY_NAME = {vector["name"]: vector for vector in VECTORS}
POSITIVE = [vector for vector in VECTORS if "outputs" in vector]
NEGATIVE = [vector for vector in VECTORS if "error" in vector]

OPERATION_ROW = re.compile(r"^\| `([a-z0-9-]+)` \|(.*)\|$", re.MULTILINE)
KEY_IN_A_CELL = re.compile(r"`(\w+)`")
KEY_MATERIAL_PREFIX = b"\xff" * 32
INFO = b"sotto/2 pqxdh_CURVE25519_SHA-256_ML-KEM-768"
OPTIONAL_KEYS = {
    "one_time_prekey_id",
    "one_time_prekey_key",
    "one_time_prekey_private_key",
    "dh4",
    "pq_prekey_id",
    "pq_prekey_key",
    "pq_prekey_signature",
    "pq_prekey_string",
    "kem_randomness",
    "kem_ciphertext",
    "kem_shared_secret",
}
PAIRS = ["with-one-time-prekeys", "with-the-last-resort-pq-prekey"]


def name_of(vector: Vector) -> str:
    return str(vector["name"])


def hex_of(fields: dict[str, Any], key: str) -> bytes:
    return bytes.fromhex(fields[key])


def bundle_of(inputs: dict[str, Any]) -> Bundle:
    one_time_prekey = None
    if "one_time_prekey_id" in inputs:
        one_time_prekey = OneTimePrekey(
            id=inputs["one_time_prekey_id"], key=hex_of(inputs, "one_time_prekey_key")
        )
    pq_prekey = None
    if "pq_prekey_id" in inputs:
        pq_prekey = SignedPrekey(
            id=inputs["pq_prekey_id"],
            key=hex_of(inputs, "pq_prekey_key"),
            signature=hex_of(inputs, "pq_prekey_signature"),
        )
    return Bundle(
        identity=hex_of(inputs, "identity"),
        identity_dh_key=hex_of(inputs, "identity_dh_key"),
        identity_dh_signature=hex_of(inputs, "identity_dh_signature"),
        signed_prekey=SignedPrekey(
            id=inputs["signed_prekey_id"],
            key=hex_of(inputs, "signed_prekey_key"),
            signature=hex_of(inputs, "signed_prekey_signature"),
        ),
        one_time_prekey=one_time_prekey,
        pq_prekey=pq_prekey,
    )


def run(vector: Vector) -> dict[str, Any]:
    """The operation of a vector through the core; the encapsulation is the recorded one."""
    inputs = vector["inputs"]
    match vector["operation"]:
        case "mlkem768-public-key":
            return {"public_key": kem_public_key(hex_of(inputs, "seed")).hex()}
        case "pqxdh-initiate":
            encapsulation = None
            if "kem_ciphertext" in inputs:
                encapsulation = Encapsulation(
                    ciphertext=hex_of(inputs, "kem_ciphertext"),
                    shared_secret=hex_of(inputs, "kem_shared_secret"),
                )

            def recorded(_: object) -> Encapsulation:
                assert encapsulation is not None
                return encapsulation

            ephemeral_private_key = hex_of(inputs, "ephemeral_private_key")
            bundle = bundle_of(inputs)
            agreement = initiate(
                bundle,
                identity_key=hex_of(inputs, "identity_key"),
                identity_dh_private_key=hex_of(inputs, "identity_dh_private_key"),
                ephemeral_private_key=ephemeral_private_key,
                contact_identity_key=decode_user_id(inputs["contact_id"]),
                pinned_identity_dh_key=None,
                encapsulate=recorded,
            )
            header: dict[str, Any] = {
                "identity_dh_key": derive_x25519_public_key(
                    hex_of(inputs, "identity_dh_private_key")
                ).hex(),
                "ephemeral_key": derive_x25519_public_key(ephemeral_private_key).hex(),
                "signed_prekey_id": bundle.signed_prekey.id,
                "pq_prekey_id": agreement.pq_prekey_id,
                "kem_ciphertext": agreement.kem_ciphertext.hex(),
            }
            if bundle.one_time_prekey is not None:
                header["one_time_prekey_id"] = bundle.one_time_prekey.id
            return {
                "sk": agreement.shared_secret.hex(),
                "session_associated_data": agreement.associated_data.hex(),
                "initial_header": header,
            }
        case "pqxdh-respond":
            one_time_prekey_private_key = None
            if "one_time_prekey_private_key" in inputs:
                one_time_prekey_private_key = hex_of(inputs, "one_time_prekey_private_key")
            responded = respond(
                identity_key=hex_of(inputs, "identity_key"),
                identity_dh_private_key=hex_of(inputs, "identity_dh_private_key"),
                signed_prekey_private_key=hex_of(inputs, "signed_prekey_private_key"),
                one_time_prekey_private_key=one_time_prekey_private_key,
                pq_prekey_seed=hex_of(inputs, "pq_prekey_seed"),
                sender_identity_key=hex_of(inputs, "sender"),
                sender_identity_dh_key=hex_of(inputs, "identity_dh_key"),
                sender_identity_dh_signature=hex_of(inputs, "identity_dh_signature"),
                ephemeral_key=hex_of(inputs, "ephemeral_key"),
                kem_ciphertext=hex_of(inputs, "kem_ciphertext"),
                pinned_identity_dh_key=None,
            )
            return {
                "sk": responded.shared_secret.hex(),
                "session_associated_data": responded.associated_data.hex(),
            }
    raise NotImplementedError(f"the operation {vector['operation']} is not implemented")


def test_file_has_the_schema_and_unique_names() -> None:
    assert DOCUMENT["schema"] == 1
    assert len(BY_NAME) == len(VECTORS)
    assert all(("outputs" in vector) != ("error" in vector) for vector in VECTORS)


@pytest.mark.parametrize("vector", POSITIVE, ids=name_of)
def test_positive_vectors_replay_byte_for_byte(vector: Vector) -> None:
    assert run(vector) == vector["outputs"]


@pytest.mark.parametrize("vector", NEGATIVE, ids=name_of)
def test_negative_vectors_raise_their_named_error(vector: Vector) -> None:
    with pytest.raises(CryptoError) as raised:
        run(vector)

    assert raised.value.result == vector["error"]


def test_vectors_use_the_operations_and_keys_of_the_document() -> None:
    start = PROTOCOL.index("\n### 43.1 ")
    table = PROTOCOL[start : PROTOCOL.index("\n### 43.2 ", start)]
    documented = {}
    for operation, cells in OPERATION_ROW.findall(table):
        _, inputs, intermediates, outputs, errors = cells.split("|")[:5]
        documented[operation] = (
            set(KEY_IN_A_CELL.findall(inputs)),
            set(KEY_IN_A_CELL.findall(intermediates)),
            set(KEY_IN_A_CELL.findall(outputs)),
            set(errors.replace(",", " ").split()),
        )

    for vector in VECTORS:
        inputs, intermediates, outputs, errors = documented[vector["operation"]]
        assert set(vector["inputs"]) <= inputs
        assert inputs - set(vector["inputs"]) <= OPTIONAL_KEYS
        assert set(vector["intermediates"]) <= intermediates
        if "error" in vector:
            assert vector["error"] in errors
        else:
            assert intermediates - set(vector["intermediates"]) <= OPTIONAL_KEYS
            assert set(vector["outputs"]) == outputs


@pytest.mark.parametrize("case", PAIRS)
def test_vectors_of_one_name_are_the_two_sides_of_one_key_agreement(case: str) -> None:
    initiated = BY_NAME[f"pqxdh-initiate-{case}"]
    responded = BY_NAME[f"pqxdh-respond-{case}"]
    header = initiated["outputs"]["initial_header"]
    seed = hex_of(responded["inputs"], "pq_prekey_seed")

    assert kem_public_key(seed).hex() == initiated["inputs"]["pq_prekey_key"]
    for key in ("ephemeral_key", "kem_ciphertext", "signed_prekey_id", "pq_prekey_id"):
        assert responded["inputs"][key] == header[key]
    assert responded["outputs"] == {
        key: initiated["outputs"][key] for key in ("sk", "session_associated_data")
    }


@pytest.mark.parametrize("case", ["replaced-kem-ciphertext", "wrong-pq-prekey"])
def test_another_ciphertext_or_key_gives_another_secret_under_the_same_data(case: str) -> None:
    honest = BY_NAME["pqxdh-respond-with-one-time-prekeys"]
    changed = BY_NAME[f"pqxdh-respond-{case}"]
    dh_outputs = ("dh1", "dh2", "dh3", "dh4")

    assert changed["outputs"]["sk"] != honest["outputs"]["sk"]
    assert (
        changed["outputs"]["session_associated_data"]
        == honest["outputs"]["session_associated_data"]
    )
    assert [changed["intermediates"][key] for key in dh_outputs] == [
        honest["intermediates"][key] for key in dh_outputs
    ]


@pytest.mark.parametrize("vector", POSITIVE, ids=name_of)
def test_every_recorded_value_recomputes_without_the_core(vector: Vector) -> None:
    inputs, intermediates = vector["inputs"], vector["intermediates"]
    if vector["operation"] == "mlkem768-public-key":
        private_key = MLKEM768PrivateKey.from_seed_bytes(hex_of(inputs, "seed"))
        assert (
            private_key.public_key().public_bytes_raw().hex()
            == (vector["outputs"]["public_key"])
        )
        return

    if vector["operation"] == "pqxdh-respond":
        private_key = MLKEM768PrivateKey.from_seed_bytes(hex_of(inputs, "pq_prekey_seed"))
        shared_secret = private_key.decapsulate(hex_of(inputs, "kem_ciphertext"))
        assert shared_secret.hex() == intermediates["kem_shared_secret"]
    else:
        assert inputs["kem_shared_secret"] == intermediates["kem_shared_secret"]

    dh_outputs = [
        intermediates[key] for key in ("dh1", "dh2", "dh3", "dh4") if key in intermediates
    ]
    key_material = (
        KEY_MATERIAL_PREFIX.hex() + "".join(dh_outputs) + intermediates["kem_shared_secret"]
    )
    assert key_material == intermediates["input_key_material"]
    if vector["operation"] == "pqxdh-initiate":
        ephemeral_private_key = hex_of(inputs, "ephemeral_private_key")
        ephemeral = X25519PrivateKey.from_private_bytes(ephemeral_private_key)
        prekey = X25519PublicKey.from_public_bytes(hex_of(inputs, "signed_prekey_key"))
        assert ephemeral.exchange(prekey).hex() == intermediates["dh3"]
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes(32), info=INFO)
    assert hkdf.derive(bytes.fromhex(key_material)).hex() == vector["outputs"]["sk"]
    assert vector["outputs"]["session_associated_data"].startswith("02")
