"""Recomputes every recorded value of vectors/x3dh.json without the core.

The values come from direct calls of the library in the order of docs/protocol.md,
sections 16.6 and 16.8, and from HKDF written out from RFC 5869 on the stdlib hmac.
"""

import ast
import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

type Vector = dict[str, Any]

ROOT = Path(__file__).parent.parent.parent
PROTOCOL = (ROOT / "docs" / "protocol.md").read_text(encoding="utf-8")
VECTORS: list[Vector] = json.loads(
    (ROOT / "vectors" / "x3dh.json").read_text(encoding="utf-8")
)["vectors"]
POSITIVE = [vector for vector in VECTORS if "outputs" in vector]
NEGATIVE = [vector for vector in VECTORS if "error" in vector]

TEXT_IN_THE_SPEC = re.compile(
    r"ASCII `(sotto/1 [a-z0-9-]+)`(?:, \d+ bytes)?, hex `([0-9a-f]+)`"
)
TEXTS: dict[str, str] = dict(TEXT_IN_THE_SPEC.findall(PROTOCOL))
LAYOUT_ROW = re.compile(r"^\| (\d+) +\| (\d+) +\| (\w+) +\|", re.MULTILINE)
TERMINATOR = "00"
VERSION = "01"
SALT = bytes(32)
F = "ff" * 32
SK_LENGTH = 32


def name_of(vector: Vector) -> str:
    return str(vector["name"])


def section(number: str) -> str:
    start = PROTOCOL.index(f"\n### {number} ")
    end = PROTOCOL.index("\n##", start + 1)
    return PROTOCOL[start:end]


def x25519(private_key: str, public_key: str) -> str:
    own_key = X25519PrivateKey.from_private_bytes(bytes.fromhex(private_key))
    peer_key = X25519PublicKey.from_public_bytes(bytes.fromhex(public_key))
    return own_key.exchange(peer_key).hex()


def public_key_of(private_key: str) -> str:
    own_key = X25519PrivateKey.from_private_bytes(bytes.fromhex(private_key))
    return own_key.public_key().public_bytes_raw().hex()


def hkdf_of_rfc_5869(
    salt: bytes, input_key_material: bytes, info: bytes, length: int
) -> bytes:
    pseudorandom_key = hmac.new(salt, input_key_material, hashlib.sha256).digest()

    output = b""
    block = b""
    counter = 0
    while len(output) < length:
        counter += 1
        message = block + info + bytes([counter])
        block = hmac.new(pseudorandom_key, message, hashlib.sha256).digest()
        output += block
    return output[:length]


def verified(signer: str, signature: str, signed_string: str) -> str:
    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer))
    public_key.verify(bytes.fromhex(signature), bytes.fromhex(signed_string))
    return signed_string


def identity_dh_string(signer: str, identity_dh_key: str) -> str:
    return TEXTS["sotto/1 identity-dh"] + TERMINATOR + signer + identity_dh_key


def signed_prekey_string(signer: str, signed_prekey: str) -> str:
    return TEXTS["sotto/1 signed-prekey"] + TERMINATOR + signer + signed_prekey


def checks_of_the_initiator(inputs: Vector) -> dict[str, str]:
    assert inputs["identity"] == inputs["contact_id"]
    return {
        "identity_dh_string": verified(
            inputs["identity"],
            inputs["identity_dh_signature"],
            identity_dh_string(inputs["identity"], inputs["identity_dh_key"]),
        ),
        "signed_prekey_string": verified(
            inputs["identity"],
            inputs["signed_prekey_signature"],
            signed_prekey_string(inputs["identity"], inputs["signed_prekey_key"]),
        ),
    }


def check_of_the_responder(inputs: Vector) -> dict[str, str]:
    return {
        "identity_dh_string": verified(
            inputs["sender"],
            inputs["identity_dh_signature"],
            identity_dh_string(inputs["sender"], inputs["identity_dh_key"]),
        ),
    }


def dh_values_of_the_initiator(inputs: Vector) -> list[str]:
    values = [
        x25519(inputs["identity_dh_private_key"], inputs["signed_prekey_key"]),
        x25519(inputs["ephemeral_private_key"], inputs["identity_dh_key"]),
        x25519(inputs["ephemeral_private_key"], inputs["signed_prekey_key"]),
    ]
    if "one_time_prekey_key" in inputs:
        values.append(x25519(inputs["ephemeral_private_key"], inputs["one_time_prekey_key"]))
    return values


def dh_values_of_the_responder(inputs: Vector) -> list[str]:
    values = [
        x25519(inputs["signed_prekey_private_key"], inputs["identity_dh_key"]),
        x25519(inputs["identity_dh_private_key"], inputs["ephemeral_key"]),
        x25519(inputs["signed_prekey_private_key"], inputs["ephemeral_key"]),
    ]
    if "one_time_prekey_id" in inputs:
        values.append(x25519(inputs["one_time_prekey_private_key"], inputs["ephemeral_key"]))
    return values


def key_derivation(dh_values: list[str]) -> dict[str, str]:
    input_key_material = F + "".join(dh_values)
    sk = hkdf_of_rfc_5869(
        SALT,
        bytes.fromhex(input_key_material),
        bytes.fromhex(TEXTS["sotto/1 x3dh"]),
        SK_LENGTH,
    )

    recomputed = {f"dh{number}": value for number, value in enumerate(dh_values, 1)}
    return recomputed | {"input_key_material": input_key_material, "sk": sk.hex()}


def recomputed(vector: Vector) -> dict[str, str]:
    inputs = vector["inputs"]
    match vector["operation"]:
        case "x3dh-initiate":
            checks = checks_of_the_initiator(inputs)
            keys = key_derivation(dh_values_of_the_initiator(inputs))
            initiator = inputs["identity_key"] + public_key_of(
                inputs["identity_dh_private_key"]
            )
            responder = inputs["identity"] + inputs["identity_dh_key"]
            ephemeral_key = public_key_of(inputs["ephemeral_private_key"])
        case "x3dh-respond":
            checks = check_of_the_responder(inputs)
            keys = key_derivation(dh_values_of_the_responder(inputs))
            initiator = inputs["sender"] + inputs["identity_dh_key"]
            responder = inputs["identity_key"] + public_key_of(
                inputs["identity_dh_private_key"]
            )
            ephemeral_key = inputs["ephemeral_key"]
        case operation:
            raise NotImplementedError(f"{vector['name']}: no operation {operation!r}")

    session_associated_data = VERSION + initiator + responder + ephemeral_key
    return checks | keys | {"session_associated_data": session_associated_data}


@pytest.mark.parametrize("vector", POSITIVE, ids=name_of)
def test_every_recorded_value_recomputes_without_the_core(vector: Vector) -> None:
    assert recomputed(vector) == vector["intermediates"] | vector["outputs"]


@pytest.mark.parametrize("vector", NEGATIVE, ids=name_of)
def test_zero_dh_vectors_pass_the_checks_and_hold_a_key_the_library_refuses(
    vector: Vector,
) -> None:
    inputs = vector["inputs"]
    match vector["operation"]:
        case "x3dh-initiate":
            checks = checks_of_the_initiator(inputs)
            compute = dh_values_of_the_initiator
        case "x3dh-respond":
            checks = check_of_the_responder(inputs)
            compute = dh_values_of_the_responder
        case operation:
            raise NotImplementedError(f"{vector['name']}: no operation {operation!r}")

    assert checks == vector["intermediates"]
    with pytest.raises(ValueError, match="Error computing shared key"):
        compute(inputs)


def test_hand_written_hkdf_gives_the_first_test_case_of_rfc_5869() -> None:
    output = hkdf_of_rfc_5869(
        bytes.fromhex("000102030405060708090a0b0c"),
        bytes.fromhex("0b" * 22),
        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        42,
    )

    assert output.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )


def test_document_and_vectors_agree_on_the_two_layouts() -> None:
    rows = [
        (int(offset), int(length), field)
        for offset, length, field in LAYOUT_ROW.findall(section("16.5"))
    ]
    fields = [field for _offset, _length, field in rows]
    end = 0
    for offset, length, _field in rows:
        assert offset == end
        end += length
    lengths = {len(vector["intermediates"]["input_key_material"]) // 2 for vector in POSITIVE}

    assert fields == ["version", "IKsig_A", "IKdh_A", "IKsig_B", "IKdh_B", "EK_A"]
    assert end == 161
    assert "Total length: 161 bytes." in section("16.5")
    assert bytes.fromhex(TEXTS["sotto/1 x3dh"]) == b"sotto/1 x3dh"
    assert lengths == {128, 160}
    assert "160 bytes" in section("16.4") and "128 bytes" in section("16.4")
    for vector in POSITIVE:
        assert len(vector["outputs"]["session_associated_data"]) // 2 == end


def test_this_file_does_not_import_the_core() -> None:
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
        if isinstance(node, ast.ImportFrom):
            imported.add(str(node.module))

    assert not any(module.partition(".")[0] == "sotto" for module in imported)
