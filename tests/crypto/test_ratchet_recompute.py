"""Recomputes every recorded value of vectors/ratchet.json without the core.

The conversation is run a second time from the inputs, in the order of the text of
docs/protocol.md, sections 17 and 18: X25519 and ChaCha20-Poly1305 by direct calls of the
library, HMAC by the stdlib hmac and HKDF written out from RFC 5869 on it.
"""

import ast
import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

type Vector = dict[str, Any]
type Fields = dict[str, Any]

ROOT = Path(__file__).parent.parent.parent
PROTOCOL = (ROOT / "docs" / "protocol.md").read_text(encoding="utf-8")
VECTORS: list[Vector] = json.loads(
    (ROOT / "vectors" / "ratchet.json").read_text(encoding="utf-8")
)["vectors"]
POSITIVE = [vector for vector in VECTORS if "outputs" in vector]

TEXT_IN_THE_SPEC = re.compile(
    r"ASCII `(sotto/1 [a-z0-9-]+)`(?:, \d+ bytes)?, hex `([0-9a-f]+)`"
)
TEXTS: dict[str, str] = dict(TEXT_IN_THE_SPEC.findall(PROTOCOL))
LAYOUT_ROW = re.compile(r"^\| (\d+) +\| (\d+) +\| ([\w ]+?) +\|", re.MULTILINE)
WIRE_ROW = re.compile(r"^\| ([0-9L +]+?) +\| (\w+) +\| (\w+) +\|", re.MULTILINE)
CONSTANT_ROW = re.compile(r"^\| (\w+) +\| (\d+) +\|", re.MULTILINE)
MESSAGE_KEY_BYTE = b"\x01"
CHAIN_KEY_BYTE = b"\x02"
MAX_SKIP = 1000
SKIPPED_KEYS_CAP = 2000
SKIPPED_KEY_STEPS = 5
NONCE_LENGTH = 12


@dataclass(slots=True, kw_only=True)
class Side:
    """The variables of section 17.2, kept as hex strings and numbers."""

    session_associated_data: str
    dhs_private: str
    dhs_public: str
    dhr: str | None
    rk: str
    cks: str | None = None
    ckr: str | None = None
    ns: int = 0
    nr: int = 0
    pn: int = 0
    dhsteps: int = 0
    skipped: dict[tuple[str, int], Fields] = field(default_factory=dict)


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


def root_step(root: str, dh_output: str) -> tuple[str, str]:
    """KDF_RK of section 17.4."""
    info = bytes.fromhex(TEXTS["sotto/1 ratchet"])
    output = hkdf_of_rfc_5869(bytes.fromhex(root), bytes.fromhex(dh_output), info, 64)
    return output[:32].hex(), output[32:].hex()


def chain_step(chain: str) -> tuple[str, str]:
    """KDF_CK of section 17.4: the message key and the next chain key."""
    chain_bytes = bytes.fromhex(chain)
    message = hmac.new(chain_bytes, MESSAGE_KEY_BYTE, hashlib.sha256).hexdigest()
    return message, hmac.new(chain_bytes, CHAIN_KEY_BYTE, hashlib.sha256).hexdigest()


def skip_one(side: Side, stored: list[Fields], purged: list[Fields]) -> None:
    """Section 17.8."""
    assert side.ckr is not None and side.dhr is not None
    message_key, side.ckr = chain_step(side.ckr)
    entry = {"ratchet_key": side.dhr, "number": side.nr, "message_key": message_key}
    entry["step"] = side.dhsteps
    pair = (side.dhr, side.nr)
    side.skipped.pop(pair, None)
    if len(side.skipped) == SKIPPED_KEYS_CAP:
        purged.append(side.skipped.pop(next(iter(side.skipped))))
    side.skipped[pair] = entry
    stored.append(entry)
    side.nr += 1


def initialise_initiator(vector: Vector) -> tuple[Side, Fields]:
    inputs = vector["inputs"]
    ratchet_key = public_key_of(inputs["ratchet_private_key"])
    dh_output = x25519(inputs["ratchet_private_key"], inputs["signed_prekey_key"])
    root, chain = root_step(inputs["sk"], dh_output)
    side = Side(
        session_associated_data=inputs["session_associated_data"],
        dhs_private=inputs["ratchet_private_key"],
        dhs_public=ratchet_key,
        dhr=inputs["signed_prekey_key"],
        rk=root,
        cks=chain,
    )
    recorded = {"ratchet_key": ratchet_key, "dh": dh_output, "root_key": root}
    return side, recorded | {"chain_key": chain}


def initialise_responder(vector: Vector) -> tuple[Side, Fields]:
    inputs = vector["inputs"]
    ratchet_key = public_key_of(inputs["signed_prekey_private_key"])
    side = Side(
        session_associated_data=inputs["session_associated_data"],
        dhs_private=inputs["signed_prekey_private_key"],
        dhs_public=ratchet_key,
        dhr=None,
        rk=inputs["sk"],
    )
    return side, {"ratchet_key": ratchet_key}


def encrypt(side: Side, vector: Vector) -> Fields:
    """Section 17.6, steps 2 to 5, and section 18."""
    inputs = vector["inputs"]
    assert side.cks is not None
    chain_key = side.cks
    message_key, side.cks = chain_step(chain_key)
    numbers = side.pn.to_bytes(4, "big") + side.ns.to_bytes(4, "big")
    header = side.dhs_public + numbers.hex()
    side.ns += 1
    associated_data = side.session_associated_data + inputs["message_id"] + header
    sealed = ChaCha20Poly1305(bytes.fromhex(message_key)).encrypt(
        bytes.fromhex(inputs["nonce"]),
        bytes.fromhex(inputs["padded_plaintext"]),
        bytes.fromhex(associated_data),
    )

    return {
        "chain_key": chain_key,
        "message_key": message_key,
        "header": header,
        "associated_data": associated_data,
        "ciphertext": inputs["nonce"] + sealed.hex(),
    }


def decrypt(side: Side, vector: Vector) -> Fields:
    """Section 17.7, steps 2 and 5 to 9, for a message that decrypts."""
    inputs = vector["inputs"]
    header = inputs["header"]
    ratchet_key = header[:64]
    previous_count = int(header[64:72], 16)
    number = int(header[72:], 16)
    recomputed: Fields = {}
    stored: list[Fields] = []
    purged: list[Fields] = []

    used = side.skipped.pop((ratchet_key, number), None)
    if used is not None:
        message_key = used["message_key"]
    else:
        if ratchet_key != side.dhr:
            if side.ckr is not None:
                while side.nr < previous_count:
                    skip_one(side, stored, purged)
            side.pn, side.ns, side.nr, side.dhr = side.ns, 0, 0, ratchet_key
            dh_receiving = x25519(side.dhs_private, ratchet_key)
            side.rk, side.ckr = root_step(side.rk, dh_receiving)
            receiving = {"root_key_receiving": side.rk, "chain_key_receiving": side.ckr}
            side.dhs_private = inputs["ratchet_private_key"]
            side.dhs_public = public_key_of(side.dhs_private)
            dh_sending = x25519(side.dhs_private, ratchet_key)
            side.rk, side.cks = root_step(side.rk, dh_sending)
            side.dhsteps += 1
            for pair, entry in list(side.skipped.items()):
                if entry["step"] + SKIPPED_KEY_STEPS <= side.dhsteps:
                    purged.append(side.skipped.pop(pair))
            recomputed |= receiving | {
                "dh_receiving": dh_receiving,
                "ratchet_key": side.dhs_public,
                "dh_sending": dh_sending,
                "root_key_sending": side.rk,
                "chain_key_sending": side.cks,
            }
        while side.nr < number:
            skip_one(side, stored, purged)
        assert side.ckr is not None
        recomputed["chain_key"] = side.ckr
        message_key, side.ckr = chain_step(side.ckr)
        side.nr += 1

    associated_data = side.session_associated_data + inputs["message_id"] + header
    ciphertext = bytes.fromhex(inputs["ciphertext"])
    plaintext = ChaCha20Poly1305(bytes.fromhex(message_key)).decrypt(
        ciphertext[:NONCE_LENGTH], ciphertext[NONCE_LENGTH:], bytes.fromhex(associated_data)
    )
    return recomputed | {
        "message_key": message_key,
        "associated_data": associated_data,
        "stored_skipped_keys": stored,
        "purged_skipped_keys": purged,
        "padded_plaintext": plaintext.hex(),
        "purged_count": len(purged),
    }


@cache
def recomputed_conversation() -> dict[str, Fields]:
    sides: dict[str, Side] = {}
    recomputed = {}
    for vector in POSITIVE:
        match vector["operation"]:
            case "ratchet-init-initiator":
                sides["initiator"], values = initialise_initiator(vector)
            case "ratchet-init-responder":
                sides["responder"], values = initialise_responder(vector)
            case "ratchet-encrypt":
                values = encrypt(sides[vector["inputs"]["party"]], vector)
            case "ratchet-decrypt":
                values = decrypt(sides[vector["inputs"]["party"]], vector)
            case operation:
                raise NotImplementedError(f"{vector['name']}: no operation {operation!r}")
        recomputed[vector["name"]] = values
    return recomputed


@pytest.mark.parametrize("vector", POSITIVE, ids=name_of)
def test_every_recorded_value_recomputes_without_the_core(vector: Vector) -> None:
    recorded = vector["intermediates"] | vector["outputs"]

    assert recomputed_conversation()[vector["name"]] == recorded


def test_document_and_vectors_agree_on_the_layouts() -> None:
    header = [(int(o), int(n), f) for o, n, f in LAYOUT_ROW.findall(section("17.5"))]
    associated_data = [(int(o), int(n), f) for o, n, f in LAYOUT_ROW.findall(section("18.2"))]
    wire = WIRE_ROW.findall(section("18.3"))
    constants = dict(CONSTANT_ROW.findall(section("24.1")))
    encryptions = [vector for vector in POSITIVE if vector["operation"] == "ratchet-encrypt"]

    assert header == [(0, 32, "DH"), (32, 4, "PN"), (36, 4, "N")]
    assert "Total length: 40 bytes." in section("17.5")
    assert [length for _offset, length, _field in associated_data] == [161, 16, 40]
    assert "Total length: 217 bytes" in section("18.2")
    assert wire == [("0", "12", "Nonce"), ("12", "L", "Ciphertext"), ("12 + L", "16", "Tag")]
    assert bytes.fromhex(TEXTS["sotto/1 ratchet"]) == b"sotto/1 ratchet"
    assert TEXTS["sotto/1 ratchet"] != TEXTS["sotto/1 x3dh"]
    assert {name: int(value) for name, value in constants.items() if "SKIP" in name} == {
        "MAX_SKIP": MAX_SKIP,
        "SKIPPED_KEYS_CAP": SKIPPED_KEYS_CAP,
        "SKIPPED_KEY_STEPS": SKIPPED_KEY_STEPS,
    }
    for vector in encryptions:
        length = len(vector["inputs"]["padded_plaintext"]) // 2
        assert len(vector["outputs"]["ciphertext"]) // 2 == length + 28
        assert len(vector["intermediates"]["associated_data"]) // 2 == 217


def test_this_file_does_not_import_the_core() -> None:
    tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
        if isinstance(node, ast.ImportFrom):
            imported.add(str(node.module))

    assert not any(module.partition(".")[0] == "sotto" for module in imported)
