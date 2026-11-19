"""The safety number of docs/protocol.md, section 44: libsignal's numeric fingerprint of
two identity keys, and the text of its QR code."""

import hashlib

from sotto.crypto.identity import encode_user_id

FINGERPRINT_VERSION = b"\x00\x00"
ITERATIONS = 5200
CHUNK_BYTES = 5
CHUNKS = 6
CHUNK_MODULUS = 100000
SCANNED_BYTES = 32
QR_PREFIX = "sotto-safety-number-1"


def fingerprint(key: bytes, stable_identifier: bytes) -> bytes:
    """The 64 bytes of one side: SHA-512 iterated as libsignal's `get_fingerprint`."""
    digest = hashlib.sha512(FINGERPRINT_VERSION + key + stable_identifier + key).digest()
    for _ in range(ITERATIONS - 1):
        digest = hashlib.sha512(digest + key).digest()
    return digest


def identity_fingerprint(identity_key: bytes) -> bytes:
    """The fingerprint of an identity key, its user id as the stable identifier (44.2)."""
    return fingerprint(identity_key, encode_user_id(identity_key).encode("ascii"))


def digits(fingerprint: bytes) -> str:
    """The 30 digits of one side (section 44.3)."""
    groups = []
    for start in range(0, CHUNKS * CHUNK_BYTES, CHUNK_BYTES):
        chunk = int.from_bytes(fingerprint[start : start + CHUNK_BYTES], "big")
        groups.append(f"{chunk % CHUNK_MODULUS:05}")
    return "".join(groups)


def safety_number(identity_key: bytes, contact_identity_key: bytes) -> str:
    """The 60 digits that the user and the contact both compute (section 44.3)."""
    halves = (identity_fingerprint(identity_key), identity_fingerprint(contact_identity_key))
    return "".join(sorted(digits(half) for half in halves))


def qr_payload(identity_key: bytes, contact_identity_key: bytes) -> str:
    """The text the QR code of the user's side carries, its own half first (44.4)."""
    own = identity_fingerprint(identity_key)[:SCANNED_BYTES]
    contact = identity_fingerprint(contact_identity_key)[:SCANNED_BYTES]
    return f"{QR_PREFIX} {own.hex()} {contact.hex()}"
