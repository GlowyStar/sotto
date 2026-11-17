"""The blob cipher of docs/protocol.md, section 29: the age v1 payload of a padded file.

Pure code without input or output: the file key and the nonce are arguments, and a blob
that fails to open raises BadBlobError and returns no byte of the file.
"""

import hashlib
import math

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from sotto.crypto.identity import CryptoError

MAX_FILE_BYTES = 104857600
FILE_PADDING_MIN = 256
STREAM_CHUNK_BYTES = 65536
FILE_KEY_LENGTH = 16
BLOB_NONCE_LENGTH = 16
DIGEST_LENGTH = 32
PAYLOAD_KEY_LENGTH = 32
PAYLOAD_INFO = b"payload"
CHUNK_TAG_LENGTH = 16
SEALED_CHUNK_BYTES = STREAM_CHUNK_BYTES + CHUNK_TAG_LENGTH
COUNTER_LENGTH = 11
LAST_CHUNK = b"\x01"
OTHER_CHUNK = b"\x00"


class BadBlobError(CryptoError):
    result = "BAD_BLOB"


def padded_length(size: int) -> int:
    """P of section 29.2: the Padme function of max(size, FILE_PADDING_MIN)."""
    length = max(size, FILE_PADDING_MIN)
    exponent = length.bit_length() - 1
    size_bits = exponent.bit_length()
    mask = (1 << (exponent - size_bits)) - 1
    return (length + mask) & ~mask


def chunk_count(size: int) -> int:
    """n of section 29.4: the chunks of the padded file."""
    return math.ceil(padded_length(size) / STREAM_CHUNK_BYTES)


def blob_length(size: int) -> int:
    """B of section 29.5: the nonce, the padded file and a tag for each chunk."""
    return BLOB_NONCE_LENGTH + padded_length(size) + CHUNK_TAG_LENGTH * chunk_count(size)


def payload_key(file_key: bytes, nonce: bytes) -> bytes:
    """The payload key of section 29.3."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(), length=PAYLOAD_KEY_LENGTH, salt=nonce, info=PAYLOAD_INFO
    )
    return hkdf.derive(file_key)


def chunk_nonces(count: int) -> list[bytes]:
    """The nonces of section 29.4 for `count` chunks, in their order."""
    return [
        index.to_bytes(COUNTER_LENGTH) + (LAST_CHUNK if index == count - 1 else OTHER_CHUNK)
        for index in range(count)
    ]


def digest_of(blob: bytes) -> bytes:
    """The digest of section 29.6."""
    return hashlib.sha256(blob).digest()


def encrypt_blob(file: bytes, *, file_key: bytes, nonce: bytes) -> bytes:
    """The blob of section 29.5; a new file key and nonce for every blob (section 29.1).

    Raises:
        ValueError: The file is longer than MAX_FILE_BYTES, or a key or nonce is not
            16 bytes.
    """
    if len(file) > MAX_FILE_BYTES:
        raise ValueError(f"the file is {len(file)} bytes long, above {MAX_FILE_BYTES}")
    if len(file_key) != FILE_KEY_LENGTH or len(nonce) != BLOB_NONCE_LENGTH:
        raise ValueError("the file key and the nonce are 16 bytes each")

    plaintext = file.ljust(padded_length(len(file)), b"\x00")
    cipher = ChaCha20Poly1305(payload_key(file_key, nonce))
    nonces = chunk_nonces(chunk_count(len(file)))
    sealed = [
        cipher.encrypt(chunk_nonce, plaintext[start : start + STREAM_CHUNK_BYTES], None)
        for start, chunk_nonce in zip(
            range(0, len(plaintext), STREAM_CHUNK_BYTES), nonces, strict=True
        )
    ]
    return nonce + b"".join(sealed)


def open_blob(blob: bytes, *, file_key: bytes, size: int, digest: bytes) -> bytes:
    """Returns the file of a blob by the six steps of section 29.7.

    Raises:
        BadBlobError: A step failed; no byte of the file is returned.
    """
    is_beyond_the_largest = size > MAX_FILE_BYTES
    has_another_length = len(blob) != blob_length(size)
    if is_beyond_the_largest or has_another_length:
        raise BadBlobError("the blob does not have the length of its size")
    if digest_of(blob) != digest:
        raise BadBlobError("the blob does not have its digest")

    cipher = ChaCha20Poly1305(payload_key(file_key, blob[:BLOB_NONCE_LENGTH]))
    starts = range(BLOB_NONCE_LENGTH, len(blob), SEALED_CHUNK_BYTES)
    nonces = chunk_nonces(chunk_count(size))
    try:
        plaintext = b"".join(
            cipher.decrypt(chunk_nonce, blob[start : start + SEALED_CHUNK_BYTES], None)
            for start, chunk_nonce in zip(starts, nonces, strict=True)
        )
    except InvalidTag as error:
        raise BadBlobError("a chunk of the blob does not verify") from error

    if plaintext[size:] != bytes(len(plaintext) - size):
        raise BadBlobError("the padding of the blob is not zero bytes")
    return plaintext[:size]
