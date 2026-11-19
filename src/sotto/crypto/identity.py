"""The identity core of docs/protocol.md: sections 3, 4 and 5.4, steps 4 and 5 of 8.3."""

import re
from dataclasses import dataclass, field
from typing import ClassVar, NamedTuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

KEY_LENGTH = 32
NONCE_LENGTH = 32
SIGNATURE_LENGTH = 64
KEM_PUBLIC_KEY_LENGTH = 1184
LONGEST_SERVER_NAME = 255

LOGIN_PREFIX = b"sotto/1 login"
IDENTITY_DH_PREFIX = b"sotto/1 identity-dh"
SIGNED_PREKEY_PREFIX = b"sotto/1 signed-prekey"
PQ_PREKEY_PREFIX = b"sotto/1 ml-kem-768-prekey"
PREFIX_END = b"\x00"

USER_ID = re.compile(r"[0-9a-f]{64}")
TOP_BIT_CLEARED = 0x7F
FIELD_PRIME = bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
# Chalkias, Garillot, Nikolaenko, "Taming the many EdDSAs", IACR ePrint 2020/1244,
# table 1: the points of small order, each with the top bit of the last byte cleared.
SMALL_ORDER = frozenset(
    bytes.fromhex(encoding)
    for encoding in (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    )
)


class CryptoError(Exception):
    """A check ended in the named result of docs/protocol.md, section 11.4, in `result`."""

    result: ClassVar[str]


class InvalidIdError(CryptoError):
    result = "INVALID_ID"


class BadBundleError(CryptoError):
    result = "BAD_BUNDLE"


class IdentityKeyMismatchError(CryptoError):
    result = "IDENTITY_KEY_MISMATCH"


class LoginRefusedError(CryptoError):
    result = "LOGIN_REFUSED"


class PqPrekeyMissingError(CryptoError):
    result = "PQ_PREKEY_MISSING"


@dataclass(frozen=True, slots=True, kw_only=True)
class SignedPrekey:
    id: int
    key: bytes
    signature: bytes = field(compare=False)


@dataclass(frozen=True, slots=True, kw_only=True)
class OneTimePrekey:
    id: int
    key: bytes


@dataclass(frozen=True, slots=True, kw_only=True)
class Bundle:
    """A fetched bundle, field for field the Bundle frame of section 7.11."""

    identity: bytes
    identity_dh_key: bytes
    identity_dh_signature: bytes = field(compare=False)
    signed_prekey: SignedPrekey
    one_time_prekey: OneTimePrekey | None
    pq_prekey: SignedPrekey | None = None


class CheckedPqPrekey(NamedTuple):
    public_key: MLKEM768PublicKey
    prekey_id: int


def derive_identity_key(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()


def derive_x25519_public_key(private_key: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes_raw()


def encode_user_id(identity_key: bytes) -> str:
    _require_length("identity_key", identity_key, KEY_LENGTH)
    return identity_key.hex()


def decode_user_id(user_id: str) -> bytes:
    """Returns the identity key of a user id by the four steps of section 3.3.

    Raises:
        InvalidIdError: The string is not a user id.
    """
    if USER_ID.fullmatch(user_id) is None:
        raise InvalidIdError("the id is not 64 characters of 0123456789abcdef")

    identity_key = bytes.fromhex(user_id)
    if _is_excluded(identity_key):
        raise InvalidIdError("the id holds a non-canonical key or a key of small order")
    return identity_key


def login_string(*, server_name: str, server_nonce: bytes, client_nonce: bytes) -> bytes:
    name = server_name.encode("ascii")
    if not 1 <= len(name) <= LONGEST_SERVER_NAME:
        raise ValueError(
            f"server_name is {len(name)} bytes long, not 1 to {LONGEST_SERVER_NAME}"
        )
    _require_length("server_nonce", server_nonce, NONCE_LENGTH)
    _require_length("client_nonce", client_nonce, NONCE_LENGTH)

    name_length = bytes([len(name)])
    return LOGIN_PREFIX + PREFIX_END + name_length + name + server_nonce + client_nonce


def identity_dh_string(*, identity_key: bytes, identity_dh_key: bytes) -> bytes:
    _require_length("identity_key", identity_key, KEY_LENGTH)
    _require_length("identity_dh_key", identity_dh_key, KEY_LENGTH)
    return IDENTITY_DH_PREFIX + PREFIX_END + identity_key + identity_dh_key


def signed_prekey_string(*, identity_key: bytes, signed_prekey: bytes) -> bytes:
    _require_length("identity_key", identity_key, KEY_LENGTH)
    _require_length("signed_prekey", signed_prekey, KEY_LENGTH)
    return SIGNED_PREKEY_PREFIX + PREFIX_END + identity_key + signed_prekey


def pq_prekey_string(*, identity_key: bytes, pq_prekey: bytes) -> bytes:
    _require_length("identity_key", identity_key, KEY_LENGTH)
    _require_length("pq_prekey", pq_prekey, KEM_PUBLIC_KEY_LENGTH)
    return PQ_PREKEY_PREFIX + PREFIX_END + identity_key + pq_prekey


def sign_login(
    seed: bytes, *, server_name: str, server_nonce: bytes, client_nonce: bytes
) -> bytes:
    signed_string = login_string(
        server_name=server_name, server_nonce=server_nonce, client_nonce=client_nonce
    )
    return _sign(seed, signed_string)


def verify_login(
    identity_key: bytes,
    *,
    signature: bytes,
    server_name: str,
    server_nonce: bytes,
    client_nonce: bytes,
) -> None:
    """Runs steps 4 and 5 of section 8.3 on the fields of a Login.

    Raises:
        LoginRefusedError: The key is excluded or the signature does not verify.
    """
    _require_length("identity_key", identity_key, KEY_LENGTH)
    signed_string = login_string(
        server_name=server_name, server_nonce=server_nonce, client_nonce=client_nonce
    )

    if not _verifies(identity_key, signature, signed_string):
        raise LoginRefusedError("the signature over the login string does not verify")


def sign_identity_dh_key(seed: bytes, *, identity_dh_key: bytes) -> bytes:
    signed_string = identity_dh_string(
        identity_key=derive_identity_key(seed), identity_dh_key=identity_dh_key
    )
    return _sign(seed, signed_string)


def verify_identity_dh_key(
    identity_key: bytes, *, identity_dh_key: bytes, signature: bytes
) -> None:
    """Verifies the signature over the string of section 4.3.

    Raises:
        BadBundleError: The signature does not verify.
    """
    signed_string = identity_dh_string(
        identity_key=identity_key, identity_dh_key=identity_dh_key
    )
    if not _verifies(identity_key, signature, signed_string):
        raise BadBundleError("the signature over the X25519 identity key does not verify")


def sign_signed_prekey(seed: bytes, *, signed_prekey: bytes) -> bytes:
    signed_string = signed_prekey_string(
        identity_key=derive_identity_key(seed), signed_prekey=signed_prekey
    )
    return _sign(seed, signed_string)


def verify_signed_prekey(
    identity_key: bytes, *, signed_prekey: bytes, signature: bytes
) -> None:
    """Verifies the signature over the string of section 4.4.

    Raises:
        BadBundleError: The signature does not verify.
    """
    signed_string = signed_prekey_string(
        identity_key=identity_key, signed_prekey=signed_prekey
    )
    if not _verifies(identity_key, signature, signed_string):
        raise BadBundleError("the signature over the signed prekey does not verify")


def sign_pq_prekey(seed: bytes, *, pq_prekey: bytes) -> bytes:
    signed_string = pq_prekey_string(
        identity_key=derive_identity_key(seed), pq_prekey=pq_prekey
    )
    return _sign(seed, signed_string)


def verify_pq_prekey(identity_key: bytes, *, pq_prekey: bytes, signature: bytes) -> None:
    """Verifies the signature over the string of section 4.5.

    Raises:
        BadBundleError: The signature does not verify.
    """
    signed_string = pq_prekey_string(identity_key=identity_key, pq_prekey=pq_prekey)
    if not _verifies(identity_key, signature, signed_string):
        raise BadBundleError("the signature over the post-quantum prekey does not verify")


def check_pq_prekey(bundle: Bundle) -> CheckedPqPrekey:
    """Runs checks 5 to 7 of section 5.4, after the four of `check_bundle`.

    Returns:
        The ML-KEM-768 encapsulation key of the bundle and its id.

    Raises:
        PqPrekeyMissingError: The bundle carries no post-quantum prekey.
        BadBundleError: Its signature does not verify, or the key fails the check of
            FIPS 203, section 7.2.
    """
    if bundle.pq_prekey is None:
        raise PqPrekeyMissingError("the bundle carries no post-quantum prekey")
    verify_pq_prekey(
        bundle.identity,
        pq_prekey=bundle.pq_prekey.key,
        signature=bundle.pq_prekey.signature,
    )

    # The library runs the modulus check of FIPS 203, section 7.2, and raises ValueError.
    try:
        public_key = MLKEM768PublicKey.from_public_bytes(bundle.pq_prekey.key)
    except ValueError as error:
        raise BadBundleError("the post-quantum prekey is no ML-KEM-768 key") from error
    return CheckedPqPrekey(public_key=public_key, prekey_id=bundle.pq_prekey.id)


def check_bundle(
    bundle: Bundle, *, contact_identity_key: bytes, pinned_identity_dh_key: bytes | None
) -> None:
    """Runs the four checks of section 5.4 in order and stops at the first that fails.

    Args:
        bundle: The bundle fetched for the contact.
        contact_identity_key: The identity key that the id of the contact decodes to.
        pinned_identity_dh_key: The pin the client holds for the contact, if any.

    Raises:
        BadBundleError: Check 1, 2 or 4 failed.
        IdentityKeyMismatchError: Check 3 failed.
    """
    _require_length("contact_identity_key", contact_identity_key, KEY_LENGTH)
    if pinned_identity_dh_key is not None:
        _require_length("pinned_identity_dh_key", pinned_identity_dh_key, KEY_LENGTH)

    if bundle.identity != contact_identity_key:
        raise BadBundleError("the bundle is not of the identity that the contact id names")

    verify_identity_dh_key(
        bundle.identity,
        identity_dh_key=bundle.identity_dh_key,
        signature=bundle.identity_dh_signature,
    )

    has_pin = pinned_identity_dh_key is not None
    carries_another_key = bundle.identity_dh_key != pinned_identity_dh_key
    if has_pin and carries_another_key:
        raise IdentityKeyMismatchError(
            "the bundle carries another X25519 identity key than the pinned one"
        )

    verify_signed_prekey(
        bundle.identity,
        signed_prekey=bundle.signed_prekey.key,
        signature=bundle.signed_prekey.signature,
    )


def _require_length(name: str, value: bytes, length: int) -> None:
    if len(value) != length:
        raise ValueError(f"{name} is {len(value)} bytes long, not {length}")


def _is_excluded(identity_key: bytes) -> bool:
    last_byte = identity_key[-1] & TOP_BIT_CLEARED
    y = identity_key[:-1] + bytes([last_byte])

    is_non_canonical = y[1:] == FIELD_PRIME[1:] and y[0] >= FIELD_PRIME[0]
    has_small_order = y in SMALL_ORDER
    return is_non_canonical or has_small_order


def _sign(seed: bytes, signed_string: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).sign(signed_string)


def _verifies(identity_key: bytes, signature: bytes, signed_string: bytes) -> bool:
    _require_length("signature", signature, SIGNATURE_LENGTH)
    if _is_excluded(identity_key):
        return False

    # By section 3.3 a key that the library refuses to load verifies no signature.
    try:
        public_key = Ed25519PublicKey.from_public_bytes(identity_key)
    except ValueError:
        return False

    try:
        public_key.verify(signature, signed_string)
    except InvalidSignature:
        return False
    return True
