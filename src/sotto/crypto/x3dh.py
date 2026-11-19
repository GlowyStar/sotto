"""The key agreement of docs/protocol.md: sections 16.3 to 16.6, steps 1, 2, 5 to 7 of 16.8."""

import operator
from dataclasses import dataclass, field
from functools import reduce

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from sotto.crypto.identity import (
    KEY_LENGTH,
    BadBundleError,
    Bundle,
    CryptoError,
    IdentityKeyMismatchError,
    _require_length,
    check_bundle,
    derive_x25519_public_key,
    verify_identity_dh_key,
)

END_TO_END_VERSION = b"\x01"
KEY_MATERIAL_PREFIX = b"\xff" * 32
KEY_DERIVATION_SALT = bytes(32)
KEY_DERIVATION_INFO = b"sotto/1 x3dh"
SHARED_SECRET_LENGTH = 32


class ZeroDhError(CryptoError):
    result = "ZERO_DH"


class BadInitialHeaderError(CryptoError):
    result = "BAD_INITIAL_HEADER"


@dataclass(frozen=True, slots=True, kw_only=True)
class KeyAgreement:
    """SK of section 16.4 and the 161 bytes of section 16.5."""

    shared_secret: bytes = field(repr=False)
    associated_data: bytes


def dh(private_key: bytes, public_key: bytes) -> bytes:
    """Returns DH(k, P) of section 16.3.

    Raises:
        ZeroDhError: The library refused the output, or the output is 32 zero bytes.
    """
    _require_length("private_key", private_key, KEY_LENGTH)
    _require_length("public_key", public_key, KEY_LENGTH)
    own_key = X25519PrivateKey.from_private_bytes(private_key)
    peer_key = X25519PublicKey.from_public_bytes(public_key)

    # With both lengths checked, the library raises ValueError only for a zero output.
    try:
        output = own_key.exchange(peer_key)
    except ValueError as error:
        raise ZeroDhError("a Diffie-Hellman output is 32 zero bytes") from error

    if reduce(operator.or_, output, 0) == 0:
        raise ZeroDhError("a Diffie-Hellman output is 32 zero bytes")
    return output


def initiate(
    bundle: Bundle,
    *,
    identity_key: bytes,
    identity_dh_private_key: bytes,
    ephemeral_private_key: bytes,
    contact_identity_key: bytes,
    pinned_identity_dh_key: bytes | None,
) -> KeyAgreement:
    """Runs steps 1 to 6 of section 16.6 on a bundle fetched for a contact.

    Args:
        bundle: The bundle fetched for this key agreement.
        identity_key: The identity key of the initiator.
        identity_dh_private_key: The private key of its X25519 identity key.
        ephemeral_private_key: The 32 random bytes of step 2, used for nothing else.
        contact_identity_key: The identity key that the id of the contact decodes to.
        pinned_identity_dh_key: The pin the client holds for the contact, if any.

    Raises:
        BadBundleError: Check 1, 2 or 4 of section 5.4 failed.
        IdentityKeyMismatchError: Check 3 of section 5.4 failed.
        ZeroDhError: A key of the bundle has small order.
    """
    _require_length("identity_key", identity_key, KEY_LENGTH)
    check_bundle(
        bundle,
        contact_identity_key=contact_identity_key,
        pinned_identity_dh_key=pinned_identity_dh_key,
    )

    dh_outputs = initiator_dh_outputs(
        bundle,
        identity_dh_private_key=identity_dh_private_key,
        ephemeral_private_key=ephemeral_private_key,
    )
    return KeyAgreement(
        shared_secret=derive_shared_secret(b"".join(dh_outputs), info=KEY_DERIVATION_INFO),
        associated_data=initiator_associated_data(
            END_TO_END_VERSION,
            bundle,
            identity_key=identity_key,
            identity_dh_private_key=identity_dh_private_key,
            ephemeral_private_key=ephemeral_private_key,
        ),
    )


def respond(
    *,
    identity_key: bytes,
    identity_dh_private_key: bytes,
    signed_prekey_private_key: bytes,
    one_time_prekey_private_key: bytes | None,
    sender_identity_key: bytes,
    sender_identity_dh_key: bytes,
    sender_identity_dh_signature: bytes,
    ephemeral_key: bytes,
    pinned_identity_dh_key: bytes | None,
) -> KeyAgreement:
    """Runs steps 1, 2 and 5 to 7 of section 16.8 on an initial header.

    Args:
        identity_key: The identity key of the responder.
        identity_dh_private_key: The private key of its X25519 identity key.
        signed_prekey_private_key: The private key that `signed_prekey_id` names.
        one_time_prekey_private_key: The private key that `one_time_prekey_id` names,
            None when the initial header carries no such id.
        sender_identity_key: The `sender` of the Deliver, IKsig_A.
        sender_identity_dh_key: `identity_dh_key` of the initial header.
        sender_identity_dh_signature: `identity_dh_signature` of the initial header.
        ephemeral_key: `ephemeral_key` of the initial header, the bytes received.
        pinned_identity_dh_key: The pin the client holds for the contact, if any.

    Raises:
        BadInitialHeaderError: The signature over the X25519 identity key does not verify.
        IdentityKeyMismatchError: The initial header carries another key than the pin.
        ZeroDhError: `sender_identity_dh_key` or `ephemeral_key` has small order.
    """
    _require_length("identity_key", identity_key, KEY_LENGTH)
    _require_length("ephemeral_key", ephemeral_key, KEY_LENGTH)
    check_initial_header(
        sender_identity_key,
        identity_dh_key=sender_identity_dh_key,
        signature=sender_identity_dh_signature,
        pinned_identity_dh_key=pinned_identity_dh_key,
    )

    dh_outputs = responder_dh_outputs(
        identity_dh_private_key=identity_dh_private_key,
        signed_prekey_private_key=signed_prekey_private_key,
        one_time_prekey_private_key=one_time_prekey_private_key,
        sender_identity_dh_key=sender_identity_dh_key,
        ephemeral_key=ephemeral_key,
    )
    initiator = sender_identity_key + sender_identity_dh_key
    responder = identity_key + derive_x25519_public_key(identity_dh_private_key)
    return KeyAgreement(
        shared_secret=derive_shared_secret(b"".join(dh_outputs), info=KEY_DERIVATION_INFO),
        associated_data=END_TO_END_VERSION + initiator + responder + ephemeral_key,
    )


def check_initial_header(
    sender_identity_key: bytes,
    *,
    identity_dh_key: bytes,
    signature: bytes,
    pinned_identity_dh_key: bytes | None,
) -> None:
    """Steps 1 and 2 of section 16.8, before any Diffie-Hellman value.

    Raises:
        BadInitialHeaderError: The signature does not verify under the sender.
        IdentityKeyMismatchError: The key is not the pinned one.
    """
    if pinned_identity_dh_key is not None:
        _require_length("pinned_identity_dh_key", pinned_identity_dh_key, KEY_LENGTH)

    try:
        verify_identity_dh_key(
            sender_identity_key, identity_dh_key=identity_dh_key, signature=signature
        )
    except BadBundleError as error:
        raise BadInitialHeaderError(
            "the signature over the X25519 identity key does not verify"
        ) from error

    has_pin = pinned_identity_dh_key is not None
    carries_another_key = identity_dh_key != pinned_identity_dh_key
    if has_pin and carries_another_key:
        raise IdentityKeyMismatchError(
            "the initial header carries another X25519 identity key than the pinned one"
        )


def initiator_dh_outputs(
    bundle: Bundle, *, identity_dh_private_key: bytes, ephemeral_private_key: bytes
) -> list[bytes]:
    """DH1 to DH4 of step 3 of section 16.6, DH4 only with a one-time prekey.

    Raises:
        ZeroDhError: A key of the bundle has small order.
    """
    signed_prekey = bundle.signed_prekey.key
    dh_outputs = [
        dh(identity_dh_private_key, signed_prekey),
        dh(ephemeral_private_key, bundle.identity_dh_key),
        dh(ephemeral_private_key, signed_prekey),
    ]
    if bundle.one_time_prekey is not None:
        dh_outputs.append(dh(ephemeral_private_key, bundle.one_time_prekey.key))
    return dh_outputs


def responder_dh_outputs(
    *,
    identity_dh_private_key: bytes,
    signed_prekey_private_key: bytes,
    one_time_prekey_private_key: bytes | None,
    sender_identity_dh_key: bytes,
    ephemeral_key: bytes,
) -> list[bytes]:
    """DH1 to DH4 of step 5 of section 16.8, DH4 only with a one-time prekey.

    Raises:
        ZeroDhError: `sender_identity_dh_key` or `ephemeral_key` has small order.
    """
    dh_outputs = [
        dh(signed_prekey_private_key, sender_identity_dh_key),
        dh(identity_dh_private_key, ephemeral_key),
        dh(signed_prekey_private_key, ephemeral_key),
    ]
    if one_time_prekey_private_key is not None:
        dh_outputs.append(dh(one_time_prekey_private_key, ephemeral_key))
    return dh_outputs


def initiator_associated_data(
    version: bytes,
    bundle: Bundle,
    *,
    identity_key: bytes,
    identity_dh_private_key: bytes,
    ephemeral_private_key: bytes,
) -> bytes:
    """The 161 bytes of section 16.5 under the version byte of the key agreement."""
    initiator = identity_key + derive_x25519_public_key(identity_dh_private_key)
    responder = bundle.identity + bundle.identity_dh_key
    ephemeral_key = derive_x25519_public_key(ephemeral_private_key)
    return version + initiator + responder + ephemeral_key


def derive_shared_secret(key_material: bytes, *, info: bytes) -> bytes:
    """SK of section 16.4, or of section 41.4 with the shared secret of the KEM."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=SHARED_SECRET_LENGTH,
        salt=KEY_DERIVATION_SALT,
        info=info,
    )
    return hkdf.derive(KEY_MATERIAL_PREFIX + key_material)
