"""The post-quantum key agreement of docs/protocol.md, section 41: PQXDH with ML-KEM-768."""

from collections.abc import Callable
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)

from sotto.crypto.identity import (
    KEY_LENGTH,
    Bundle,
    _require_length,
    check_bundle,
    check_pq_prekey,
    derive_x25519_public_key,
)
from sotto.crypto.x3dh import (
    KeyAgreement,
    check_initial_header,
    derive_shared_secret,
    initiator_associated_data,
    initiator_dh_outputs,
    responder_dh_outputs,
)

END_TO_END_VERSION = b"\x02"
KEY_DERIVATION_INFO = b"sotto/2 pqxdh_CURVE25519_SHA-256_ML-KEM-768"
KEM_SEED_LENGTH = 64
KEM_CIPHERTEXT_LENGTH = 1088


@dataclass(frozen=True, slots=True, kw_only=True)
class Encapsulation:
    """(CT, SS) of PQKEM-ENC: the ciphertext and the shared secret it carries."""

    ciphertext: bytes
    shared_secret: bytes = field(repr=False)


type Encapsulate = Callable[[MLKEM768PublicKey], Encapsulation]


@dataclass(frozen=True, slots=True, kw_only=True)
class PqKeyAgreement:
    """SK and the session associated data of section 41.4, and what the initial header
    of section 41.6 adds: the ciphertext and the id of the post-quantum prekey."""

    shared_secret: bytes = field(repr=False)
    associated_data: bytes
    kem_ciphertext: bytes
    pq_prekey_id: int


def encapsulate_randomly(public_key: MLKEM768PublicKey) -> Encapsulation:
    """ML-KEM.Encaps of FIPS 203 with the random bytes of the library."""
    shared_secret, ciphertext = public_key.encapsulate()
    return Encapsulation(ciphertext=ciphertext, shared_secret=shared_secret)


def kem_public_key(seed: bytes) -> bytes:
    """The encapsulation key of a 64-byte seed d || z (FIPS 203, ML-KEM.KeyGen_internal)."""
    _require_length("seed", seed, KEM_SEED_LENGTH)
    return MLKEM768PrivateKey.from_seed_bytes(seed).public_key().public_bytes_raw()


def initiate(
    bundle: Bundle,
    *,
    identity_key: bytes,
    identity_dh_private_key: bytes,
    ephemeral_private_key: bytes,
    contact_identity_key: bytes,
    pinned_identity_dh_key: bytes | None,
    encapsulate: Encapsulate = encapsulate_randomly,
) -> PqKeyAgreement:
    """Runs steps 1 to 7 of section 41.5 on a bundle fetched for a contact.

    Args:
        bundle: The bundle fetched for this key agreement.
        identity_key: The identity key of the initiator.
        identity_dh_private_key: The private key of its X25519 identity key.
        ephemeral_private_key: The 32 random bytes of EK_A, used for nothing else.
        contact_identity_key: The identity key that the id of the contact decodes to.
        pinned_identity_dh_key: The pin the client holds for the contact, if any.
        encapsulate: PQKEM-ENC; a test vector gives one with fixed randomness.

    Raises:
        BadBundleError: Check 1, 2, 4, 6 or 7 of section 5.4 failed.
        IdentityKeyMismatchError: Check 3 of section 5.4 failed.
        PqPrekeyMissingError: Check 5 of section 5.4 failed.
        ZeroDhError: A key of the bundle has small order.
    """
    _require_length("identity_key", identity_key, KEY_LENGTH)
    check_bundle(
        bundle,
        contact_identity_key=contact_identity_key,
        pinned_identity_dh_key=pinned_identity_dh_key,
    )
    checked = check_pq_prekey(bundle)

    dh_outputs = initiator_dh_outputs(
        bundle,
        identity_dh_private_key=identity_dh_private_key,
        ephemeral_private_key=ephemeral_private_key,
    )
    encapsulation = encapsulate(checked.public_key)
    _require_length("kem_ciphertext", encapsulation.ciphertext, KEM_CIPHERTEXT_LENGTH)

    key_material = b"".join(dh_outputs) + encapsulation.shared_secret
    return PqKeyAgreement(
        shared_secret=derive_shared_secret(key_material, info=KEY_DERIVATION_INFO),
        associated_data=initiator_associated_data(
            END_TO_END_VERSION,
            bundle,
            identity_key=identity_key,
            identity_dh_private_key=identity_dh_private_key,
            ephemeral_private_key=ephemeral_private_key,
        ),
        kem_ciphertext=encapsulation.ciphertext,
        pq_prekey_id=checked.prekey_id,
    )


def respond(
    *,
    identity_key: bytes,
    identity_dh_private_key: bytes,
    signed_prekey_private_key: bytes,
    one_time_prekey_private_key: bytes | None,
    pq_prekey_seed: bytes,
    sender_identity_key: bytes,
    sender_identity_dh_key: bytes,
    sender_identity_dh_signature: bytes,
    ephemeral_key: bytes,
    kem_ciphertext: bytes,
    pinned_identity_dh_key: bytes | None,
) -> KeyAgreement:
    """Runs steps 1, 2 and 6 to 8 of section 41.7 on an initial header of version 2.

    Args:
        identity_key: The identity key of the responder.
        identity_dh_private_key: The private key of its X25519 identity key.
        signed_prekey_private_key: The private key that `signed_prekey_id` names.
        one_time_prekey_private_key: The private key that `one_time_prekey_id` names,
            None when the initial header carries no such id.
        pq_prekey_seed: The seed of the post-quantum prekey that `pq_prekey_id` names.
        sender_identity_key: The `sender` of the Deliver, IKsig_A.
        sender_identity_dh_key: `identity_dh_key` of the initial header.
        sender_identity_dh_signature: `identity_dh_signature` of the initial header.
        ephemeral_key: `ephemeral_key` of the initial header, the bytes received.
        kem_ciphertext: `kem_ciphertext` of the initial header.
        pinned_identity_dh_key: The pin the client holds for the contact, if any.

    Raises:
        BadInitialHeaderError: The signature over the X25519 identity key does not verify.
        IdentityKeyMismatchError: The initial header carries another key than the pin.
        ZeroDhError: `sender_identity_dh_key` or `ephemeral_key` has small order.
    """
    _require_length("identity_key", identity_key, KEY_LENGTH)
    _require_length("ephemeral_key", ephemeral_key, KEY_LENGTH)
    _require_length("pq_prekey_seed", pq_prekey_seed, KEM_SEED_LENGTH)
    _require_length("kem_ciphertext", kem_ciphertext, KEM_CIPHERTEXT_LENGTH)
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
    # ML-KEM rejects implicitly, so another ciphertext gives another secret and no error.
    kem_shared_secret = MLKEM768PrivateKey.from_seed_bytes(pq_prekey_seed).decapsulate(
        kem_ciphertext
    )

    key_material = b"".join(dh_outputs) + kem_shared_secret
    initiator = sender_identity_key + sender_identity_dh_key
    responder = identity_key + derive_x25519_public_key(identity_dh_private_key)
    return KeyAgreement(
        shared_secret=derive_shared_secret(key_material, info=KEY_DERIVATION_INFO),
        associated_data=END_TO_END_VERSION + initiator + responder + ephemeral_key,
    )
