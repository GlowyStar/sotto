"""The PQXDH core of docs/protocol.md, section 41, without a store and without a network."""

import os
from collections.abc import Callable
from dataclasses import fields, replace

import pytest
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PublicKey

from sotto.crypto.identity import (
    KEM_PUBLIC_KEY_LENGTH,
    BadBundleError,
    Bundle,
    PqPrekeyMissingError,
    SignedPrekey,
    derive_identity_key,
    derive_x25519_public_key,
    sign_identity_dh_key,
    sign_pq_prekey,
    sign_signed_prekey,
)
from sotto.crypto.pqxdh import (
    KEM_SEED_LENGTH,
    Encapsulate,
    Encapsulation,
    PqKeyAgreement,
    encapsulate_randomly,
    initiate,
    kem_public_key,
    respond,
)
from sotto.crypto.x3dh import KeyAgreement


class Responder:
    """The keys of Bob, the identity whose bundle is fetched."""

    def __init__(self) -> None:
        self.seed = os.urandom(32)
        self.identity_key = derive_identity_key(self.seed)
        self.identity_dh_private_key = os.urandom(32)
        self.signed_prekey_private_key = os.urandom(32)
        self.pq_prekey_seed = os.urandom(KEM_SEED_LENGTH)

    def bundle(self) -> Bundle:
        identity_dh_key = derive_x25519_public_key(self.identity_dh_private_key)
        signed_prekey = derive_x25519_public_key(self.signed_prekey_private_key)
        pq_prekey = kem_public_key(self.pq_prekey_seed)
        return Bundle(
            identity=self.identity_key,
            identity_dh_key=identity_dh_key,
            identity_dh_signature=sign_identity_dh_key(
                self.seed, identity_dh_key=identity_dh_key
            ),
            signed_prekey=SignedPrekey(
                id=3,
                key=signed_prekey,
                signature=sign_signed_prekey(self.seed, signed_prekey=signed_prekey),
            ),
            one_time_prekey=None,
            pq_prekey=SignedPrekey(
                id=9, key=pq_prekey, signature=sign_pq_prekey(self.seed, pq_prekey=pq_prekey)
            ),
        )


class Initiator:
    def __init__(self) -> None:
        self.seed = os.urandom(32)
        self.identity_key = derive_identity_key(self.seed)
        self.identity_dh_private_key = os.urandom(32)
        self.ephemeral_private_key = os.urandom(32)

    def start(
        self, bob: Responder, bundle: Bundle, kem: Encapsulate = encapsulate_randomly
    ) -> PqKeyAgreement:
        return initiate(
            bundle,
            identity_key=self.identity_key,
            identity_dh_private_key=self.identity_dh_private_key,
            ephemeral_private_key=self.ephemeral_private_key,
            contact_identity_key=bob.identity_key,
            pinned_identity_dh_key=None,
            encapsulate=kem,
        )


def answer(alice: Initiator, bob: Responder, kem_ciphertext: bytes) -> KeyAgreement:
    identity_dh_key = derive_x25519_public_key(alice.identity_dh_private_key)
    return respond(
        identity_key=bob.identity_key,
        identity_dh_private_key=bob.identity_dh_private_key,
        signed_prekey_private_key=bob.signed_prekey_private_key,
        one_time_prekey_private_key=None,
        pq_prekey_seed=bob.pq_prekey_seed,
        sender_identity_key=alice.identity_key,
        sender_identity_dh_key=identity_dh_key,
        sender_identity_dh_signature=sign_identity_dh_key(
            alice.seed, identity_dh_key=identity_dh_key
        ),
        ephemeral_key=derive_x25519_public_key(alice.ephemeral_private_key),
        kem_ciphertext=kem_ciphertext,
        pinned_identity_dh_key=None,
    )


def test_both_sides_derive_the_same_secret_and_associated_data_of_version_2() -> None:
    alice, bob = Initiator(), Responder()

    started = alice.start(bob, bob.bundle())
    accepted = answer(alice, bob, started.kem_ciphertext)

    assert started.shared_secret == accepted.shared_secret
    assert started.associated_data == accepted.associated_data
    assert started.associated_data[0] == 2
    assert len(started.associated_data) == 161
    assert started.pq_prekey_id == 9


def test_another_ciphertext_gives_the_responder_another_secret() -> None:
    alice, bob = Initiator(), Responder()
    started = alice.start(bob, bob.bundle())
    other = Initiator().start(bob, bob.bundle())

    accepted = answer(alice, bob, other.kem_ciphertext)

    assert accepted.shared_secret != started.shared_secret
    assert accepted.associated_data == started.associated_data


# The first coefficient is 4095, above q = 3329: the key fails FIPS 203, section 7.2.
NO_ML_KEM_KEY = b"\xff\xff" + bytes(KEM_PUBLIC_KEY_LENGTH - 2)


def flip_the_pq_signature(bundle: Bundle, _: Responder) -> Bundle:
    assert bundle.pq_prekey is not None
    signature = bundle.pq_prekey.signature
    flipped = bytes([signature[0] ^ 1]) + signature[1:]
    return replace(bundle, pq_prekey=replace(bundle.pq_prekey, signature=flipped))


def sign_no_ml_kem_key(bundle: Bundle, bob: Responder) -> Bundle:
    signature = sign_pq_prekey(bob.seed, pq_prekey=NO_ML_KEM_KEY)
    return replace(
        bundle, pq_prekey=SignedPrekey(id=9, key=NO_ML_KEM_KEY, signature=signature)
    )


SPOILED: dict[str, tuple[Callable[[Bundle, Responder], Bundle], type[Exception]]] = {
    "no pq prekey": (lambda bundle, _: replace(bundle, pq_prekey=None), PqPrekeyMissingError),
    "pq prekey under another signature": (flip_the_pq_signature, BadBundleError),
    "signed pq prekey that is no ml-kem key": (sign_no_ml_kem_key, BadBundleError),
    "another identity and no pq prekey": (
        lambda bundle, _: replace(bundle, identity=os.urandom(32), pq_prekey=None),
        BadBundleError,
    ),
}


@pytest.mark.parametrize("case", SPOILED)
def test_bundle_that_fails_a_check_reaches_no_encapsulation(case: str) -> None:
    spoil, error = SPOILED[case]
    alice, bob = Initiator(), Responder()
    calls: list[MLKEM768PublicKey] = []

    def counted(public_key: MLKEM768PublicKey) -> Encapsulation:
        calls.append(public_key)
        return encapsulate_randomly(public_key)

    with pytest.raises(error):
        alice.start(bob, spoil(bob.bundle(), bob), counted)
    assert calls == []


def test_key_agreement_hands_back_the_secret_the_data_and_the_header_fields_only() -> None:
    alice, bob = Initiator(), Responder()

    made = alice.start(bob, bob.bundle())

    assert [field.name for field in fields(made)] == [
        "shared_secret",
        "associated_data",
        "kem_ciphertext",
        "pq_prekey_id",
    ]
    assert made.shared_secret.hex() not in repr(made)
