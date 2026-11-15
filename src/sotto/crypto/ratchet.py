"""The Double Ratchet of docs/protocol.md, sections 17 and 18.

A state machine without input or output of its own: every function takes the state and
every random value as arguments and returns a new state. A call that fails returns
nothing, so the state the caller holds stays as it was.
"""

import hmac
from dataclasses import dataclass, field, replace
from hashlib import sha256
from typing import NamedTuple, Self

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from sotto.crypto.identity import (
    KEY_LENGTH,
    CryptoError,
    _require_length,
    derive_x25519_public_key,
)
from sotto.crypto.x3dh import dh

MAX_SKIP = 1000
SKIPPED_KEYS_CAP = 2000
SKIPPED_KEY_STEPS = 5

HEADER_LENGTH = 40
CALLER_ASSOCIATED_DATA_LENGTH = 177
MESSAGE_NONCE_LENGTH = 12
TAG_LENGTH = 16
LAST_MESSAGE_NUMBER = 2**32 - 1
NUMBER_LENGTH = 4

ROOT_KDF_INFO = b"sotto/1 ratchet"
ROOT_KDF_LENGTH = 64
MESSAGE_KEY_INPUT = b"\x01"
CHAIN_KEY_INPUT = b"\x02"


class DecryptFailedError(CryptoError):
    result = "DECRYPT_FAILED"


class TooManySkippedError(CryptoError):
    result = "TOO_MANY_SKIPPED"


class ChainExhaustedError(CryptoError):
    result = "CHAIN_EXHAUSTED"


class NoSendingChainError(CryptoError):
    result = "NO_SENDING_CHAIN"


@dataclass(frozen=True, slots=True, kw_only=True)
class SkippedKey:
    """An entry of MKSKIPPED (section 17.8)."""

    ratchet_key: bytes
    number: int
    message_key: bytes = field(repr=False)
    step: int


@dataclass(frozen=True, slots=True, kw_only=True)
class RatchetState:
    """The variables of section 17.2; None is the value "empty"."""

    dhs_private_key: bytes = field(repr=False)
    dhs_public_key: bytes
    dhr: bytes | None
    rk: bytes = field(repr=False)
    cks: bytes | None = field(repr=False)
    ckr: bytes | None = field(repr=False)
    ns: int
    nr: int
    pn: int
    dhsteps: int
    mkskipped: tuple[SkippedKey, ...]


class Encrypted(NamedTuple):
    state: RatchetState
    header: bytes
    ciphertext: bytes


class Decrypted(NamedTuple):
    state: RatchetState
    padded_plaintext: bytes
    purged: int


def kdf_rk(rk: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    """Returns the new root key and the chain key of KDF_RK (section 17.4)."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=ROOT_KDF_LENGTH, salt=rk, info=ROOT_KDF_INFO)
    output = hkdf.derive(dh_output)
    return output[:KEY_LENGTH], output[KEY_LENGTH:]


def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    """Returns the message key and the next chain key of KDF_CK (section 17.4)."""
    message_key = hmac.digest(ck, MESSAGE_KEY_INPUT, sha256)
    return message_key, hmac.digest(ck, CHAIN_KEY_INPUT, sha256)


def init_initiator(
    *, shared_secret: bytes, signed_prekey: bytes, ratchet_private_key: bytes
) -> RatchetState:
    """The state of an initiator after section 17.3.

    Args:
        shared_secret: SK of the key agreement.
        signed_prekey: SPK_B, the 32 bytes of the Bundle.
        ratchet_private_key: 32 random bytes, the private key of the first DHs.

    Raises:
        ZeroDhError: SPK_B has small order.
    """
    _require_length("shared_secret", shared_secret, KEY_LENGTH)
    root_key, chain_key = kdf_rk(shared_secret, dh(ratchet_private_key, signed_prekey))
    return RatchetState(
        dhs_private_key=ratchet_private_key,
        dhs_public_key=derive_x25519_public_key(ratchet_private_key),
        dhr=signed_prekey,
        rk=root_key,
        cks=chain_key,
        ckr=None,
        ns=0,
        nr=0,
        pn=0,
        dhsteps=0,
        mkskipped=(),
    )


def init_responder(*, shared_secret: bytes, signed_prekey_private_key: bytes) -> RatchetState:
    """The state of a responder after section 17.3: it cannot encrypt yet."""
    _require_length("shared_secret", shared_secret, KEY_LENGTH)
    return RatchetState(
        dhs_private_key=signed_prekey_private_key,
        dhs_public_key=derive_x25519_public_key(signed_prekey_private_key),
        dhr=None,
        rk=shared_secret,
        cks=None,
        ckr=None,
        ns=0,
        nr=0,
        pn=0,
        dhsteps=0,
        mkskipped=(),
    )


def encrypt(
    state: RatchetState, padded_plaintext: bytes, *, associated_data: bytes, nonce: bytes
) -> Encrypted:
    """Runs the steps of section 17.6.

    Args:
        state: The state of the session.
        padded_plaintext: P of section 19.6.
        associated_data: The 177 bytes of the session associated data and the message id.
        nonce: 12 random bytes.

    Returns:
        The new state, the 40 bytes of the header and the `ciphertext` field of 18.3.

    Raises:
        NoSendingChainError: The state has no sending chain.
        ChainExhaustedError: Ns is 2^32 - 1.
    """
    _require_length("associated_data", associated_data, CALLER_ASSOCIATED_DATA_LENGTH)
    _require_length("nonce", nonce, MESSAGE_NONCE_LENGTH)
    if state.cks is None:
        raise NoSendingChainError("the state has no sending chain")
    if state.ns == LAST_MESSAGE_NUMBER:
        raise ChainExhaustedError("the sending chain is at its end")

    message_key, next_chain_key = kdf_ck(state.cks)
    header = (
        state.dhs_public_key
        + state.pn.to_bytes(NUMBER_LENGTH, "big")
        + state.ns.to_bytes(NUMBER_LENGTH, "big")
    )
    sealed = ChaCha20Poly1305(message_key).encrypt(
        nonce, padded_plaintext, associated_data + header
    )

    new_state = replace(state, cks=next_chain_key, ns=state.ns + 1)
    return Encrypted(state=new_state, header=header, ciphertext=nonce + sealed)


def decrypt(
    state: RatchetState,
    header: bytes,
    ciphertext: bytes,
    *,
    associated_data: bytes,
    ratchet_private_key: bytes,
) -> Decrypted:
    """Runs the steps of section 17.7 on a copy of the state.

    Args:
        state: The state of the session; it is not changed.
        header: The 40 bytes of the `header` field as received.
        ciphertext: The `ciphertext` field as received.
        associated_data: The 177 bytes of the session associated data and the message id.
        ratchet_private_key: 32 random bytes, used only when a DH ratchet step is taken.

    Returns:
        The new state, the padded plaintext and the number of skipped keys that the cap
        and the purge of section 17.8 removed.

    Raises:
        ChainExhaustedError: The header carries the number 2^32 - 1.
        DecryptFailedError: The key of the message was used or purged, or the message
            does not verify under it.
        TooManySkippedError: The header asks for more than MAX_SKIP keys of one chain.
        ZeroDhError: The ratchet key of the header has small order.
    """
    _require_length("header", header, HEADER_LENGTH)
    _require_length("associated_data", associated_data, CALLER_ASSOCIATED_DATA_LENGTH)
    _require_length("ratchet_private_key", ratchet_private_key, KEY_LENGTH)
    ratchet_key = header[:KEY_LENGTH]
    previous_count = int.from_bytes(header[KEY_LENGTH : KEY_LENGTH + NUMBER_LENGTH], "big")
    number = int.from_bytes(header[KEY_LENGTH + NUMBER_LENGTH :], "big")
    sealed_with = associated_data + header

    if number == LAST_MESSAGE_NUMBER:
        raise ChainExhaustedError("the header carries the number 2^32 - 1")
    for entry in state.mkskipped:
        if entry.ratchet_key == ratchet_key and entry.number == number:
            padded_plaintext = _open(entry.message_key, ciphertext, sealed_with)
            kept = tuple(other for other in state.mkskipped if other is not entry)
            return Decrypted(replace(state, mkskipped=kept), padded_plaintext, 0)

    receiving = _Receiving.of(state)
    if ratchet_key == state.dhr:
        _check_current_chain(state, number)
    else:
        _check_new_chain(state, previous_count, number)
        receiving.step(ratchet_key, previous_count, ratchet_private_key)
    receiving.skip_until(number)
    message_key = receiving.next_message_key()
    padded_plaintext = _open(message_key, ciphertext, sealed_with)

    return Decrypted(receiving.state(), padded_plaintext, receiving.purged)


def _check_current_chain(state: RatchetState, number: int) -> None:
    if state.ckr is None:
        raise DecryptFailedError("the state has no receiving chain")
    if number < state.nr:
        raise DecryptFailedError("the key of the message was used or purged")
    if number > state.nr + MAX_SKIP:
        raise TooManySkippedError("the header asks for more than MAX_SKIP skipped keys")


def _check_new_chain(state: RatchetState, previous_count: int, number: int) -> None:
    if previous_count > state.nr + MAX_SKIP:
        raise TooManySkippedError("the header asks for more than MAX_SKIP skipped keys")
    if number > MAX_SKIP:
        raise TooManySkippedError("the header asks for more than MAX_SKIP skipped keys")


def _open(message_key: bytes, ciphertext: bytes, associated_data: bytes) -> bytes:
    if len(ciphertext) < MESSAGE_NONCE_LENGTH + TAG_LENGTH:
        raise DecryptFailedError("the message does not verify")
    nonce = ciphertext[:MESSAGE_NONCE_LENGTH]
    try:
        return ChaCha20Poly1305(message_key).decrypt(
            nonce, ciphertext[MESSAGE_NONCE_LENGTH:], associated_data
        )
    except InvalidTag as error:
        raise DecryptFailedError("the message does not verify") from error


@dataclass(slots=True, kw_only=True)
class _Receiving:
    """The copy of the state that steps 5 to 7 of section 17.7 change."""

    dhs_private_key: bytes
    dhs_public_key: bytes
    dhr: bytes | None
    rk: bytes
    cks: bytes | None
    ckr: bytes | None
    ns: int
    nr: int
    pn: int
    dhsteps: int
    skipped: dict[tuple[bytes, int], SkippedKey]
    purged: int = 0

    @classmethod
    def of(cls, state: RatchetState) -> Self:
        return cls(
            dhs_private_key=state.dhs_private_key,
            dhs_public_key=state.dhs_public_key,
            dhr=state.dhr,
            rk=state.rk,
            cks=state.cks,
            ckr=state.ckr,
            ns=state.ns,
            nr=state.nr,
            pn=state.pn,
            dhsteps=state.dhsteps,
            skipped={(entry.ratchet_key, entry.number): entry for entry in state.mkskipped},
        )

    def step(self, ratchet_key: bytes, previous_count: int, private_key: bytes) -> None:
        """The DH ratchet step, step 5 of section 17.7."""
        if self.ckr is not None:
            self.skip_until(previous_count)
        self.pn = self.ns
        self.ns = 0
        self.nr = 0
        self.dhr = ratchet_key
        self.rk, self.ckr = kdf_rk(self.rk, dh(self.dhs_private_key, ratchet_key))
        self.dhs_private_key = private_key
        self.dhs_public_key = derive_x25519_public_key(private_key)
        self.rk, self.cks = kdf_rk(self.rk, dh(private_key, ratchet_key))
        self.dhsteps += 1

        kept = {
            pair: entry
            for pair, entry in self.skipped.items()
            if entry.step + SKIPPED_KEY_STEPS > self.dhsteps
        }
        self.purged += len(self.skipped) - len(kept)
        self.skipped = kept

    def skip_until(self, number: int) -> None:
        """Skips one key of the receiving chain (section 17.8) while Nr is below `number`."""
        while self.nr < number:
            pair = (self.ratchet_key(), self.nr)
            message_key = self.next_message_key()
            self.skipped.pop(pair, None)
            if len(self.skipped) == SKIPPED_KEYS_CAP:
                del self.skipped[next(iter(self.skipped))]
                self.purged += 1
            self.skipped[pair] = SkippedKey(
                ratchet_key=pair[0], number=pair[1], message_key=message_key, step=self.dhsteps
            )

    def ratchet_key(self) -> bytes:
        if self.dhr is None:
            raise DecryptFailedError("the state has no receiving chain")
        return self.dhr

    def next_message_key(self) -> bytes:
        if self.ckr is None:
            raise DecryptFailedError("the state has no receiving chain")
        message_key, self.ckr = kdf_ck(self.ckr)
        self.nr += 1
        return message_key

    def state(self) -> RatchetState:
        return RatchetState(
            dhs_private_key=self.dhs_private_key,
            dhs_public_key=self.dhs_public_key,
            dhr=self.dhr,
            rk=self.rk,
            cks=self.cks,
            ckr=self.ckr,
            ns=self.ns,
            nr=self.nr,
            pn=self.pn,
            dhsteps=self.dhsteps,
            mkskipped=tuple(self.skipped.values()),
        )
