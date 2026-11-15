"""The session rules of docs/protocol.md: sections 16.6 to 16.8, 20 and 22.2, no network.

`Client.receive` turns a delivered message into what to show and an ack, and
`Client.send_text` turns a text into the bytes of a Send. Both commit what they change
before they answer.
"""

import secrets
from collections.abc import Callable
from dataclasses import dataclass

from sotto.client.envelope import (
    VERSION,
    BadContentError,
    BadPaddingError,
    UnknownContentError,
    decode_text,
    encode_text,
    parse_envelope,
)
from sotto.client.store import Identity, OutboxRow, Store, StoredSession
from sotto.crypto import ratchet, x3dh
from sotto.crypto.identity import (
    KEY_LENGTH,
    BadBundleError,
    Bundle,
    CryptoError,
    IdentityKeyMismatchError,
    OneTimePrekey,
    SignedPrekey,
    decode_user_id,
    derive_identity_key,
    derive_x25519_public_key,
    sign_identity_dh_key,
    sign_signed_prekey,
    verify_identity_dh_key,
)
from sotto.crypto.ratchet import MESSAGE_NONCE_LENGTH, DecryptFailedError, RatchetState
from sotto.crypto.x3dh import BadInitialHeaderError
from sotto.proto.sotto_pb2 import InitialHeader, PeerMessage

MESSAGE_ID_LENGTH = 16

type RandomBytes = Callable[[int], bytes]


class NotAContactError(CryptoError):
    result = "NOT_A_CONTACT"


class DuplicateError(CryptoError):
    result = "DUPLICATE"


class ReplayedInitialError(CryptoError):
    result = "REPLAYED_INITIAL"


class NoSessionError(CryptoError):
    result = "NO_SESSION"


class UnknownSignedPrekeyError(CryptoError):
    result = "UNKNOWN_SIGNED_PREKEY"


class UnknownOneTimePrekeyError(CryptoError):
    result = "UNKNOWN_ONE_TIME_PREKEY"


class OwnIdentityError(ValueError):
    """The id of the client's own identity is never a contact (section 16.1)."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Delivered:
    """A Deliver of section 7.14, its lengths checked by the parser of the frame."""

    sender: bytes
    message_id: bytes
    payload: bytes


@dataclass(frozen=True, slots=True, kw_only=True)
class Received:
    """What a Deliver gives: a text to show, or the named result of section 24.2."""

    ack: bool
    text: str | None
    result: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class Outgoing:
    """The fields of a Send; a repeated Send carries them unchanged (section 22.2)."""

    message_id: bytes
    recipient: bytes
    payload: bytes


@dataclass(frozen=True, slots=True, kw_only=True)
class PrekeyUpload:
    """The keys of an UploadBundle (section 21.4), saved before they are handed out."""

    identity_dh_key: bytes
    identity_dh_signature: bytes
    signed_prekey: SignedPrekey
    one_time_prekeys: tuple[OneTimePrekey, ...]


class Client:
    """The session layer of one identity over its store.

    Args:
        store: The store of the identity; an empty one gets a new identity.
        random_bytes: The one source of random bytes, called with the number it needs.
    """

    def __init__(self, store: Store, *, random_bytes: RandomBytes = secrets.token_bytes):
        self.store = store
        self.random_bytes = random_bytes
        identity = store.identity()
        if identity is None:
            identity = Identity(
                seed=random_bytes(KEY_LENGTH), identity_dh_private_key=random_bytes(KEY_LENGTH)
            )
            with store.transaction():
                store.save_identity(identity)
        self._identity = identity
        self.identity_key = derive_identity_key(identity.seed)
        self.identity_dh_key = derive_x25519_public_key(identity.identity_dh_private_key)

    def make_prekeys(self, one_time_count: int) -> PrekeyUpload:
        """Makes a signed prekey and `one_time_count` one-time prekeys and saves them."""
        signed_private_key = self.random_bytes(KEY_LENGTH)
        one_time_private_keys = [self.random_bytes(KEY_LENGTH) for _ in range(one_time_count)]
        with self.store.transaction():
            signed_id = self.store.add_signed_prekey(signed_private_key)
            one_time_ids = [
                self.store.add_one_time_prekey(private_key)
                for private_key in one_time_private_keys
            ]

        signed_key = derive_x25519_public_key(signed_private_key)
        signed_prekey = SignedPrekey(
            id=signed_id,
            key=signed_key,
            signature=sign_signed_prekey(self._identity.seed, signed_prekey=signed_key),
        )
        one_time_prekeys = tuple(
            OneTimePrekey(id=prekey_id, key=derive_x25519_public_key(private_key))
            for prekey_id, private_key in zip(one_time_ids, one_time_private_keys, strict=True)
        )
        return PrekeyUpload(
            identity_dh_key=self.identity_dh_key,
            identity_dh_signature=self._identity_dh_signature(),
            signed_prekey=signed_prekey,
            one_time_prekeys=one_time_prekeys,
        )

    def add_contact(self, user_id: str) -> bytes:
        """Adds the identity of a user id and returns its identity key.

        Raises:
            InvalidIdError: The string is not a user id.
            OwnIdentityError: The id is the client's own.
        """
        contact = decode_user_id(user_id)
        if contact == self.identity_key:
            raise OwnIdentityError("the id of the client's own identity is never a contact")
        with self.store.transaction():
            self.store.add_contact(contact)
        return contact

    def has_session(self, contact: bytes) -> bool:
        return bool(self.store.sessions(contact))

    def start_session(self, contact: bytes, bundle: Bundle) -> None:
        """START of section 20.3: section 16.6 with a bundle fetched for the contact.

        Raises:
            NotAContactError: The identity is not a contact.
            BadBundleError: Check 1, 2 or 4 of section 5.4 failed.
            IdentityKeyMismatchError: The bundle carries another key than the pin.
            ZeroDhError: A key of the bundle has small order.
        """
        if not self.store.is_contact(contact):
            raise NotAContactError("the identity is not a contact")
        pin = self.store.pin(contact)
        ephemeral_private_key = self.random_bytes(KEY_LENGTH)
        agreement = x3dh.initiate(
            bundle,
            identity_key=self.identity_key,
            identity_dh_private_key=self._identity.identity_dh_private_key,
            ephemeral_private_key=ephemeral_private_key,
            contact_identity_key=contact,
            pinned_identity_dh_key=pin,
        )
        state = ratchet.init_initiator(
            shared_secret=agreement.shared_secret,
            signed_prekey=bundle.signed_prekey.key,
            ratchet_private_key=self.random_bytes(KEY_LENGTH),
        )

        initial_header = InitialHeader(
            identity_dh_key=self.identity_dh_key,
            identity_dh_signature=self._identity_dh_signature(),
            ephemeral_key=derive_x25519_public_key(ephemeral_private_key),
            signed_prekey_id=bundle.signed_prekey.id,
        )
        if bundle.one_time_prekey is not None:
            initial_header.one_time_prekey_id = bundle.one_time_prekey.id

        with self.store.transaction():
            self.store.add_session(
                contact,
                associated_data=agreement.associated_data,
                state=state,
                initial_header=initial_header.SerializeToString(),
            )
            if pin is None:
                self.store.set_pin(contact, bundle.identity_dh_key)

    def send_text(
        self, contact: bytes, text: str, *, bundle: Bundle | None = None
    ) -> Outgoing:
        """L1 of section 20.2: the bytes of a Send, committed to the outbox first.

        Args:
            contact: The identity key of the contact.
            text: The text to send.
            bundle: A bundle fetched for the contact; needed when it has no session.

        Raises:
            TextTooLongError: The text is longer than MAX_TEXT_BYTES; nothing else ran.
            NotAContactError: The identity is not a contact.
            CryptoError: START failed with the result that it names.
            ValueError: The contact has no session and no bundle was given.
        """
        padded_plaintext = encode_text(text)
        if not self.store.is_contact(contact):
            raise NotAContactError("the identity is not a contact")
        if not self.has_session(contact):
            if bundle is None:
                raise ValueError("a contact without a session needs a fetched bundle")
            self.start_session(contact, bundle)

        session = self.store.sessions(contact)[0]
        message_id = self.random_bytes(MESSAGE_ID_LENGTH)
        encrypted = ratchet.encrypt(
            session.state,
            padded_plaintext,
            associated_data=session.associated_data + message_id,
            nonce=self.random_bytes(MESSAGE_NONCE_LENGTH),
        )
        envelope = PeerMessage(
            version=VERSION, header=encrypted.header, ciphertext=encrypted.ciphertext
        )
        if session.initial_header is not None:
            envelope.initial_header.MergeFromString(session.initial_header)
        outgoing = Outgoing(
            message_id=message_id, recipient=contact, payload=envelope.SerializeToString()
        )

        with self.store.transaction():
            self.store.advance_session(session.session_id, encrypted.state)
            self.store.add_to_outbox(
                OutboxRow(message_id=message_id, recipient=contact, payload=outgoing.payload)
            )
            self.store.log_message(contact, direction="out", message_id=message_id, text=text)
        return outgoing

    def outbox(self) -> list[Outgoing]:
        """The Sends that the relay has not confirmed, to be sent again as they are."""
        return [
            Outgoing(message_id=row.message_id, recipient=row.recipient, payload=row.payload)
            for row in self.store.outbox()
        ]

    def confirm_stored(self, message_id: bytes) -> None:
        """Removes the outbox row of a Send that the relay answered with Stored."""
        with self.store.transaction():
            self.store.remove_from_outbox(message_id)

    def receive(self, delivered: Delivered) -> Received:
        """Runs the row of section 20.2 that a Deliver falls into.

        Every result is acked; an accepted message only after its commit, so an exception
        other than a named result leaves the store as it was and gives no ack.
        """
        try:
            return self._receive(delivered)
        except CryptoError as error:
            return Received(ack=True, text=None, result=error.result)

    def _receive(self, delivered: Delivered) -> Received:
        if not self.store.is_contact(delivered.sender):
            raise NotAContactError("the sender is not a contact")
        if self.store.is_seen(delivered.sender, delivered.message_id):
            raise DuplicateError("the message was accepted before")

        envelope = parse_envelope(delivered.payload)
        if envelope.HasField("initial_header"):
            return self._receive_initial(delivered, envelope)
        return self._receive_on_list(delivered, envelope)

    def _receive_initial(self, delivered: Delivered, envelope: PeerMessage) -> Received:
        """I3 to I8 of section 20.2."""
        initial_header = envelope.initial_header
        pin = self.store.pin(delivered.sender)
        _check_initial_header(delivered.sender, initial_header, pin)

        record = self.store.record(delivered.sender, initial_header.ephemeral_key)
        if record is None:
            return self._accept_new(delivered, envelope, pin)
        session = self.store.session(record.session_id)
        if session is None:
            raise ReplayedInitialError("the record of the initial message has no session")
        return self._accept(delivered, session, self._decrypt(session, delivered, envelope))

    def _receive_on_list(self, delivered: Delivered, envelope: PeerMessage) -> Received:
        """I9 and I10 of section 20.2."""
        sessions = self.store.sessions(delivered.sender)
        if not sessions:
            raise NoSessionError("the contact has no session")
        for session in sessions:
            try:
                decrypted = self._decrypt(session, delivered, envelope)
            except DecryptFailedError:
                continue
            return self._accept(delivered, session, decrypted)
        raise DecryptFailedError("no session of the list decrypts the message")

    def _accept_new(
        self, delivered: Delivered, envelope: PeerMessage, pin: bytes | None
    ) -> Received:
        """Steps 3 to 9 of section 16.8 and ACCEPT-NEW of section 20.3."""
        initial_header = envelope.initial_header
        signed_prekey_id = initial_header.signed_prekey_id
        signed_prekey_private_key = self.store.signed_prekey(signed_prekey_id)
        if signed_prekey_private_key is None:
            raise UnknownSignedPrekeyError("no signed prekey has the id of the initial header")

        one_time_prekey_id: int | None = None
        one_time_prekey_private_key: bytes | None = None
        if initial_header.HasField("one_time_prekey_id"):
            one_time_prekey_id = initial_header.one_time_prekey_id
            one_time_prekey_private_key = self.store.one_time_prekey(one_time_prekey_id)
            if one_time_prekey_private_key is None:
                raise UnknownOneTimePrekeyError(
                    "no one-time prekey has the id of the initial header"
                )

        agreement = x3dh.respond(
            identity_key=self.identity_key,
            identity_dh_private_key=self._identity.identity_dh_private_key,
            signed_prekey_private_key=signed_prekey_private_key,
            one_time_prekey_private_key=one_time_prekey_private_key,
            sender_identity_key=delivered.sender,
            sender_identity_dh_key=initial_header.identity_dh_key,
            sender_identity_dh_signature=initial_header.identity_dh_signature,
            ephemeral_key=initial_header.ephemeral_key,
            pinned_identity_dh_key=pin,
        )
        state = ratchet.init_responder(
            shared_secret=agreement.shared_secret,
            signed_prekey_private_key=signed_prekey_private_key,
        )
        decrypted = self._decrypt_state(state, agreement.associated_data, delivered, envelope)
        text, result = _read_content(decrypted.padded_plaintext)

        with self.store.transaction():
            session_id = self.store.add_session(
                delivered.sender,
                associated_data=agreement.associated_data,
                state=decrypted.state,
                initial_header=None,
            )
            self.store.add_record(
                delivered.sender,
                initial_header.ephemeral_key,
                session_id=session_id,
                signed_prekey_id=signed_prekey_id,
            )
            if one_time_prekey_id is not None:
                self.store.delete_one_time_prekey(one_time_prekey_id)
            if pin is None:
                self.store.set_pin(delivered.sender, initial_header.identity_dh_key)
            self._save_received(delivered, text)
        return Received(ack=True, text=text, result=result)

    def _accept(
        self, delivered: Delivered, session: StoredSession, decrypted: ratchet.Decrypted
    ) -> Received:
        """ACCEPT of section 20.3."""
        text, result = _read_content(decrypted.padded_plaintext)
        with self.store.transaction():
            self.store.accept_on_session(session.session_id, decrypted.state)
            self._save_received(delivered, text)
        return Received(ack=True, text=text, result=result)

    def _save_received(self, delivered: Delivered, text: str | None) -> None:
        self.store.add_seen_id(delivered.sender, delivered.message_id)
        if text is not None:
            self.store.log_message(
                delivered.sender, direction="in", message_id=delivered.message_id, text=text
            )

    def _decrypt(
        self, session: StoredSession, delivered: Delivered, envelope: PeerMessage
    ) -> ratchet.Decrypted:
        return self._decrypt_state(session.state, session.associated_data, delivered, envelope)

    def _decrypt_state(
        self,
        state: RatchetState,
        associated_data: bytes,
        delivered: Delivered,
        envelope: PeerMessage,
    ) -> ratchet.Decrypted:
        """Section 17.7 on a copy of the state; any failure is DECRYPT_FAILED (20.2)."""
        try:
            return ratchet.decrypt(
                state,
                envelope.header,
                envelope.ciphertext,
                associated_data=associated_data + delivered.message_id,
                ratchet_private_key=self.random_bytes(KEY_LENGTH),
            )
        except CryptoError as error:
            raise DecryptFailedError("the message does not decrypt") from error

    def _identity_dh_signature(self) -> bytes:
        return sign_identity_dh_key(self._identity.seed, identity_dh_key=self.identity_dh_key)


def _check_initial_header(
    sender: bytes, initial_header: InitialHeader, pin: bytes | None
) -> None:
    """Steps 1 and 2 of section 16.8, before any Diffie-Hellman value.

    Raises:
        BadInitialHeaderError: The signature does not verify under the sender.
        IdentityKeyMismatchError: The key is not the pinned one.
    """
    try:
        verify_identity_dh_key(
            sender,
            identity_dh_key=initial_header.identity_dh_key,
            signature=initial_header.identity_dh_signature,
        )
    except BadBundleError as error:
        raise BadInitialHeaderError("the signature over the X25519 key fails") from error

    has_pin = pin is not None
    carries_another_key = initial_header.identity_dh_key != pin
    if has_pin and carries_another_key:
        raise IdentityKeyMismatchError("the initial header carries another X25519 key")


def _read_content(padded_plaintext: bytes) -> tuple[str | None, str | None]:
    """The text of a message that decrypted, or the result that it has none (20.3)."""
    try:
        return decode_text(padded_plaintext), None
    except (BadPaddingError, BadContentError, UnknownContentError) as error:
        return None, error.result
