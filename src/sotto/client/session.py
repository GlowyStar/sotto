"""The session rules of docs/protocol.md: sections 16.6 to 16.8, 20, 21 and 22.2, no network.

`Client.receive` turns a delivered message into what to show and an ack, and
`Client.send_text` turns a text into the bytes of a Send. Both commit what they change
before they answer. The prekey lifecycle of section 21 is a set of methods that the network
client calls at a start and after a LoggedIn; every one reads the time from one clock.
"""

import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from sotto.client.envelope import (
    BLOB_ID_LENGTH,
    VERSION,
    BadContentError,
    BadPaddingError,
    UnknownContentError,
    decode_content,
    encode_attachment,
    encode_text,
    parse_envelope,
)
from sotto.client.files import save_file
from sotto.client.store import (
    FileRow,
    Identity,
    OutboxRow,
    Store,
    StoredSession,
    StoredSignedPrekey,
    UploadRow,
)
from sotto.crypto import ratchet, x3dh
from sotto.crypto.blob import (
    BLOB_NONCE_LENGTH,
    FILE_KEY_LENGTH,
    MAX_FILE_BYTES,
    BadBlobError,
    blob_length,
    digest_of,
    encrypt_blob,
    open_blob,
)
from sotto.crypto.identity import (
    KEY_LENGTH,
    NONCE_LENGTH,
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
    sign_login,
    sign_signed_prekey,
    verify_identity_dh_key,
)
from sotto.crypto.ratchet import MESSAGE_NONCE_LENGTH, DecryptFailedError, RatchetState
from sotto.crypto.x3dh import BadInitialHeaderError
from sotto.proto.sotto_pb2 import Attachment, InitialHeader, Login, PeerMessage

MESSAGE_ID_LENGTH = 16
SEEN_ID_SECONDS = 3196800
SIGNED_PREKEY_ROTATION_SECONDS = 604800
SIGNED_PREKEY_GRACE_SECONDS = 3196800
ONE_TIME_PREKEY_REFILL_BELOW = 50
ONE_TIME_PREKEY_CAP = 100
ONE_TIME_PREKEY_HELD_MAX = 1000
BLOB_GONE = "BLOB_GONE"

type RandomBytes = Callable[[int], bytes]
type Clock = Callable[[], float]


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


class FilesUnsupportedError(CryptoError):
    result = "FILES_UNSUPPORTED"


class FileTooLargeError(CryptoError):
    result = "FILE_TOO_LARGE"


class FileState(StrEnum):
    """The states of a file of section 33.5, as the store keeps them."""

    SENDING = "sending"
    SENT = "sent"
    NOT_SENT = "not sent"
    OFFERED = "offered"
    RECEIVING = "receiving"
    RECEIVED = "received"
    NOT_RECEIVED = "could not be received"
    NOT_AVAILABLE = "not available"


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
    """What a Deliver gives: a text or an attachment to show, or the named result of
    section 24.2.

    `missing` is the GAP of section 20.3: the messages of the sender that can never be read,
    counted by the skipped keys that this message removed without use.
    """

    ack: bool
    text: str | None
    result: str | None
    missing: int = 0
    attachment: Attachment | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Outgoing:
    """The fields of a Send; a repeated Send carries them unchanged (section 22.2)."""

    message_id: bytes
    recipient: bytes
    payload: bytes


@dataclass(frozen=True, slots=True, kw_only=True)
class _Sealed:
    """A message encrypted on the head session of a contact, not yet committed."""

    outgoing: Outgoing
    session_id: int
    state: RatchetState


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
        clock: The one clock, read in whole seconds (section 21.1).
    """

    def __init__(
        self,
        store: Store,
        *,
        random_bytes: RandomBytes = secrets.token_bytes,
        clock: Clock = time.time,
    ):
        self.store = store
        self.random_bytes = random_bytes
        self.clock = clock
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

    def now(self) -> int:
        return int(self.clock())

    def sign_login(self, *, server_name: str, server_nonce: bytes) -> Login:
        """The Login of section 8.1 for the nonce of a Hello and the server name of 8.2."""
        client_nonce = self.random_bytes(NONCE_LENGTH)
        signature = sign_login(
            self._identity.seed,
            server_name=server_name,
            server_nonce=server_nonce,
            client_nonce=client_nonce,
        )
        return Login(
            identity_key=self.identity_key, client_nonce=client_nonce, signature=signature
        )

    def make_prekeys(self, one_time_count: int) -> PrekeyUpload:
        """Makes a new signed prekey and `one_time_count` one-time prekeys and saves them."""
        now = self.now()
        with self.store.transaction():
            self.store.add_signed_prekey(self.random_bytes(KEY_LENGTH), made_at=now)
            one_time_prekeys = self._add_one_time_prekeys(one_time_count)
        return self._upload(self._newest_signed_prekey(), one_time_prekeys)

    def delete_expired_prekeys(self) -> None:
        """Step 1 of section 21.2, after every LoggedIn and at every start before a dial."""
        replaced_at_or_before = self.now() - SIGNED_PREKEY_GRACE_SECONDS
        with self.store.transaction():
            self.store.delete_signed_prekeys(replaced_at_or_before=replaced_at_or_before)

    def prepare_upload(self, one_time_prekey_count: int) -> PrekeyUpload | None:
        """Steps 1 and 2 of section 21.2 and the refill of section 21.3, after a LoggedIn.

        Args:
            one_time_prekey_count: The count of the LoggedIn, the word of the relay.

        Returns:
            The one UploadBundle of the login, every key of it saved first, or None when
            the relay confirmed the newest signed prekey and no one-time prekey was made.
            A one-time prekey is made for one frame and put into no other (section 21.4).
        """
        self.delete_expired_prekeys()
        now = self.now()
        refill = 0
        if one_time_prekey_count < ONE_TIME_PREKEY_REFILL_BELOW:
            refill = ONE_TIME_PREKEY_CAP - one_time_prekey_count

        with self.store.transaction():
            newest = self.store.newest_signed_prekey()
            if newest is None or now - newest.made_at >= SIGNED_PREKEY_ROTATION_SECONDS:
                self.store.add_signed_prekey(self.random_bytes(KEY_LENGTH), made_at=now)
            one_time_prekeys = self._add_one_time_prekeys(refill)

        newest = self._newest_signed_prekey()
        relay_holds_the_newest = newest.confirmed
        made_no_one_time_prekey = not one_time_prekeys
        if relay_holds_the_newest and made_no_one_time_prekey:
            return None
        return self._upload(newest, one_time_prekeys)

    def confirm_upload(self, upload: PrekeyUpload) -> None:
        """Records the BundleStored of an UploadBundle: the relay holds its signed prekey."""
        with self.store.transaction():
            self.store.confirm_signed_prekey(upload.signed_prekey.id)

    def drop_refused_upload(self, upload: PrekeyUpload) -> None:
        """Deletes the one-time prekeys of an UploadBundle that waited in Back off when its
        connection ended: the relay holds none of them (section 21.4). An UploadBundle
        without an answer needs no call, as the relay can hold its keys."""
        with self.store.transaction():
            for one_time_prekey in upload.one_time_prekeys:
                self.store.delete_one_time_prekey(one_time_prekey.id)

    def forget_seen_ids(self) -> None:
        """Deletes the seen ids older than SEEN_ID_SECONDS, at a login (section 20.4)."""
        seen_at_or_before = self.now() - SEEN_ID_SECONDS
        with self.store.transaction():
            self.store.delete_seen_ids(seen_at_or_before=seen_at_or_before)

    def add_contact(self, user_id: str, *, name: str | None = None) -> bytes:
        """Adds the identity of a user id, under a local name if given, and returns its
        identity key; a contact that exists keeps its name.

        Raises:
            InvalidIdError: The string is not a user id.
            OwnIdentityError: The id is the client's own.
        """
        contact = decode_user_id(user_id)
        if contact == self.identity_key:
            raise OwnIdentityError("the id of the client's own identity is never a contact")
        with self.store.transaction():
            self.store.add_contact(contact, name=name)
        return contact

    def remove_contact(self, contact: bytes) -> None:
        """Deletes a contact with its sessions; its seen ids and records stay (20.6)."""
        with self.store.transaction():
            self.store.remove_contact(contact)

    def has_session(self, contact: bytes) -> bool:
        return bool(self.store.sessions(contact))

    def start_session(self, contact: bytes, bundle: Bundle) -> int:
        """START of section 20.3: section 16.6 with a bundle fetched for the contact.

        It serves L1 without a session and L2, the reset: the new session enters the list
        at its head and the older ones stay behind it (section 20.6).

        Returns:
            The GAP of section 20.3: the skipped keys of a session that left the list.

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
            missing = self.store.drop_sessions_behind(contact)
            if pin is None:
                self.store.set_pin(contact, bundle.identity_dh_key)
        return missing

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
        sealed = self._seal(contact, encode_text(text), bundle)
        message_id = sealed.outgoing.message_id
        with self.store.transaction():
            self._commit_sealed(sealed)
            self.store.log_message(contact, direction="out", message_id=message_id, text=text)
        return sealed.outgoing

    def check_file(self, contact: bytes, size: int, *, blob_max_bytes: int) -> None:
        """The checks of section 33.1, in their order.

        Raises:
            NotAContactError: The identity is not a contact.
            FilesUnsupportedError: The relay announced no blob frames.
            FileTooLargeError: The file or its blob is longer than the limits allow.
        """
        if not self.store.is_contact(contact):
            raise NotAContactError("the identity is not a contact")
        if blob_max_bytes == 0:
            raise FilesUnsupportedError("the relay announced no blob frames")
        is_above_the_largest_file = size > MAX_FILE_BYTES
        is_above_the_relay = blob_length(size) > blob_max_bytes
        if is_above_the_largest_file or is_above_the_relay:
            raise FileTooLargeError(f"a file of {size} bytes is above the limits")

    def start_upload(
        self,
        contact: bytes,
        file: bytes,
        *,
        blob_max_bytes: int,
        file_name: str = "",
        media_type: str = "",
        caption: str = "",
    ) -> UploadRow:
        """Steps 1 and 2 of section 33.2: the checks, the blob and the upload, committed.

        Raises:
            NotAContactError, FilesUnsupportedError, FileTooLargeError: A check of 33.1.
            ValueError: A name, media type or caption is beyond its limit of 32.1.
        """
        self.check_file(contact, len(file), blob_max_bytes=blob_max_bytes)
        blob_id = self.random_bytes(BLOB_ID_LENGTH)
        file_key = self.random_bytes(FILE_KEY_LENGTH)
        blob = encrypt_blob(
            file, file_key=file_key, nonce=self.random_bytes(BLOB_NONCE_LENGTH)
        )
        attachment = Attachment(
            blob_id=blob_id,
            key=file_key,
            size=len(file),
            digest=digest_of(blob),
            media_type=media_type,
            file_name=file_name,
            caption=caption,
        )
        encode_attachment(attachment)

        with self.store.transaction():
            self.store.add_upload(blob_id, contact=contact, attachment=attachment, blob=blob)
        return UploadRow(
            blob_id=blob_id, contact=contact, attachment=attachment, length=len(blob)
        )

    def uploads(self) -> list[UploadRow]:
        return self.store.uploads()

    def read_upload(self, blob_id: bytes, offset: int, length: int) -> bytes:
        return self.store.read_upload(blob_id, offset, length)

    def send_attachment(self, upload: UploadRow, *, bundle: Bundle | None = None) -> Outgoing:
        """Step 5 of section 33.2: SEND of the attachment, which deletes the upload.

        Raises:
            NotAContactError: The identity is no longer a contact.
            CryptoError: START failed with the result that it names.
            ValueError: The contact has no session and no bundle was given.
        """
        sealed = self._seal(upload.contact, encode_attachment(upload.attachment), bundle)
        with self.store.transaction():
            self._commit_sealed(sealed)
            self.store.delete_upload(upload.blob_id)
            self.store.add_file(
                upload.contact,
                incoming=False,
                message_id=sealed.outgoing.message_id,
                attachment=upload.attachment,
                state=FileState.SENDING,
            )
        return sealed.outgoing

    def give_up_upload(self, blob_id: bytes) -> None:
        """Deletes an upload that is not sent and saves the DeleteBlob of its blob."""
        with self.store.transaction():
            self.store.delete_upload(blob_id)
            self.store.add_blob_deletion(self.identity_key, blob_id)

    def downloads(self) -> list[FileRow]:
        """The received files whose blob is not downloaded yet, offered or receiving."""
        waiting = (FileState.OFFERED, FileState.RECEIVING)
        return [row for row in self.store.files() if row.incoming and row.state in waiting]

    def begin_download(self, position: int) -> None:
        """Makes room for the blob of a received file in the store (section 33.3)."""
        file = self._file(position)
        with self.store.transaction():
            length = blob_length(file.attachment.size)
            self.store.begin_download(position, FileState.RECEIVING, length)

    def save_download_piece(self, position: int, data: bytes) -> None:
        """Saves bytes of a blob at its held length together with the new length."""
        with self.store.transaction():
            self.store.add_download_piece(position, data)

    def finish_download(self, position: int, folder: Path) -> Path:
        """Step 4 of section 33.3: opens the blob, writes the file into the folder, drops
        the downloaded bytes and saves the DeleteBlob of the blob.

        Raises:
            BadBlobError: The blob does not open (section 29.7); nothing is written.
        """
        file = self._file(position)
        attachment = file.attachment
        data = open_blob(
            self.store.downloaded(position),
            file_key=attachment.key,
            size=attachment.size,
            digest=attachment.digest,
        )
        path = save_file(folder, attachment.file_name, data)
        with self.store.transaction():
            self.store.set_file_state(position, FileState.RECEIVED, saved_as=str(path))
            self.store.add_blob_deletion(file.contact, attachment.blob_id)
        return path

    def fail_download(self, position: int, result: str) -> FileState:
        """Steps 5 and 6 of section 33.3: drops the downloaded bytes, and a BAD_BLOB also
        saves the DeleteBlob of the blob; returns the state that the file takes."""
        file = self._file(position)
        state = FileState.NOT_AVAILABLE if result == BLOB_GONE else FileState.NOT_RECEIVED
        with self.store.transaction():
            self.store.set_file_state(position, state)
            if result == BadBlobError.result:
                self.store.add_blob_deletion(file.contact, file.attachment.blob_id)
        return state

    def blob_deletions(self) -> list[tuple[bytes, bytes]]:
        """The DeleteBlob frames still to send, as (uploader, blob id)."""
        return self.store.blob_deletions()

    def confirm_blob_deletion(self, uploader: bytes, blob_id: bytes) -> None:
        """Forgets a DeleteBlob that the relay handled (section 33.2, last paragraph)."""
        with self.store.transaction():
            self.store.delete_blob_deletion(uploader, blob_id)

    def outbox(self) -> list[Outgoing]:
        """The Sends that the relay has not confirmed, to be sent again as they are."""
        return [
            Outgoing(message_id=row.message_id, recipient=row.recipient, payload=row.payload)
            for row in self.store.outbox()
        ]

    def confirm_stored(self, message_id: bytes) -> FileRow | None:
        """Removes the outbox row of a Send that the relay answered with Stored; a file
        that the message carries counts as sent (section 33.2, step 6) and is returned."""
        file = self.store.file_of_message(message_id)
        with self.store.transaction():
            self.store.remove_from_outbox(message_id)
            if file is not None:
                self.store.set_file_state(file.position, FileState.SENT)
        return file

    def drop_refused_send(self, message_id: bytes) -> FileRow | None:
        """Removes the outbox row of a Send that the relay refused with an action Stop; a
        file that the message carries is not sent, and the DeleteBlob of its blob is saved
        (section 33.2). The file is returned."""
        file = self.store.file_of_message(message_id)
        with self.store.transaction():
            self.store.remove_from_outbox(message_id)
            if file is not None:
                self.store.set_file_state(file.position, FileState.NOT_SENT)
                self.store.add_blob_deletion(self.identity_key, file.attachment.blob_id)
        return file

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
        signed_prekey_private_key = self.store.signed_prekey(
            signed_prekey_id, replaced_after=self.now() - SIGNED_PREKEY_GRACE_SECONDS
        )
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
        text, attachment, result = _read_content(decrypted.padded_plaintext)

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
            dropped = self.store.drop_sessions_behind(delivered.sender)
            if one_time_prekey_id is not None:
                self.store.delete_one_time_prekey(one_time_prekey_id)
            if pin is None:
                self.store.set_pin(delivered.sender, initial_header.identity_dh_key)
            self._save_received(delivered, text, attachment)
        return Received(
            ack=True,
            text=text,
            result=result,
            missing=decrypted.purged + dropped,
            attachment=attachment,
        )

    def _accept(
        self, delivered: Delivered, session: StoredSession, decrypted: ratchet.Decrypted
    ) -> Received:
        """ACCEPT of section 20.3."""
        text, attachment, result = _read_content(decrypted.padded_plaintext)
        with self.store.transaction():
            self.store.accept_on_session(session.session_id, decrypted.state)
            self._save_received(delivered, text, attachment)
        return Received(
            ack=True,
            text=text,
            result=result,
            missing=decrypted.purged,
            attachment=attachment,
        )

    def _save_received(
        self, delivered: Delivered, text: str | None, attachment: Attachment | None
    ) -> None:
        self.store.add_seen_id(delivered.sender, delivered.message_id, seen_at=self.now())
        if text is not None:
            self.store.log_message(
                delivered.sender, direction="in", message_id=delivered.message_id, text=text
            )
        if attachment is not None:
            self.store.add_file(
                delivered.sender,
                incoming=True,
                message_id=delivered.message_id,
                attachment=attachment,
                state=FileState.OFFERED,
            )

    def _seal(self, contact: bytes, padded_plaintext: bytes, bundle: Bundle | None) -> _Sealed:
        """L1 of section 20.2 up to the commit: START when the contact has no session.

        Raises:
            NotAContactError: The identity is not a contact.
            CryptoError: START failed with the result that it names.
            ValueError: The contact has no session and no bundle was given.
        """
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
        return _Sealed(outgoing=outgoing, session_id=session.session_id, state=encrypted.state)

    def _commit_sealed(self, sealed: _Sealed) -> None:
        """The chain advance and the outbox row of SEND, inside the caller's transaction."""
        outgoing = sealed.outgoing
        self.store.advance_session(sealed.session_id, sealed.state)
        self.store.add_to_outbox(
            OutboxRow(
                message_id=outgoing.message_id,
                recipient=outgoing.recipient,
                payload=outgoing.payload,
            )
        )

    def _file(self, position: int) -> FileRow:
        file = self.store.file(position)
        if file is None:
            raise ValueError(f"the store holds no file at position {position}")
        return file

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

    def _add_one_time_prekeys(self, count: int) -> tuple[OneTimePrekey, ...]:
        """Makes `count` one-time prekeys, first deleting those with the lowest ids that a
        batch would push past ONE_TIME_PREKEY_HELD_MAX (section 21.3)."""
        count = min(count, ONE_TIME_PREKEY_HELD_MAX, self.store.one_time_prekey_ids_left())
        over_the_bound = self.store.one_time_prekey_count() + count - ONE_TIME_PREKEY_HELD_MAX
        if over_the_bound > 0:
            self.store.delete_lowest_one_time_prekeys(over_the_bound)

        one_time_prekeys = []
        for _ in range(count):
            private_key = self.random_bytes(KEY_LENGTH)
            prekey_id = self.store.add_one_time_prekey(private_key)
            if prekey_id is None:
                break
            key = derive_x25519_public_key(private_key)
            one_time_prekeys.append(OneTimePrekey(id=prekey_id, key=key))
        return tuple(one_time_prekeys)

    def _upload(
        self, newest: StoredSignedPrekey, one_time_prekeys: tuple[OneTimePrekey, ...]
    ) -> PrekeyUpload:
        """An UploadBundle of section 21.4 with the newest signed prekey."""
        signed_key = derive_x25519_public_key(newest.private_key)
        signed_prekey = SignedPrekey(
            id=newest.prekey_id,
            key=signed_key,
            signature=sign_signed_prekey(self._identity.seed, signed_prekey=signed_key),
        )
        return PrekeyUpload(
            identity_dh_key=self.identity_dh_key,
            identity_dh_signature=self._identity_dh_signature(),
            signed_prekey=signed_prekey,
            one_time_prekeys=one_time_prekeys,
        )

    def _newest_signed_prekey(self) -> StoredSignedPrekey:
        newest = self.store.newest_signed_prekey()
        if newest is None:
            raise RuntimeError("the identity holds no signed prekey")
        return newest

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


def _read_content(
    padded_plaintext: bytes,
) -> tuple[str | None, Attachment | None, str | None]:
    """The text or the attachment of a message that decrypted, or the result that it has
    neither (20.3)."""
    try:
        content = decode_content(padded_plaintext)
    except (BadPaddingError, BadContentError, UnknownContentError) as error:
        return None, None, error.result
    if isinstance(content, str):
        return content, None, None
    return None, content, None
