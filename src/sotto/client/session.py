"""The session rules of docs/protocol.md: sections 16.6 to 16.8, 20, 21 and 22.2, no network.

`Client.receive` turns a delivered message into what to show and an ack, and
`Client.send_text` turns a text into the bytes of a Send. Both commit what they change
before they answer. The prekey lifecycle of section 21 is a set of methods that the network
client calls at a start and after a LoggedIn; every one reads the time from one clock.
The changes of part 5 (section 39) name a logged message by its number, its position in
the log.
"""

import itertools
import secrets
import time
from collections import defaultdict
from collections.abc import Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path

from sotto.client.envelope import (
    BLOB_ID_LENGTH,
    MAX_AVATAR_BYTES,
    MAX_CAPTION_BYTES,
    MAX_QUOTE_BYTES,
    MAX_RECEIPT_IDS,
    MESSAGE_ID_LENGTH,
    X3DH_VERSION,
    AvatarTooLargeError,
    BadContentError,
    BadPaddingError,
    BadProfileNameError,
    NotAnImageError,
    TextTooLongError,
    UnknownContentError,
    avatar_media_type,
    cut_to,
    encode_attachment,
    encode_deletion,
    encode_edit,
    encode_profile,
    encode_receipt,
    encode_text,
    encode_timer,
    is_profile_name,
    open_content,
    parse_envelope,
)
from sotto.client.files import save_file
from sotto.client.store import (
    FileRow,
    Identity,
    LoggedMessage,
    NewState,
    OutboxRow,
    OwnProfile,
    ReceiptKind,
    Store,
    StoredQuote,
    StoredSession,
    StoredSignedPrekey,
    UploadRow,
)
from sotto.crypto import pqxdh, ratchet
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
    Bundle,
    CryptoError,
    OneTimePrekey,
    SignedPrekey,
    decode_user_id,
    derive_identity_key,
    derive_x25519_public_key,
    sign_identity_dh_key,
    sign_login,
    sign_pq_prekey,
    sign_signed_prekey,
)
from sotto.crypto.pqxdh import KEM_SEED_LENGTH, kem_public_key
from sotto.crypto.ratchet import MESSAGE_NONCE_LENGTH, DecryptFailedError, RatchetState
from sotto.crypto.x3dh import check_initial_header
from sotto.proto.sotto_pb2 import (
    Attachment,
    Content,
    Deletion,
    Edit,
    InitialHeader,
    Login,
    PeerMessage,
    Profile,
    Quote,
    Receipt,
)

SEEN_ID_SECONDS = 3196800
SIGNED_PREKEY_ROTATION_SECONDS = 604800
SIGNED_PREKEY_GRACE_SECONDS = 3196800
ONE_TIME_PREKEY_REFILL_BELOW = 50
ONE_TIME_PREKEY_CAP = 100
ONE_TIME_PREKEY_HELD_MAX = 1000
PQ_ONE_TIME_PREKEY_REFILL_BELOW = 20
PQ_ONE_TIME_PREKEY_CAP = 40
PQ_ONE_TIME_PREKEY_HELD_MAX = 400
BLOB_GONE = "BLOB_GONE"
DELETED_ON_FAILURE = frozenset({BadBlobError.result, NotAnImageError.result})
MAX_EDITS = 10
EDIT_SECONDS = 86400

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


class UnknownPqPrekeyError(CryptoError):
    result = "UNKNOWN_PQ_PREKEY"


class X3dhRefusedError(CryptoError):
    result = "X3DH_REFUSED"


class FilesUnsupportedError(CryptoError):
    result = "FILES_UNSUPPORTED"


class FileTooLargeError(CryptoError):
    result = "FILE_TOO_LARGE"


class NoSuchMessageError(CryptoError):
    result = "NO_SUCH_MESSAGE"


class NotOwnMessageError(CryptoError):
    result = "NOT_OWN_MESSAGE"


class EditTooLateError(CryptoError):
    result = "EDIT_TOO_LATE"


class TooManyEditsError(CryptoError):
    result = "TOO_MANY_EDITS"


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
class Quoted:
    """The message a reply quotes as the client shows it: the number and the text of its
    own copy when it has one, else the text of the quote; no text once it is gone."""

    number: int | None
    text: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class Received:
    """What a Deliver gives: a text or an attachment to show, a profile that replaced the
    sender's earlier one, a change of part 5, or the named result of section 24.2.

    `missing` is the GAP of section 20.3: the messages of the sender that can never be read,
    counted by the skipped keys that this message removed without use. `number` is the
    message of the log that the Deliver added, or the one that an edit (`edited`, the new
    text in `text`) or a deletion (`deleted`) changed. `marked` are the own messages that a
    receipt reached, delivered or `read`; `timer` is a new timer of the chat.
    """

    ack: bool
    text: str | None
    result: str | None
    missing: int = 0
    attachment: Attachment | None = None
    profile: Profile | None = None
    number: int | None = None
    quote: Quoted | None = None
    expires_after: int = 0
    edited: bool = False
    deleted: bool = False
    marked: tuple[int, ...] = ()
    read: bool = False
    timer: int | None = None

    @property
    def is_a_new_message(self) -> bool:
        """A message of the chat that entered the log: a text or an attachment."""
        is_a_change = self.edited or self.deleted
        return self.number is not None and not is_a_change


@dataclass(frozen=True, slots=True, kw_only=True)
class Outgoing:
    """The fields of a Send; a repeated Send carries them unchanged (section 22.2).
    `number` is the message of the log that the Send carries, when it carries one."""

    message_id: bytes
    recipient: bytes
    payload: bytes
    number: int | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True, kw_only=True)
class _Sealed:
    """A message encrypted on the head session of a contact, not yet committed."""

    outgoing: Outgoing
    session_id: int
    state: RatchetState


@dataclass(frozen=True, slots=True, kw_only=True)
class PrekeyUpload:
    """The keys of an UploadBundle (section 21.4), saved before they are handed out.
    `pq_prekey` is the last-resort post-quantum prekey of the signed prekey (42.2)."""

    identity_dh_key: bytes
    identity_dh_signature: bytes
    signed_prekey: SignedPrekey
    one_time_prekeys: tuple[OneTimePrekey, ...]
    pq_prekey: SignedPrekey | None
    pq_one_time_prekeys: tuple[SignedPrekey, ...]


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
        self.expire_messages()

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

    def make_prekeys(self, one_time_count: int, pq_one_time_count: int) -> PrekeyUpload:
        """Makes a new signed prekey with its last-resort post-quantum prekey, and the
        one-time prekeys of both kinds that the counts ask for, and saves them."""
        with self.store.transaction():
            self._add_signed_prekey()
            one_time_prekeys = self._add_one_time_prekeys(one_time_count)
            pq_one_time_prekeys = self._add_pq_one_time_prekeys(pq_one_time_count)
        newest = self._newest_signed_prekey()
        return self._upload(newest, one_time_prekeys, pq_one_time_prekeys)

    def delete_expired_prekeys(self) -> None:
        """Step 1 of section 21.2, after every LoggedIn and at every start before a dial."""
        replaced_at_or_before = self.now() - SIGNED_PREKEY_GRACE_SECONDS
        with self.store.transaction():
            self.store.delete_signed_prekeys(replaced_at_or_before=replaced_at_or_before)

    def prepare_upload(
        self, one_time_prekey_count: int, pq_one_time_prekey_count: int
    ) -> PrekeyUpload | None:
        """Steps 1 and 2 of section 21.2 and the refills of sections 21.3 and 42.2, after
        a LoggedIn.

        Args:
            one_time_prekey_count: The count of the LoggedIn, the word of the relay.
            pq_one_time_prekey_count: Its count of one-time post-quantum prekeys.

        Returns:
            The one UploadBundle of the login, every key of it saved first, or None when
            the relay confirmed the newest signed prekey and no one-time prekey was made.
            A one-time prekey is made for one frame and put into no other (section 21.4).
        """
        self.delete_expired_prekeys()
        refill = 0
        if one_time_prekey_count < ONE_TIME_PREKEY_REFILL_BELOW:
            refill = ONE_TIME_PREKEY_CAP - one_time_prekey_count
        pq_refill = 0
        if pq_one_time_prekey_count < PQ_ONE_TIME_PREKEY_REFILL_BELOW:
            pq_refill = PQ_ONE_TIME_PREKEY_CAP - pq_one_time_prekey_count

        with self.store.transaction():
            if self._is_rotation_due():
                self._add_signed_prekey()
            one_time_prekeys = self._add_one_time_prekeys(refill)
            pq_one_time_prekeys = self._add_pq_one_time_prekeys(pq_refill)

        newest = self._newest_signed_prekey()
        relay_holds_the_newest = newest.confirmed
        made_no_one_time_prekey = not one_time_prekeys and not pq_one_time_prekeys
        if relay_holds_the_newest and made_no_one_time_prekey:
            return None
        return self._upload(newest, one_time_prekeys, pq_one_time_prekeys)

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
            for pq_one_time_prekey in upload.pq_one_time_prekeys:
                self.store.delete_pq_one_time_prekey(pq_one_time_prekey.id)

    def forget_seen_ids(self) -> None:
        """Deletes the seen ids and the traces of part 5 older than SEEN_ID_SECONDS, at a
        login (sections 20.4 and 39.7)."""
        seen_at_or_before = self.now() - SEEN_ID_SECONDS
        with self.store.transaction():
            self.store.delete_seen_ids(seen_at_or_before=seen_at_or_before)
            self.store.forget_traces(written_at_or_before=seen_at_or_before)

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
        """START of section 20.3: section 41.5 with a bundle fetched for the contact.

        It serves L1 without a session and L2, the reset: the new session enters the list
        at its head and the older ones stay behind it (section 20.6).

        Returns:
            The GAP of section 20.3: the skipped keys of a session that left the list.

        Raises:
            NotAContactError: The identity is not a contact.
            BadBundleError: Check 1, 2, 4, 6 or 7 of section 5.4 failed.
            IdentityKeyMismatchError: The bundle carries another key than the pin.
            PqPrekeyMissingError: The bundle carries no post-quantum prekey.
            ZeroDhError: A key of the bundle has small order.
        """
        if not self.store.is_contact(contact):
            raise NotAContactError("the identity is not a contact")
        pin = self.store.pin(contact)
        ephemeral_private_key = self.random_bytes(KEY_LENGTH)
        agreement = pqxdh.initiate(
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
            kem_ciphertext=agreement.kem_ciphertext,
            pq_prekey_id=agreement.pq_prekey_id,
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
            self._owe_profile_to_a_new_session(contact)
        return missing

    def send_text(
        self,
        contact: bytes,
        text: str,
        *,
        bundle: Bundle | None = None,
        reply_to: int | None = None,
    ) -> Outgoing:
        """L1 of section 20.2: the bytes of a Send, committed to the outbox first, with the
        number of the logged message. The text carries the timer of the chat and, with
        `reply_to`, a quote of that message of the chat (section 39.2).

        Args:
            contact: The identity key of the contact.
            text: The text to send.
            bundle: A bundle fetched for the contact; needed when it has no session.
            reply_to: The number of the message of the chat that the text answers.

        Raises:
            TextTooLongError: The text is longer than MAX_TEXT_BYTES, or with its quote
                longer than MAX_CONTENT_BYTES; nothing else ran.
            NoSuchMessageError: `reply_to` names no message of the chat with the contact.
            NotAContactError: The identity is not a contact.
            CryptoError: START failed with the result that it names.
            ValueError: The contact has no session and no bundle was given.
        """
        quote = None if reply_to is None else self._quote(contact, reply_to)
        expires_after = self.store.timer(contact)
        plaintext = encode_text(text, quote=quote, expires_after=expires_after)
        sealed = self._seal(contact, plaintext, bundle)
        with self.store.transaction():
            self._commit_sealed(sealed)
            number = self._log_own(sealed.outgoing, text, quote, expires_after)
        return replace(sealed.outgoing, number=number)

    def edit(
        self, contact: bytes, number: int, text: str, *, bundle: Bundle | None = None
    ) -> Outgoing:
        """Sends an edit of an own message of the chat and replaces its text, the caption of
        an attachment (section 39.3).

        Raises:
            NoSuchMessageError, NotOwnMessageError: The number names no own message of the
                chat with the contact.
            TooManyEditsError: The message was edited MAX_EDITS times.
            EditTooLateError: The message was logged more than EDIT_SECONDS ago.
            TextTooLongError: The text does not fit an edit, or a caption is longer than
                MAX_CAPTION_BYTES.
        """
        message = self._own_message(contact, number)
        now = self.now()
        if message.edits >= MAX_EDITS:
            raise TooManyEditsError(f"the message was edited {MAX_EDITS} times")
        if message.written_at is None or now - message.written_at > EDIT_SECONDS:
            raise EditTooLateError(f"an edit comes within {EDIT_SECONDS} seconds")
        is_a_file = bool(self.store.files_of(message))
        caption_is_too_long = is_a_file and len(text.encode()) > MAX_CAPTION_BYTES
        if caption_is_too_long:
            raise TextTooLongError(f"a caption is at most {MAX_CAPTION_BYTES} bytes")

        sealed = self._seal(contact, encode_edit(message.message_id, text), bundle)
        with self.store.transaction():
            self._commit_sealed(sealed)
            self.store.edit_message(message, text, at=now)
        return sealed.outgoing

    def delete(self, contact: bytes, number: int, *, bundle: Bundle | None = None) -> Outgoing:
        """Sends the request that both sides delete an own message of the chat, deletes it
        here and saves the DeleteBlob of the blob of an attachment (section 39.4).

        Raises:
            NoSuchMessageError, NotOwnMessageError: The number names no own message of the
                chat with the contact.
        """
        message = self._own_message(contact, number)
        sealed = self._seal(contact, encode_deletion(message.message_id), bundle)
        with self.store.transaction():
            self._commit_sealed(sealed)
            files = self._remove(message)
            for file in files:
                self.store.add_blob_deletion(self.identity_key, file.attachment.blob_id)
        _delete_saved_files(files)
        return sealed.outgoing

    def timer(self, contact: bytes) -> int:
        return self.store.timer(contact)

    def set_timer(
        self, contact: bytes, seconds: int, *, bundle: Bundle | None = None
    ) -> Outgoing:
        """Sends a new timer of the chat, 0 for none, and keeps it (section 39.6).

        Raises:
            BadTimerError: The seconds are above MAX_TIMER_SECONDS.
            NotAContactError: The identity is not a contact.
        """
        sealed = self._seal(contact, encode_timer(seconds), bundle)
        with self.store.transaction():
            self._commit_sealed(sealed)
            self.store.set_timer(contact, seconds)
        return sealed.outgoing

    def read_receipts(self) -> bool:
        return self.store.read_receipts()

    def set_read_receipts(self, *, on: bool) -> None:
        """Turns read receipts on or off; off, the read receipts still owed go out as
        delivery receipts (section 39.5)."""
        with self.store.transaction():
            self.store.set_read_receipts(on=on)
            if not on:
                self.store.owe_delivery_for_read()

    def mark_read(self, contact: bytes, numbers: Iterable[int]) -> None:
        """The user has seen these messages of the chat: their timer starts, and a read
        receipt is owed unless read receipts are off (sections 39.5 and 39.6)."""
        now = self.now()
        sends_read_receipts = self.store.read_receipts()
        with self.store.transaction():
            for number in numbers:
                message = self.store.message(number)
                if message is None or message.contact != contact:
                    continue
                is_own_or_seen = not message.incoming or message.read_at is not None
                if is_own_or_seen:
                    continue
                expires_at = now + message.expires_after if message.expires_after else None
                owed = ReceiptKind.READ if sends_read_receipts else message.owed
                self.store.set_read(message, read_at=now, expires_at=expires_at, owed=owed)

    def send_owed_receipts(self) -> list[Outgoing]:
        """Seals the receipts owed to contacts with a session, one message per contact and
        kind for up to MAX_RECEIPT_IDS messages, each committed with its debt cleared."""
        owed: defaultdict[tuple[bytes, bool], list[bytes]] = defaultdict(list)
        for contact, message_id, kind in self.store.owed_receipts():
            owed[contact, kind is ReceiptKind.READ].append(message_id)

        outgoing = []
        for (contact, read), message_ids in owed.items():
            if not self.has_session(contact):
                continue
            for batch in itertools.batched(message_ids, MAX_RECEIPT_IDS, strict=False):
                sealed = self._seal(contact, encode_receipt(batch, read=read), None)
                with self.store.transaction():
                    self._commit_sealed(sealed)
                    self.store.clear_owed(contact, batch)
                outgoing.append(sealed.outgoing)
        return outgoing

    def expire_messages(self) -> list[int]:
        """Removes the messages whose timer ran out, their files included, and returns their
        numbers (section 39.6)."""
        expired = self.store.expired_messages(self.now())
        if not expired:
            return []
        files = []
        with self.store.transaction():
            for message in expired:
                files += self._remove(message)
        _delete_saved_files(files)
        return [message.number for message in expired]

    def sent_number(self, message_id: bytes) -> int | None:
        """The number of the own message of the log with this id, while no receipt has
        reached it."""
        return self.store.own_message_without_receipt(message_id)

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
        attachment, blob = self._encrypt_file(file, media_type=media_type)
        attachment.file_name = file_name
        attachment.caption = caption
        encode_attachment(attachment)

        with self.store.transaction():
            self.store.add_upload(
                attachment.blob_id, contact=contact, attachment=attachment, blob=blob
            )
        return UploadRow(
            blob_id=attachment.blob_id,
            contact=contact,
            attachment=attachment,
            length=len(blob),
        )

    def uploads(self) -> list[UploadRow]:
        return self.store.uploads()

    def read_upload(self, blob_id: bytes, offset: int, length: int) -> bytes:
        return self.store.read_upload(blob_id, offset, length)

    def send_attachment(self, upload: UploadRow, *, bundle: Bundle | None = None) -> Outgoing:
        """Step 5 of section 33.2: SEND of the attachment, which deletes the upload. The
        upload of an avatar sends the own profile with its current name (section 36.2).

        Raises:
            NotAContactError: The identity is no longer a contact.
            CryptoError: START failed with the result that it names.
            ValueError: The contact has no session and no bundle was given.
        """
        expires_after = self.store.timer(upload.contact)
        if upload.profile:
            plaintext = encode_profile(self.store.own_profile().name, upload.attachment)
        else:
            plaintext = encode_attachment(upload.attachment, expires_after=expires_after)
        sealed = self._seal(upload.contact, plaintext, bundle)
        with self.store.transaction():
            self._commit_sealed(sealed)
            self.store.delete_upload(upload.blob_id)
            if upload.profile:
                return sealed.outgoing
            caption = upload.attachment.caption
            number = self._log_own(sealed.outgoing, caption, None, expires_after)
            self.store.add_file(
                upload.contact,
                incoming=False,
                message_id=sealed.outgoing.message_id,
                attachment=upload.attachment,
                state=FileState.SENDING,
            )
        return replace(sealed.outgoing, number=number)

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

    def finish_avatar_download(self, position: int) -> None:
        """Step 4 of section 33.3 for an avatar (section 36.3): opens the blob, keeps the
        image with the profile of its contact and saves the DeleteBlob of the blob.

        Raises:
            BadBlobError: The blob does not open (section 29.7); nothing is kept.
            NotAnImageError: The image does not start with the signature of its media type.
        """
        file = self._file(position)
        attachment = file.attachment
        image = open_blob(
            self.store.downloaded(position),
            file_key=attachment.key,
            size=attachment.size,
            digest=attachment.digest,
        )
        if avatar_media_type(image) != attachment.media_type:
            raise NotAnImageError("the avatar is not an image of its media type")
        with self.store.transaction():
            self.store.set_avatar(position, image)
            self.store.set_file_state(position, FileState.RECEIVED)
            self.store.add_blob_deletion(file.contact, attachment.blob_id)

    def fail_download(self, position: int, result: str) -> FileState:
        """Steps 5 and 6 of section 33.3: drops the downloaded bytes, and a BAD_BLOB or a
        NOT_AN_IMAGE also saves the DeleteBlob of the blob; returns the state that the
        file takes."""
        file = self._file(position)
        state = FileState.NOT_AVAILABLE if result == BLOB_GONE else FileState.NOT_RECEIVED
        with self.store.transaction():
            self.store.set_file_state(position, state)
            if result in DELETED_ON_FAILURE:
                self.store.add_blob_deletion(file.contact, file.attachment.blob_id)
        return state

    def blob_deletions(self) -> list[tuple[bytes, bytes]]:
        """The DeleteBlob frames still to send, as (uploader, blob id)."""
        return self.store.blob_deletions()

    def confirm_blob_deletion(self, uploader: bytes, blob_id: bytes) -> None:
        """Forgets a DeleteBlob that the relay handled (section 33.2, last paragraph)."""
        with self.store.transaction():
            self.store.delete_blob_deletion(uploader, blob_id)

    def own_profile(self) -> OwnProfile:
        return self.store.own_profile()

    def set_profile(self, name: str, avatar: bytes | None) -> None:
        """Saves the own profile and owes it to every contact with a session (section
        36.2); an empty name and no avatar clear it. A newer profile gives up the avatar
        upload of an older one.

        Raises:
            BadProfileNameError: The name breaks section 35.2.
            AvatarTooLargeError: The avatar is longer than MAX_AVATAR_BYTES.
            NotAnImageError: The avatar is neither a JPEG nor a PNG image.
        """
        if not is_profile_name(name):
            raise BadProfileNameError("the name is too long or holds a control character")
        media_type = ""
        if avatar is not None:
            if len(avatar) > MAX_AVATAR_BYTES:
                raise AvatarTooLargeError(f"the avatar is above {MAX_AVATAR_BYTES} bytes")
            media_type = avatar_media_type(avatar)

        with self.store.transaction():
            self.store.set_own_profile(name, avatar, media_type)
            for contact, _name in self.store.contacts():
                blob_id = self.store.profile_upload(contact)
                if blob_id is not None:
                    self.store.delete_upload(blob_id)
                    self.store.add_blob_deletion(self.identity_key, blob_id)
                if self.has_session(contact):
                    self.store.owe_profile(contact)

    def owe_profile(self, contact: bytes) -> None:
        with self.store.transaction():
            self.store.owe_profile(contact)

    def send_owed_profiles(self, *, blob_max_bytes: int) -> list[Outgoing]:
        """Turns the profile sends owed to contacts into messages (section 36.2).

        A profile without an avatar, or one whose avatar the relay does not take, is sealed
        and committed at once and returned as a Send. One with an avatar becomes an upload
        of `uploads`, whose message `send_attachment` sends once its blob is complete.
        """
        own = self.store.own_profile()
        outgoing = []
        for contact in self.store.owed_profiles():
            if not self.has_session(contact):
                continue
            if own.avatar is not None and blob_length(len(own.avatar)) <= blob_max_bytes:
                self._start_profile_upload(contact, own.avatar, own.media_type)
                continue
            sealed = self._seal(contact, encode_profile(own.name, None), None)
            with self.store.transaction():
                self._commit_sealed(sealed)
                self.store.delete_profile_send(contact)
            outgoing.append(sealed.outgoing)
        return outgoing

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
        check_initial_header(
            delivered.sender,
            identity_dh_key=initial_header.identity_dh_key,
            signature=initial_header.identity_dh_signature,
            pinned_identity_dh_key=pin,
        )

        record = self.store.record(delivered.sender, initial_header.ephemeral_key)
        if record is None:
            if envelope.version == X3DH_VERSION:
                raise X3dhRefusedError("a new session of version 1 is refused (41.10)")
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
        """Steps 3 to 10 of section 41.7 and ACCEPT-NEW of section 20.3."""
        initial_header = envelope.initial_header
        signed_prekey_id = initial_header.signed_prekey_id
        replaced_after = self.now() - SIGNED_PREKEY_GRACE_SECONDS
        signed_prekey_private_key = self.store.signed_prekey(
            signed_prekey_id, replaced_after=replaced_after
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

        pq_prekey_id = initial_header.pq_prekey_id
        pq_prekey = self.store.pq_prekey(pq_prekey_id, replaced_after=replaced_after)
        if pq_prekey is None:
            raise UnknownPqPrekeyError("no post-quantum prekey has the id of the header")

        agreement = pqxdh.respond(
            identity_key=self.identity_key,
            identity_dh_private_key=self._identity.identity_dh_private_key,
            signed_prekey_private_key=signed_prekey_private_key,
            one_time_prekey_private_key=one_time_prekey_private_key,
            pq_prekey_seed=pq_prekey.seed,
            sender_identity_key=delivered.sender,
            sender_identity_dh_key=initial_header.identity_dh_key,
            sender_identity_dh_signature=initial_header.identity_dh_signature,
            ephemeral_key=initial_header.ephemeral_key,
            kem_ciphertext=initial_header.kem_ciphertext,
            pinned_identity_dh_key=pin,
        )
        state = ratchet.init_responder(
            shared_secret=agreement.shared_secret,
            signed_prekey_private_key=signed_prekey_private_key,
        )
        decrypted = self._decrypt_state(state, agreement.associated_data, delivered, envelope)
        content, result = _read_content(decrypted.padded_plaintext)

        files: list[FileRow] = []
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
            if pq_prekey.is_one_time:
                self.store.delete_pq_one_time_prekey(pq_prekey_id)
            if pin is None:
                self.store.set_pin(delivered.sender, initial_header.identity_dh_key)
            self._owe_profile_to_a_new_session(delivered.sender)
            received = self._save_received(delivered, content, files)
        _delete_saved_files(files)
        return replace(received, result=result, missing=decrypted.purged + dropped)

    def _accept(
        self, delivered: Delivered, session: StoredSession, decrypted: ratchet.Decrypted
    ) -> Received:
        """ACCEPT of section 20.3."""
        content, result = _read_content(decrypted.padded_plaintext)
        files: list[FileRow] = []
        with self.store.transaction():
            self.store.accept_on_session(session.session_id, decrypted.state)
            received = self._save_received(delivered, content, files)
        _delete_saved_files(files)
        return replace(received, result=result, missing=decrypted.purged)

    def _save_received(
        self, delivered: Delivered, content: Content | None, removed: list[FileRow]
    ) -> Received:
        """Saves what an accepted message changes, in the caller's transaction; the files of
        a message that a deletion removed go into `removed`."""
        sender = delivered.sender
        self.store.add_seen_id(sender, delivered.message_id, seen_at=self.now())
        nothing = Received(ack=True, text=None, result=None)
        if content is None:
            return nothing

        match content.WhichOneof("body"):
            case "text" | "attachment":
                return self._save_message(delivered, content)
            case "profile":
                self._save_profile(delivered, content.profile)
                return replace(nothing, profile=content.profile)
            case "edit":
                return self._apply_edit(sender, content.edit)
            case "deletion":
                return self._apply_deletion(sender, content.deletion, removed)
            case "receipt":
                return self._apply_receipt(sender, content.receipt)
            case "timer":
                self.store.set_timer(sender, content.timer.seconds)
                return replace(nothing, timer=content.timer.seconds)
            case member:
                raise AssertionError(f"open_content passed the member {member} unchecked")

    def _save_message(self, delivered: Delivered, content: Content) -> Received:
        """A text or an attachment of the chat (section 39): logged with its quote and its
        timer and a delivery receipt owed, unless a deletion came first; an edit that came
        first gives its text."""
        sender, message_id = delivered.sender, delivered.message_id
        trace = self.store.trace(sender, incoming=True, message_id=message_id)
        nothing = Received(ack=True, text=None, result=None)
        if trace is not None and trace.gone:
            return nothing

        early_text = None if trace is None else trace.early_text
        attachment = content.attachment if content.HasField("attachment") else None
        text = content.text if attachment is None else attachment.caption
        if early_text is not None:
            text = early_text
            if attachment is not None:
                attachment.caption = early_text
        quote = self._received_quote(sender, content) if content.HasField("quote") else None

        number = self.store.log_message(
            sender, direction="in", message_id=message_id, text=text
        )
        state = NewState(
            written_at=self.now(),
            expires_after=content.expires_after,
            quote=quote,
            owed=ReceiptKind.DELIVERED,
        )
        self.store.save_state(sender, incoming=True, message_id=message_id, state=state)
        if attachment is not None:
            self.store.add_file(
                sender,
                incoming=True,
                message_id=message_id,
                attachment=attachment,
                state=FileState.OFFERED,
            )
        return Received(
            ack=True,
            text=None if attachment is not None else text,
            result=None,
            attachment=attachment,
            number=number,
            quote=None if quote is None else self._shown_quote(sender, quote),
            expires_after=content.expires_after,
        )

    def _received_quote(self, sender: bytes, content: Content) -> StoredQuote:
        """The quote of a received reply; `own` means the sender wrote the quoted message.
        The text of a quote of a message that is gone here is not kept."""
        quote = content.quote
        quoted_incoming = quote.own
        trace = self.store.trace(sender, incoming=quoted_incoming, message_id=quote.message_id)
        is_gone = trace is not None and trace.gone
        return StoredQuote(
            incoming=quoted_incoming,
            message_id=quote.message_id,
            text=None if is_gone else quote.text,
        )

    def _shown_quote(self, contact: bytes, quote: StoredQuote) -> Quoted:
        """The client's own copy of the quoted message when it has one (section 39.2)."""
        own_copy = self.store.message_by_id(
            contact, incoming=quote.incoming, message_id=quote.message_id
        )
        if own_copy is None:
            return Quoted(number=None, text=quote.text)
        return Quoted(number=own_copy.number, text=own_copy.text)

    def _apply_edit(self, sender: bytes, edit: Edit) -> Received:
        """An edit of a message of the sender's own (section 39.3); one that comes before
        its message is kept for it, one for a message that is gone is dropped."""
        nothing = Received(ack=True, text=None, result=None)
        now = self.now()
        message = self.store.message_by_id(sender, incoming=True, message_id=edit.message_id)
        if message is None:
            trace = self.store.trace(sender, incoming=True, message_id=edit.message_id)
            edits = 0 if trace is None else trace.edits
            is_awaited = trace is None or not trace.gone
            has_edits_left = edits < MAX_EDITS
            if is_awaited and has_edits_left:
                self.store.count_edit(sender, edit.message_id, at=now, early_text=edit.text)
            return nothing
        if message.edits >= MAX_EDITS:
            return nothing
        self.store.edit_message(message, edit.text, at=now)
        return replace(nothing, text=edit.text, number=message.number, edited=True)

    def _apply_deletion(
        self, sender: bytes, deletion: Deletion, removed: list[FileRow]
    ) -> Received:
        """Deletes a message of the sender's own; one that has not arrived is deleted when
        it comes (section 39.4)."""
        nothing = Received(ack=True, text=None, result=None)
        message_id = deletion.message_id
        message = self.store.message_by_id(sender, incoming=True, message_id=message_id)
        if message is None:
            self.store.leave_trace(sender, incoming=True, message_id=message_id, at=self.now())
            return nothing
        removed += self._remove(message)
        return replace(nothing, number=message.number, deleted=True)

    def _apply_receipt(self, sender: bytes, receipt: Receipt) -> Received:
        """Moves the own messages a receipt names forward: delivered, then read; a read
        receipt also counts as delivered, and a mark never goes back (section 39.5)."""
        mark = ReceiptKind.READ if receipt.read else ReceiptKind.DELIVERED
        marked = []
        for message_id in receipt.message_ids:
            message = self.store.message_by_id(sender, incoming=False, message_id=message_id)
            # A message logged before part 5 takes no mark (section 39.10).
            if message is None or message.written_at is None:
                continue
            moves_forward = message.receipt is None or (
                receipt.read and message.receipt is ReceiptKind.DELIVERED
            )
            if moves_forward:
                self.store.set_receipt(message, mark)
                marked.append(message.number)
        return Received(
            ack=True, text=None, result=None, marked=tuple(marked), read=receipt.read
        )

    def _remove(self, message: LoggedMessage) -> list[FileRow]:
        """Deletes a message of the log in the caller's transaction and returns its files;
        the blob of a received file that was not downloaded is deleted at the relay."""
        files = self.store.files_of(message)
        for file in files:
            not_downloaded = file.state in (FileState.OFFERED, FileState.RECEIVING)
            if file.incoming and not_downloaded:
                self.store.add_blob_deletion(file.contact, file.attachment.blob_id)
        self.store.remove_message(message, at=self.now())
        return files

    def _log_own(
        self, outgoing: Outgoing, text: str, quote: Quote | None, expires_after: int
    ) -> int:
        """Logs an own message of the chat in the caller's transaction; its timer runs from
        now (section 39.6)."""
        now = self.now()
        number = self.store.log_message(
            outgoing.recipient, direction="out", message_id=outgoing.message_id, text=text
        )
        stored_quote = None
        if quote is not None:
            stored_quote = StoredQuote(
                incoming=not quote.own, message_id=quote.message_id, text=quote.text
            )
        state = NewState(
            written_at=now,
            expires_after=expires_after,
            expires_at=now + expires_after if expires_after else None,
            quote=stored_quote,
        )
        self.store.save_state(
            outgoing.recipient, incoming=False, message_id=outgoing.message_id, state=state
        )
        return number

    def _quote(self, contact: bytes, number: int) -> Quote:
        quoted = self._message_of(contact, number)
        return Quote(
            message_id=quoted.message_id,
            own=not quoted.incoming,
            text=cut_to(quoted.text, MAX_QUOTE_BYTES),
        )

    def _message_of(self, contact: bytes, number: int) -> LoggedMessage:
        message = self.store.message(number)
        if message is None or message.contact != contact:
            raise NoSuchMessageError(f"the chat has no message {number}")
        return message

    def _own_message(self, contact: bytes, number: int) -> LoggedMessage:
        message = self._message_of(contact, number)
        if message.incoming:
            raise NotOwnMessageError(f"message {number} is the contact's")
        return message

    def _save_profile(self, delivered: Delivered, profile: Profile) -> None:
        """Section 36.3: the profile replaces the earlier one of its sender whole; an
        earlier avatar that was not downloaded gets its blob deleted."""
        contact = delivered.sender
        earlier = self.store.profile(contact)
        if earlier is not None and earlier.avatar_file is not None:
            earlier_file = self._file(earlier.avatar_file)
            if earlier_file.state in (FileState.OFFERED, FileState.RECEIVING):
                self.store.add_blob_deletion(contact, earlier_file.attachment.blob_id)
            self.store.delete_file(earlier.avatar_file)

        has_an_avatar = profile.HasField("avatar")
        is_the_empty_profile = not profile.name and not has_an_avatar
        if is_the_empty_profile:
            self.store.delete_profile(contact)
            return
        avatar_file = None
        if has_an_avatar:
            avatar_file = self.store.add_file(
                contact,
                incoming=True,
                message_id=delivered.message_id,
                attachment=profile.avatar,
                state=FileState.OFFERED,
            )
        self.store.set_profile(contact, profile.name, avatar_file=avatar_file)

    def _owe_profile_to_a_new_session(self, contact: bytes) -> None:
        """Section 36.2: a session that enters the list gets the own profile once, unless
        the profile is empty."""
        if not self.store.own_profile().is_empty:
            self.store.owe_profile(contact)

    def _start_profile_upload(self, contact: bytes, avatar: bytes, media_type: str) -> None:
        attachment, blob = self._encrypt_file(avatar, media_type=media_type)
        with self.store.transaction():
            self.store.add_upload(
                attachment.blob_id, contact=contact, attachment=attachment, blob=blob
            )
            self.store.start_profile_upload(contact, attachment.blob_id)

    def _encrypt_file(self, file: bytes, *, media_type: str) -> tuple[Attachment, bytes]:
        """Step 2 of section 33.2: a new blob id, file key and nonce, and the blob."""
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
        )
        return attachment, blob

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
            version=session.version,
            header=encrypted.header,
            ciphertext=encrypted.ciphertext,
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
        """Section 17.7 on a session of the version of the envelope only (41.10)."""
        if session.version != envelope.version:
            raise DecryptFailedError("the session is of another version than the envelope")
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

    def _add_pq_one_time_prekeys(self, count: int) -> tuple[SignedPrekey, ...]:
        """Makes `count` one-time post-quantum prekeys, first deleting those with the
        lowest ids that a batch would push past PQ_ONE_TIME_PREKEY_HELD_MAX (42.2)."""
        count = min(count, PQ_ONE_TIME_PREKEY_HELD_MAX, self.store.pq_prekey_ids_left())
        held = self.store.pq_one_time_prekey_count()
        over_the_bound = held + count - PQ_ONE_TIME_PREKEY_HELD_MAX
        if over_the_bound > 0:
            self.store.delete_lowest_pq_one_time_prekeys(over_the_bound)

        pq_one_time_prekeys = []
        for _ in range(count):
            seed = self.random_bytes(KEM_SEED_LENGTH)
            prekey_id = self.store.add_pq_prekey(seed, signed_prekey_id=None)
            if prekey_id is None:
                break
            pq_one_time_prekeys.append(self._signed_pq_prekey(prekey_id, seed))
        return tuple(pq_one_time_prekeys)

    def _add_signed_prekey(self) -> None:
        """Step 2 of section 21.2: a new signed prekey with its last-resort post-quantum
        prekey, inside the caller's transaction."""
        signed_prekey_id = self.store.add_signed_prekey(
            self.random_bytes(KEY_LENGTH), made_at=self.now()
        )
        if signed_prekey_id is not None:
            seed = self.random_bytes(KEM_SEED_LENGTH)
            self.store.add_pq_prekey(seed, signed_prekey_id=signed_prekey_id)

    def _is_rotation_due(self) -> bool:
        """Step 2 of section 21.2: no signed prekey, an old one, or one without a
        last-resort post-quantum prekey while its counter can still give one."""
        newest = self.store.newest_signed_prekey()
        if newest is None:
            return True
        is_old = self.now() - newest.made_at >= SIGNED_PREKEY_ROTATION_SECONDS
        lacks_a_pq_prekey = newest.pq_prekey is None
        can_make_a_pq_prekey = self.store.pq_prekey_ids_left() > 0
        return is_old or (lacks_a_pq_prekey and can_make_a_pq_prekey)

    def _signed_pq_prekey(self, prekey_id: int, seed: bytes) -> SignedPrekey:
        key = kem_public_key(seed)
        signature = sign_pq_prekey(self._identity.seed, pq_prekey=key)
        return SignedPrekey(id=prekey_id, key=key, signature=signature)

    def _upload(
        self,
        newest: StoredSignedPrekey,
        one_time_prekeys: tuple[OneTimePrekey, ...],
        pq_one_time_prekeys: tuple[SignedPrekey, ...],
    ) -> PrekeyUpload:
        """An UploadBundle of section 21.4 with the newest signed prekey and its pair."""
        signed_key = derive_x25519_public_key(newest.private_key)
        signed_prekey = SignedPrekey(
            id=newest.prekey_id,
            key=signed_key,
            signature=sign_signed_prekey(self._identity.seed, signed_prekey=signed_key),
        )
        pq_prekey = None
        if newest.pq_prekey is not None:
            pq_prekey = self._signed_pq_prekey(
                newest.pq_prekey.prekey_id, newest.pq_prekey.seed
            )
        return PrekeyUpload(
            identity_dh_key=self.identity_dh_key,
            identity_dh_signature=self._identity_dh_signature(),
            signed_prekey=signed_prekey,
            one_time_prekeys=one_time_prekeys,
            pq_prekey=pq_prekey,
            pq_one_time_prekeys=pq_one_time_prekeys,
        )

    def _newest_signed_prekey(self) -> StoredSignedPrekey:
        newest = self.store.newest_signed_prekey()
        if newest is None:
            raise RuntimeError("the identity holds no signed prekey")
        return newest

    def _identity_dh_signature(self) -> bytes:
        return sign_identity_dh_key(self._identity.seed, identity_dh_key=self.identity_dh_key)


def _read_content(padded_plaintext: bytes) -> tuple[Content | None, str | None]:
    """The content of a message that decrypted, or the result that it has none (20.3)."""
    try:
        return open_content(padded_plaintext), None
    except (BadPaddingError, BadContentError, UnknownContentError) as error:
        return None, error.result


def _delete_saved_files(files: list[FileRow]) -> None:
    """Removes the received files of messages that are gone, after their commit."""
    for file in files:
        if file.saved_as is None:
            continue
        # A file that cannot be removed stays where it is (section 39.4).
        with suppress(OSError):
            Path(file.saved_as).unlink()
