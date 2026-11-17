"""The peer envelope and the plaintext of docs/protocol.md, sections 19, 32, 35 and 38."""

from collections.abc import Sequence

from google.protobuf.message import DecodeError

from sotto.crypto.blob import DIGEST_LENGTH, FILE_KEY_LENGTH, MAX_FILE_BYTES
from sotto.crypto.identity import KEY_LENGTH, SIGNATURE_LENGTH, CryptoError
from sotto.crypto.ratchet import HEADER_LENGTH, MESSAGE_NONCE_LENGTH, TAG_LENGTH
from sotto.proto.sotto_pb2 import (
    Attachment,
    Content,
    Deletion,
    Edit,
    PeerMessage,
    Profile,
    Quote,
    Receipt,
    Timer,
)

VERSION = 1
PADDING_BLOCK = 256
MAX_TEXT_BYTES = 65019
MAX_CONTENT_BYTES = 65023
PADDING_MARK = b"\x80"
SEALING_OVERHEAD = MESSAGE_NONCE_LENGTH + TAG_LENGTH
BLOB_ID_LENGTH = 16
MAX_MEDIA_TYPE_BYTES = 127
MAX_FILE_NAME_BYTES = 255
MAX_THUMBNAIL_BYTES = 16384
MAX_CAPTION_BYTES = 4096
MAX_PROFILE_NAME_BYTES = 256
MAX_AVATAR_BYTES = 1048576
MESSAGE_ID_LENGTH = 16
MAX_QUOTE_BYTES = 256
MAX_TIMER_SECONDS = 2419200
MAX_RECEIPT_IDS = 1000
# The members that are messages of the chat; `quote` and `expires_after` go with them.
CHAT_MEMBERS = frozenset({"text", "attachment"})
AVATAR_SIGNATURES = {"image/jpeg": b"\xff\xd8\xff", "image/png": b"\x89PNG\r\n\x1a\n"}
BIDI_CONTROLS = frozenset(
    chr(code)
    for code in (0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A))
)
LINE_SEPARATORS = frozenset((chr(0x2028), chr(0x2029)))
ESCAPED_ABOVE_C1 = BIDI_CONTROLS | LINE_SEPARATORS

type Body = str | Attachment | Profile | Edit | Deletion | Receipt | Timer


class UnsupportedVersionError(CryptoError):
    result = "UNSUPPORTED_VERSION"


class BadEnvelopeError(CryptoError):
    result = "BAD_ENVELOPE"


class BadPaddingError(CryptoError):
    result = "BAD_PADDING"


class BadContentError(CryptoError):
    result = "BAD_CONTENT"


class UnknownContentError(CryptoError):
    result = "UNKNOWN_CONTENT"


class TextTooLongError(CryptoError):
    result = "TEXT_TOO_LONG"


class BadProfileNameError(CryptoError):
    result = "BAD_PROFILE_NAME"


class AvatarTooLargeError(CryptoError):
    result = "AVATAR_TOO_LARGE"


class NotAnImageError(CryptoError):
    result = "NOT_AN_IMAGE"


class BadTimerError(CryptoError):
    result = "BAD_TIMER"


def pad(content: bytes) -> bytes:
    """Returns P of section 19.6: the content, `80`, then `00` up to the next block."""
    padded_length = PADDING_BLOCK * (len(content) // PADDING_BLOCK + 1)
    return (content + PADDING_MARK).ljust(padded_length, b"\x00")


def unpad(padded: bytes) -> bytes:
    """Returns the content in front of the last byte that is not `00`.

    Raises:
        BadPaddingError: That byte is missing or is not `80`.
    """
    stripped = padded.rstrip(b"\x00")
    if not stripped.endswith(PADDING_MARK):
        raise BadPaddingError("the plaintext has no padding")
    return stripped[: -len(PADDING_MARK)]


def encode_text(text: str, *, quote: Quote | None = None, expires_after: int = 0) -> bytes:
    """Returns the padded plaintext of a text, a reply when it has a quote (section 38.2).

    Raises:
        TextTooLongError: The text is longer than MAX_TEXT_BYTES in UTF-8, or the content
            with its quote and timer longer than MAX_CONTENT_BYTES.
        BadTimerError: `expires_after` is above MAX_TIMER_SECONDS.
        ValueError: The quote breaks its limits of section 38.2.
    """
    text_length = len(text.encode("utf-8"))
    if text_length > MAX_TEXT_BYTES:
        raise TextTooLongError(f"the text is {text_length} bytes long, above {MAX_TEXT_BYTES}")
    return _padded_message(Content(text=text), quote, expires_after)


def encode_attachment(
    attachment: Attachment, *, quote: Quote | None = None, expires_after: int = 0
) -> bytes:
    """Returns the padded plaintext of an attachment that the client filled (section 32.1).

    Raises:
        BadTimerError: `expires_after` is above MAX_TIMER_SECONDS.
        ValueError: A field is beyond its limit of section 32.1, or the quote beyond its
            limits of section 38.2.
    """
    _check_attachment_limits(attachment)
    return _padded_message(Content(attachment=attachment), quote, expires_after)


def encode_edit(message_id: bytes, text: str) -> bytes:
    """Returns the padded plaintext of an edit (section 38.2).

    Raises:
        TextTooLongError: The content is longer than MAX_CONTENT_BYTES.
        ValueError: The message id is not MESSAGE_ID_LENGTH bytes.
    """
    _require_message_id(message_id)
    return _padded(Content(edit=Edit(message_id=message_id, text=text)))


def encode_deletion(message_id: bytes) -> bytes:
    """Returns the padded plaintext of a deletion for both (section 38.2).

    Raises:
        ValueError: The message id is not MESSAGE_ID_LENGTH bytes.
    """
    _require_message_id(message_id)
    return _padded(Content(deletion=Deletion(message_id=message_id)))


def encode_receipt(message_ids: Sequence[bytes], *, read: bool) -> bytes:
    """Returns the padded plaintext of a delivery or a read receipt (section 38.2).

    Raises:
        ValueError: An id is not MESSAGE_ID_LENGTH bytes, or there are more than
            MAX_RECEIPT_IDS.
    """
    if len(message_ids) > MAX_RECEIPT_IDS:
        raise ValueError(f"a receipt names at most {MAX_RECEIPT_IDS} messages")
    for message_id in message_ids:
        _require_message_id(message_id)
    return _padded(Content(receipt=Receipt(read=read, message_ids=message_ids)))


def encode_timer(seconds: int) -> bytes:
    """Returns the padded plaintext of a change of the chat timer (section 38.2).

    Raises:
        BadTimerError: The seconds are above MAX_TIMER_SECONDS.
    """
    _require_timer(seconds)
    return _padded(Content(timer=Timer(seconds=seconds)))


def _padded_message(content: Content, quote: Quote | None, expires_after: int) -> bytes:
    """A text or an attachment with the quote and the timer of part 5, padded."""
    _require_timer(expires_after)
    if quote is not None:
        _require_message_id(quote.message_id)
        if len(quote.text.encode()) > MAX_QUOTE_BYTES:
            raise ValueError(f"a quote holds at most {MAX_QUOTE_BYTES} bytes of text")
        content.quote.CopyFrom(quote)
    content.expires_after = expires_after
    return _padded(content)


def _padded(content: Content) -> bytes:
    """The padded plaintext of a content that fits a message whatever its session (38.4)."""
    serialized = content.SerializeToString()
    if len(serialized) > MAX_CONTENT_BYTES:
        raise TextTooLongError(
            f"the content is {len(serialized)} bytes long, above {MAX_CONTENT_BYTES}"
        )
    return pad(serialized)


def _require_message_id(message_id: bytes) -> None:
    if len(message_id) != MESSAGE_ID_LENGTH:
        raise ValueError(f"a message id is {MESSAGE_ID_LENGTH} bytes, not {len(message_id)}")


def _require_timer(seconds: int) -> None:
    if seconds > MAX_TIMER_SECONDS:
        raise BadTimerError(f"a timer is at most {MAX_TIMER_SECONDS} seconds, not {seconds}")


def cut_to(text: str, limit: int) -> str:
    """The longest start of `text` that is at most `limit` bytes of UTF-8."""
    return text.encode()[:limit].decode(errors="ignore")


def encode_profile(name: str, avatar: Attachment | None) -> bytes:
    """Returns the padded plaintext of the client's own profile (section 35.2).

    Raises:
        BadProfileNameError: The name is longer than MAX_PROFILE_NAME_BYTES or holds a
            control character.
        AvatarTooLargeError: The avatar is longer than MAX_AVATAR_BYTES.
        NotAnImageError: The media type of the avatar is not one of AVATAR_SIGNATURES.
        ValueError: A field of the avatar is beyond its limit of section 32.1, or it has a
            file name or a caption.
    """
    if not is_profile_name(name):
        raise BadProfileNameError("the name is too long or holds a control character")
    profile = Profile(name=name)
    if avatar is not None:
        if avatar.size > MAX_AVATAR_BYTES:
            raise AvatarTooLargeError(f"the avatar is above {MAX_AVATAR_BYTES} bytes")
        if avatar.media_type not in AVATAR_SIGNATURES:
            raise NotAnImageError("the avatar is not a JPEG or PNG image")
        if avatar.file_name or avatar.caption:
            raise ValueError("an avatar has no file name and no caption")
        _check_attachment_limits(avatar)
        profile.avatar.CopyFrom(avatar)
    return pad(Content(profile=profile).SerializeToString())


def is_profile_name(name: str) -> bool:
    """Whether a name keeps the rule of section 35.2: its length and no control character."""
    is_too_long = len(name.encode()) > MAX_PROFILE_NAME_BYTES
    return not is_too_long and not any(is_control(character) for character in name)


def avatar_media_type(image: bytes) -> str:
    """The media type of an avatar by its first bytes (section 35.2).

    Raises:
        NotAnImageError: The bytes start with no signature of AVATAR_SIGNATURES.
    """
    for media_type, signature in AVATAR_SIGNATURES.items():
        if image.startswith(signature):
            return media_type
    raise NotAnImageError("the bytes are not a JPEG or PNG image")


def _check_attachment_limits(attachment: Attachment) -> None:
    breaks_a_limit = (
        len(attachment.blob_id) != BLOB_ID_LENGTH
        or len(attachment.key) != FILE_KEY_LENGTH
        or len(attachment.digest) != DIGEST_LENGTH
        or attachment.size > MAX_FILE_BYTES
        or len(attachment.media_type.encode()) > MAX_MEDIA_TYPE_BYTES
        or len(attachment.file_name.encode()) > MAX_FILE_NAME_BYTES
        or len(attachment.thumbnail) > MAX_THUMBNAIL_BYTES
        or len(attachment.caption.encode()) > MAX_CAPTION_BYTES
    )
    if breaks_a_limit:
        raise ValueError("a field of the attachment is beyond its limit of section 32.1")


def decode_content(padded: bytes) -> Body:
    """Returns the member of the body of a padded plaintext that `open_content` checked."""
    content = open_content(padded)
    body: Body = getattr(content, str(content.WhichOneof("body")))
    return body


def open_content(padded: bytes) -> Content:
    """Returns the content of a padded plaintext by sections 19.5, 19.6, 32.2, 35.3 and
    38.3; `quote` and `expires_after` are cleared unless the body is a text or an
    attachment, which alone they go with.

    Raises:
        BadPaddingError: The plaintext has no padding.
        BadContentError: The content does not parse, a string that is not UTF-8 included, or
            a member breaks a check of section 32.2, 35.3 or 38.3.
        UnknownContentError: The content sets no member that this client knows.
    """
    try:
        content = Content.FromString(unpad(padded))
    except DecodeError as error:
        raise BadContentError("the plaintext is not a Content") from error

    member = content.WhichOneof("body")
    match member:
        case "text":
            pass
        case "attachment":
            _check_attachment(content.attachment)
        case "profile":
            _check_profile(content.profile)
        case "edit":
            _check_message_id(content.edit.message_id)
        case "deletion":
            _check_message_id(content.deletion.message_id)
        case "receipt":
            for message_id in content.receipt.message_ids:
                _check_message_id(message_id)
        case "timer":
            _check_seconds(content.timer.seconds)
        case _:
            raise UnknownContentError("the Content sets no member that this client knows")

    if member not in CHAT_MEMBERS:
        content.ClearField("quote")
        content.ClearField("expires_after")
        return content
    if content.HasField("quote"):
        _check_message_id(content.quote.message_id)
    _check_seconds(content.expires_after)
    return content


def is_control(character: str) -> bool:
    """A character that section 19.5 escapes: C0, DEL, C1, bidi controls, line separators."""
    code = ord(character)
    is_c0_or_del = code < 0x20 or code == 0x7F
    is_c1 = 0x80 <= code <= 0x9F
    return is_c0_or_del or is_c1 or character in ESCAPED_ABOVE_C1


def _check_attachment(attachment: Attachment) -> None:
    lengths = (len(attachment.blob_id), len(attachment.key), len(attachment.digest))
    if lengths != (BLOB_ID_LENGTH, FILE_KEY_LENGTH, DIGEST_LENGTH):
        raise BadContentError("a field of the attachment breaks its length")
    if attachment.size > MAX_FILE_BYTES:
        raise BadContentError(f"the attachment names a file above {MAX_FILE_BYTES} bytes")


def _check_message_id(message_id: bytes) -> None:
    if len(message_id) != MESSAGE_ID_LENGTH:
        raise BadContentError("a message id of the content breaks its length")


def _check_seconds(seconds: int) -> None:
    if seconds > MAX_TIMER_SECONDS:
        raise BadContentError(f"a timer of the content is above {MAX_TIMER_SECONDS} seconds")


def _check_profile(profile: Profile) -> None:
    if not is_profile_name(profile.name):
        raise BadContentError("the name of the profile breaks section 35.3")
    if not profile.HasField("avatar"):
        return
    avatar = profile.avatar
    _check_attachment(avatar)
    is_too_large = avatar.size > MAX_AVATAR_BYTES
    is_no_image_type = avatar.media_type not in AVATAR_SIGNATURES
    if is_too_large or is_no_image_type:
        raise BadContentError("the avatar of the profile breaks section 35.3")


def parse_envelope(payload: bytes) -> PeerMessage:
    """Turns a payload into an envelope by the three steps of section 19.4.

    Raises:
        BadEnvelopeError: The payload is no PeerMessage, or a field breaks its length.
        UnsupportedVersionError: The version is not 1.
    """
    try:
        envelope = PeerMessage.FromString(payload)
    except DecodeError as error:
        raise BadEnvelopeError("the payload is not a PeerMessage") from error

    if envelope.version != VERSION:
        raise UnsupportedVersionError(f"the envelope has version {envelope.version}")

    padded_length = len(envelope.ciphertext) - SEALING_OVERHEAD
    header_breaks_its_length = len(envelope.header) != HEADER_LENGTH
    is_too_short = padded_length < PADDING_BLOCK
    is_off_the_blocks = padded_length % PADDING_BLOCK != 0
    if header_breaks_its_length or is_too_short or is_off_the_blocks:
        raise BadEnvelopeError("the header or the ciphertext breaks its length")

    if envelope.HasField("initial_header"):
        initial_header = envelope.initial_header
        lengths = (
            len(initial_header.identity_dh_key),
            len(initial_header.identity_dh_signature),
            len(initial_header.ephemeral_key),
        )
        if lengths != (KEY_LENGTH, SIGNATURE_LENGTH, KEY_LENGTH):
            raise BadEnvelopeError("a field of the initial header breaks its length")
    return envelope
