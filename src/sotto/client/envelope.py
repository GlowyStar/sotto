"""The peer envelope and the plaintext of docs/protocol.md, sections 19, 32 and 35."""

from google.protobuf.message import DecodeError

from sotto.crypto.blob import DIGEST_LENGTH, FILE_KEY_LENGTH, MAX_FILE_BYTES
from sotto.crypto.identity import KEY_LENGTH, SIGNATURE_LENGTH, CryptoError
from sotto.crypto.ratchet import HEADER_LENGTH, MESSAGE_NONCE_LENGTH, TAG_LENGTH
from sotto.proto.sotto_pb2 import Attachment, Content, PeerMessage, Profile

VERSION = 1
PADDING_BLOCK = 256
MAX_TEXT_BYTES = 65019
PADDING_MARK = b"\x80"
SEALING_OVERHEAD = MESSAGE_NONCE_LENGTH + TAG_LENGTH
BLOB_ID_LENGTH = 16
MAX_MEDIA_TYPE_BYTES = 127
MAX_FILE_NAME_BYTES = 255
MAX_THUMBNAIL_BYTES = 16384
MAX_CAPTION_BYTES = 4096
MAX_PROFILE_NAME_BYTES = 256
MAX_AVATAR_BYTES = 1048576
AVATAR_SIGNATURES = {"image/jpeg": b"\xff\xd8\xff", "image/png": b"\x89PNG\r\n\x1a\n"}
BIDI_CONTROLS = frozenset(
    chr(code)
    for code in (0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A))
)
LINE_SEPARATORS = frozenset((chr(0x2028), chr(0x2029)))
ESCAPED_ABOVE_C1 = BIDI_CONTROLS | LINE_SEPARATORS


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


def encode_text(text: str) -> bytes:
    """Returns the padded plaintext of a text.

    Raises:
        TextTooLongError: The text is longer than MAX_TEXT_BYTES in UTF-8.
    """
    text_length = len(text.encode("utf-8"))
    if text_length > MAX_TEXT_BYTES:
        raise TextTooLongError(f"the text is {text_length} bytes long, above {MAX_TEXT_BYTES}")
    return pad(Content(text=text).SerializeToString())


def encode_attachment(attachment: Attachment) -> bytes:
    """Returns the padded plaintext of an attachment that the client filled (section 32.1).

    Raises:
        ValueError: A field is beyond its limit of section 32.1.
    """
    _check_attachment_limits(attachment)
    return pad(Content(attachment=attachment).SerializeToString())


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


def decode_content(padded: bytes) -> str | Attachment | Profile:
    """Returns the text, the attachment or the profile of a padded plaintext by sections
    19.5, 19.6, 32.2 and 35.3.

    Raises:
        BadPaddingError: The plaintext has no padding.
        BadContentError: The content does not parse, a text that is not UTF-8 included, an
            attachment breaks a length of section 32.2 or a profile a check of 35.3.
        UnknownContentError: The content sets no member that this client knows.
    """
    try:
        content = Content.FromString(unpad(padded))
    except DecodeError as error:
        raise BadContentError("the plaintext is not a Content") from error

    match content.WhichOneof("body"):
        case "text":
            return content.text
        case "attachment":
            _check_attachment(content.attachment)
            return content.attachment
        case "profile":
            _check_profile(content.profile)
            return content.profile
        case _:
            raise UnknownContentError("the Content sets no member that this client knows")


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
