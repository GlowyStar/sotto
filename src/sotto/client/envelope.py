"""The peer envelope and the plaintext of docs/protocol.md, section 19."""

from google.protobuf.message import DecodeError

from sotto.crypto.identity import KEY_LENGTH, SIGNATURE_LENGTH, CryptoError
from sotto.crypto.ratchet import HEADER_LENGTH, MESSAGE_NONCE_LENGTH, TAG_LENGTH
from sotto.proto.sotto_pb2 import Content, PeerMessage

VERSION = 1
PADDING_BLOCK = 256
MAX_TEXT_BYTES = 65019
PADDING_MARK = b"\x80"
SEALING_OVERHEAD = MESSAGE_NONCE_LENGTH + TAG_LENGTH


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


def decode_text(padded: bytes) -> str:
    """Returns the text of a padded plaintext by sections 19.5 and 19.6.

    Raises:
        BadPaddingError: The plaintext has no padding.
        BadContentError: The content does not parse, a text that is not UTF-8 included.
        UnknownContentError: The content sets no member that this client knows.
    """
    try:
        content = Content.FromString(unpad(padded))
    except DecodeError as error:
        raise BadContentError("the plaintext is not a Content") from error

    if content.WhichOneof("body") != "text":
        raise UnknownContentError("the Content sets no member that this client knows")
    return content.text


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
