import pytest
from hypothesis import given
from hypothesis import strategies as st

from sotto.client.envelope import (
    MAX_CAPTION_BYTES,
    MAX_FILE_NAME_BYTES,
    MAX_MEDIA_TYPE_BYTES,
    MAX_TEXT_BYTES,
    MAX_THUMBNAIL_BYTES,
    PADDING_BLOCK,
    BadContentError,
    BadEnvelopeError,
    BadPaddingError,
    TextTooLongError,
    UnknownContentError,
    UnsupportedVersionError,
    decode_content,
    encode_attachment,
    encode_text,
    pad,
    parse_envelope,
)
from sotto.crypto.blob import MAX_FILE_BYTES
from sotto.proto.sotto_pb2 import Attachment, Content, InitialHeader, PeerMessage

GOOD_HEADER = bytes(40)
GOOD_CIPHERTEXT = bytes(284)
GOOD_INITIAL_HEADER = InitialHeader(
    identity_dh_key=bytes(32), identity_dh_signature=bytes(64), ephemeral_key=bytes(32)
)


def test_constants_are_those_of_section_24_1() -> None:
    assert (PADDING_BLOCK, MAX_TEXT_BYTES) == (256, 65019)


@pytest.mark.parametrize(
    ("content_length", "padded_length"), [(0, 256), (1, 256), (255, 256), (256, 512)]
)
def test_padding_adds_the_mark_and_zero_bytes_up_to_the_next_block(
    content_length: int, padded_length: int
) -> None:
    content = b"\x01" * content_length

    padded = pad(content)

    assert len(padded) == padded_length
    assert padded == content + b"\x80" + bytes(padded_length - content_length - 1)


@given(content=st.binary(max_size=1000), extra_zeros=st.integers(0, 600))
def test_receiver_takes_the_content_in_front_of_the_mark_behind_any_zero_bytes(
    content: bytes, extra_zeros: int
) -> None:
    text = content.decode("latin-1")
    padded = encode_text(text) + bytes(extra_zeros)

    assert decode_content(padded) == text


@pytest.mark.parametrize("padded", [b"", bytes(256), b"\x0a\x00\x81" + bytes(253)])
def test_plaintext_without_padding_is_bad_padding(padded: bytes) -> None:
    with pytest.raises(BadPaddingError):
        decode_content(padded)


def test_content_that_does_not_parse_or_is_not_utf8_is_bad_content() -> None:
    for content in (b"\x0a\x05ab", b"\x0a\x02\xff\xfe"):
        with pytest.raises(BadContentError):
            decode_content(pad(content))


def test_content_without_a_known_member_is_unknown_content() -> None:
    unknown_member = b"\x1a\x01x"
    for content in (Content().SerializeToString(), unknown_member):
        with pytest.raises(UnknownContentError):
            decode_content(pad(content))


def test_largest_text_fills_254_blocks_and_one_byte_more_is_refused() -> None:
    largest = "x" * MAX_TEXT_BYTES

    assert len(Content(text=largest).SerializeToString()) == 65023
    assert len(encode_text(largest)) == 254 * PADDING_BLOCK
    assert len(encode_text("")) == PADDING_BLOCK
    with pytest.raises(TextTooLongError):
        encode_text(largest + "x")
    with pytest.raises(TextTooLongError):
        encode_text(chr(0xE9) * (MAX_TEXT_BYTES // 2 + 1))


def envelope(**fields: object) -> bytes:
    peer_message = PeerMessage(version=1, header=GOOD_HEADER, ciphertext=GOOD_CIPHERTEXT)
    for name, value in fields.items():
        if isinstance(value, InitialHeader):
            peer_message.initial_header.CopyFrom(value)
        else:
            setattr(peer_message, name, value)
    return peer_message.SerializeToString()


def test_well_formed_envelope_parses_with_and_without_an_initial_header() -> None:
    parse_envelope(envelope())
    parse_envelope(envelope(ciphertext=bytes(28 + 512)))
    parsed = parse_envelope(envelope(initial_header=GOOD_INITIAL_HEADER) + b"\x2a\x01\x00")

    assert parsed.initial_header == GOOD_INITIAL_HEADER


def test_payload_that_is_no_peer_message_is_bad_envelope() -> None:
    for payload in (b"\xff", b"\x0a\x05ab", b"\x08"):
        with pytest.raises(BadEnvelopeError):
            parse_envelope(payload)


@given(version=st.integers(0, 2**32 - 1).filter(lambda version: version != 1))
def test_other_version_is_read_before_any_other_rule(version: int) -> None:
    with pytest.raises(UnsupportedVersionError):
        parse_envelope(envelope(version=version, header=b"", ciphertext=b""))


@pytest.mark.parametrize(
    "fields",
    [
        {"header": bytes(39)},
        {"header": bytes(41)},
        {"ciphertext": bytes(283)},
        {"ciphertext": bytes(285)},
        {"ciphertext": bytes(28)},
        {"initial_header": InitialHeader(identity_dh_key=bytes(31))},
        {
            "initial_header": InitialHeader(
                identity_dh_key=bytes(32), identity_dh_signature=bytes(63)
            )
        },
        {
            "initial_header": InitialHeader(
                identity_dh_key=bytes(32), identity_dh_signature=bytes(64), ephemeral_key=b""
            )
        },
    ],
)
def test_field_that_breaks_its_length_is_bad_envelope(fields: dict[str, object]) -> None:
    with pytest.raises(BadEnvelopeError):
        parse_envelope(envelope(**fields))


def longest_attachment() -> Attachment:
    return Attachment(
        blob_id=bytes(16),
        key=bytes(16),
        size=MAX_FILE_BYTES,
        digest=bytes(32),
        media_type="m" * MAX_MEDIA_TYPE_BYTES,
        file_name="n" * MAX_FILE_NAME_BYTES,
        width=2**32 - 1,
        height=2**32 - 1,
        thumbnail=bytes(MAX_THUMBNAIL_BYTES),
        caption="c" * MAX_CAPTION_BYTES,
    )


def test_longest_attachment_is_the_content_of_section_32_3_and_decodes() -> None:
    attachment = longest_attachment()

    assert len(Content(attachment=attachment).SerializeToString()) == 20965
    assert decode_content(encode_attachment(attachment)) == attachment


@pytest.mark.parametrize(
    "field", ["media_type", "file_name", "thumbnail", "caption", "size", "blob_id"]
)
def test_attachment_beyond_a_limit_of_section_32_1_is_not_encoded(field: str) -> None:
    attachment = longest_attachment()
    match field:
        case "size":
            attachment.size += 1
        case "thumbnail" | "blob_id":
            setattr(attachment, field, getattr(attachment, field) + b"x")
        case _:
            setattr(attachment, field, getattr(attachment, field) + "x")

    with pytest.raises(ValueError, match="limit"):
        encode_attachment(attachment)


@pytest.mark.parametrize(
    "change",
    [
        {"blob_id": bytes(15)},
        {"key": bytes(17)},
        {"digest": bytes(31)},
        {"size": MAX_FILE_BYTES + 1},
    ],
)
def test_received_attachment_that_breaks_section_32_2_is_bad_content(
    change: dict[str, bytes | int],
) -> None:
    attachment = Attachment(blob_id=bytes(16), key=bytes(16), digest=bytes(32))
    for field, value in change.items():
        setattr(attachment, field, value)

    with pytest.raises(BadContentError):
        decode_content(pad(Content(attachment=attachment).SerializeToString()))
