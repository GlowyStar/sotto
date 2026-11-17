from collections.abc import Callable
from typing import Any

import pytest
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from google.protobuf.descriptor_pb2 import FieldDescriptorProto
from google.protobuf.json_format import MessageToDict
from google.protobuf.message import Message
from hypothesis import given
from hypothesis import strategies as st

from sotto.client.envelope import (
    MAX_AVATAR_BYTES,
    MAX_CAPTION_BYTES,
    MAX_CONTENT_BYTES,
    MAX_FILE_NAME_BYTES,
    MAX_MEDIA_TYPE_BYTES,
    MAX_PROFILE_NAME_BYTES,
    MAX_QUOTE_BYTES,
    MAX_RECEIPT_IDS,
    MAX_TEXT_BYTES,
    MAX_THUMBNAIL_BYTES,
    MAX_TIMER_SECONDS,
    PADDING_BLOCK,
    AvatarTooLargeError,
    BadContentError,
    BadEnvelopeError,
    BadPaddingError,
    BadProfileNameError,
    NotAnImageError,
    TextTooLongError,
    UnknownContentError,
    UnsupportedVersionError,
    avatar_media_type,
    decode_content,
    encode_attachment,
    encode_deletion,
    encode_edit,
    encode_profile,
    encode_receipt,
    encode_text,
    pad,
    parse_envelope,
    unpad,
)
from sotto.crypto.blob import MAX_FILE_BYTES
from sotto.proto.sotto_pb2 import (
    Attachment,
    Content,
    Deletion,
    Edit,
    InitialHeader,
    PeerMessage,
    Profile,
    Quote,
    Receipt,
    Timer,
)

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
    unknown_member = b"\x7a\x01x"
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


def avatar(**fields: Any) -> Attachment:
    defaults: dict[str, Any] = {
        "blob_id": bytes(16),
        "key": bytes(16),
        "size": 1000,
        "digest": bytes(32),
        "media_type": "image/jpeg",
    }
    return Attachment(**(defaults | fields))


def test_profile_encodes_and_decodes_with_and_without_an_avatar() -> None:
    with_avatar = avatar(width=512, height=512, thumbnail=b"\xff\xd8\xff")
    named = Profile(name="Alice")
    pictured = Profile(name="Alice", avatar=with_avatar)
    with_unknown_field = named.SerializeToString() + b"\x7a\x03new"

    assert decode_content(encode_profile("Alice", None)) == named
    assert decode_content(encode_profile("Alice", with_avatar)) == pictured
    assert pad(b"\x1a\x00") == encode_profile("", None)
    assert decode_content(encode_profile("", None)) == Profile()
    newer = decode_content(pad(b"\x1a\x0c" + with_unknown_field))
    assert isinstance(newer, Profile)
    assert (newer.name, newer.HasField("avatar")) == ("Alice", False)


def test_avatar_media_type_is_read_from_the_first_bytes() -> None:
    assert avatar_media_type(b"\xff\xd8\xff\xe0rest") == "image/jpeg"
    assert avatar_media_type(b"\x89PNG\r\n\x1a\nrest") == "image/png"
    for not_an_image in (b"GIF89a", b"", b"\xff\xd8", b"<svg>"):
        with pytest.raises(NotAnImageError):
            avatar_media_type(not_an_image)


@pytest.mark.parametrize(
    ("name", "avatar_fields", "refusal"),
    [
        ("x" * (MAX_PROFILE_NAME_BYTES + 1), None, BadProfileNameError),
        ("Alice\u202e", None, BadProfileNameError),
        ("Alice\n", None, BadProfileNameError),
        ("Alice", {"size": MAX_AVATAR_BYTES + 1}, AvatarTooLargeError),
        ("Alice", {"media_type": "image/gif"}, NotAnImageError),
        ("Alice", {"file_name": "me.jpg"}, ValueError),
        ("Alice", {"caption": "me"}, ValueError),
        ("Alice", {"thumbnail": bytes(MAX_THUMBNAIL_BYTES + 1)}, ValueError),
    ],
)
def test_profile_beyond_a_limit_of_section_35_2_is_not_encoded(
    name: str, avatar_fields: dict[str, Any] | None, refusal: type[Exception]
) -> None:
    picture = None if avatar_fields is None else avatar(**avatar_fields)

    with pytest.raises(refusal):
        encode_profile(name, picture)


@pytest.mark.parametrize(
    "profile",
    [
        Profile(name="x" * (MAX_PROFILE_NAME_BYTES + 1)),
        Profile(name="Al\x00ice"),
        Profile(name="Al\u0085ice"),
        Profile(name="Al\u2066ice"),
        Profile(avatar=avatar(blob_id=bytes(15))),
        Profile(avatar=avatar(digest=bytes(33))),
        Profile(avatar=avatar(size=MAX_AVATAR_BYTES + 1)),
        Profile(avatar=avatar(media_type="image/webp")),
        Profile(avatar=avatar(media_type="")),
    ],
)
def test_received_profile_that_breaks_section_35_3_is_bad_content(profile: Profile) -> None:
    with pytest.raises(BadContentError):
        decode_content(pad(Content(profile=profile).SerializeToString()))


def test_longest_profile_is_the_content_of_section_35_4_and_decodes() -> None:
    largest = avatar(
        size=MAX_AVATAR_BYTES,
        width=2**32 - 1,
        height=2**32 - 1,
        thumbnail=bytes(MAX_THUMBNAIL_BYTES),
    )
    name = "\u00e9" * (MAX_PROFILE_NAME_BYTES // 2)
    profile = Profile(name=name, avatar=largest)

    assert len(Content(profile=profile).SerializeToString()) == 16753
    assert decode_content(encode_profile(name, largest)) == profile


OLDER_MEMBERS = (
    ("text", 1, FieldDescriptorProto.TYPE_STRING),
    ("attachment", 2, FieldDescriptorProto.TYPE_BYTES),
    ("profile", 3, FieldDescriptorProto.TYPE_BYTES),
)


def content_of_a_client_without_part_4(parts: int = 3) -> type[Message]:
    """`Content` as a client of parts 1 to 3 has it, the members text and attachment, or of
    parts 1 to 4 with `parts` 4, which adds profile."""
    schema = descriptor_pb2.FileDescriptorProto(
        name="older.proto", package="older", syntax="proto3"
    )
    content = schema.message_type.add(name="Content")
    content.oneof_decl.add(name="body")
    for name, number, kind in OLDER_MEMBERS[: parts - 1]:
        content.field.add(
            name=name,
            number=number,
            type=kind,
            label=FieldDescriptorProto.LABEL_OPTIONAL,
            oneof_index=0,
        )
    pool = descriptor_pool.DescriptorPool()
    pool.Add(schema)
    return message_factory.GetMessageClass(pool.FindMessageTypeByName("older.Content"))


def test_profile_is_unknown_content_to_a_client_without_part_4() -> None:
    older_content = content_of_a_client_without_part_4()
    profile = Content(profile=Profile(name="Alice", avatar=avatar())).SerializeToString()
    text = Content(text="hi").SerializeToString()

    assert older_content.FromString(profile).WhichOneof("body") is None
    assert older_content.FromString(text).WhichOneof("body") == "text"


@pytest.mark.parametrize(
    "change",
    [
        Content(edit=Edit(message_id=bytes(16), text="new")),
        Content(deletion=Deletion(message_id=bytes(16))),
        Content(receipt=Receipt(read=True, message_ids=[bytes(16)])),
        Content(timer=Timer(seconds=3600)),
    ],
)
def test_change_is_unknown_content_and_a_reply_a_text_to_a_client_without_part_5(
    change: Content,
) -> None:
    older_content = content_of_a_client_without_part_4(parts=4)
    quote = Quote(message_id=bytes(16), own=True, text="are you coming?")
    reply = Content(text="yes", quote=quote, expires_after=3600).SerializeToString()

    assert older_content.FromString(change.SerializeToString()).WhichOneof("body") is None
    assert MessageToDict(older_content.FromString(reply)) == {"text": "yes"}


def test_longest_contents_are_those_of_section_38_4() -> None:
    longest_quote = Quote(
        message_id=bytes(16), own=True, text="\u00e9" * (MAX_QUOTE_BYTES // 2)
    )
    longest_reply = "x" * 64732
    receipt = Content(receipt=Receipt(read=True, message_ids=[bytes(16)] * MAX_RECEIPT_IDS))

    assert MAX_CONTENT_BYTES == 65023
    assert len(unpad(encode_edit(bytes(16), "x" * 64997))) == MAX_CONTENT_BYTES
    with pytest.raises(TextTooLongError):
        encode_edit(bytes(16), "x" * 64998)
    reply = encode_text(longest_reply, quote=longest_quote, expires_after=MAX_TIMER_SECONDS)
    assert len(unpad(reply)) == MAX_CONTENT_BYTES
    with pytest.raises(TextTooLongError):
        encode_text(longest_reply + "x", quote=longest_quote, expires_after=MAX_TIMER_SECONDS)
    assert len(receipt.SerializeToString()) == 18006


@pytest.mark.parametrize(
    "refused",
    [
        lambda: encode_text("hi", quote=Quote(message_id=bytes(15))),
        lambda: encode_text("hi", quote=Quote(message_id=bytes(16), text="x" * 257)),
        lambda: encode_edit(bytes(17), "new"),
        lambda: encode_deletion(b""),
        lambda: encode_receipt([bytes(16)] * (MAX_RECEIPT_IDS + 1), read=False),
    ],
)
def test_part_5_member_beyond_a_limit_of_section_38_2_is_not_encoded(
    refused: Callable[[], bytes],
) -> None:
    with pytest.raises(ValueError):
        refused()
