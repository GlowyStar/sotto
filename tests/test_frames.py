import os
from collections.abc import Callable

import pytest
from hypothesis import given
from hypothesis import strategies as st
from relay_harness import build_upload

from sotto.proto.sotto_pb2 import (
    Ack,
    BlobData,
    ClientFrame,
    DeleteBlob,
    FetchBlob,
    FetchBundle,
    Login,
    MessageRef,
    OneTimePrekey,
    PutBlob,
    Send,
    ServerFrame,
    SignedPrekey,
    StartBlob,
    UploadBundle,
)
from sotto.relay.frames import (
    BLOB_CHUNK_BYTES,
    MAX_FRAME_BYTES,
    MAX_PAYLOAD_BYTES,
    MalformedFrameError,
    ParsedFrame,
    parse_client_frame,
)

UNKNOWN_FIELD = b"\x7a\x03new"

fields = st.one_of(st.binary(max_size=80), st.binary(min_size=32, max_size=32))
signatures = st.one_of(st.binary(max_size=80), st.binary(min_size=64, max_size=64))
ids = st.integers(0, 2**32 - 1)
logins = st.builds(Login, identity_key=fields, client_nonce=fields, signature=signatures)
uploads = st.builds(
    UploadBundle,
    identity_dh_key=fields,
    identity_dh_signature=signatures,
    signed_prekey=st.none()
    | st.builds(SignedPrekey, id=ids, key=fields, signature=signatures),
    one_time_prekeys=st.lists(st.builds(OneTimePrekey, id=ids, key=fields), max_size=3),
)
fetches = st.builds(FetchBundle, identity=fields)
message_ids = st.one_of(st.binary(max_size=24), st.binary(min_size=16, max_size=16))
sends = st.builds(
    Send, message_id=message_ids, recipient=fields, payload=st.binary(max_size=8)
)
acks = st.builds(
    Ack,
    messages=st.lists(
        st.builds(MessageRef, message_id=message_ids, sender=fields), max_size=3
    ),
)
blob_ids = st.one_of(st.binary(max_size=24), st.binary(min_size=16, max_size=16))
chunk_lengths = st.sampled_from([0, 1, BLOB_CHUNK_BYTES, BLOB_CHUNK_BYTES + 1])
starts = st.builds(
    StartBlob, blob_id=blob_ids, recipient=fields, length=st.sampled_from([0, 1, 2**32 - 1])
)
puts = st.builds(
    PutBlob,
    blob_id=blob_ids,
    offset=ids,
    data=st.one_of(st.binary(max_size=8), chunk_lengths.map(bytes)),
)
blob_fetches = st.builds(
    FetchBlob, blob_id=blob_ids, uploader=fields, offset=ids, length=chunk_lengths
)
deletes = st.builds(DeleteBlob, blob_id=blob_ids, uploader=fields)
serialized_frames = st.one_of(
    logins.map(lambda login: ClientFrame(login=login)),
    uploads.map(lambda upload: ClientFrame(upload_bundle=upload)),
    fetches.map(lambda fetch: ClientFrame(fetch_bundle=fetch)),
    sends.map(lambda send: ClientFrame(send=send)),
    acks.map(lambda ack: ClientFrame(ack=ack)),
    starts.map(lambda start: ClientFrame(start_blob=start)),
    puts.map(lambda put: ClientFrame(put_blob=put)),
    blob_fetches.map(lambda fetch: ClientFrame(fetch_blob=fetch)),
    deletes.map(lambda delete: ClientFrame(delete_blob=delete)),
).map(lambda frame: frame.SerializeToString())
damaged_frames = st.tuples(serialized_frames, st.binary(max_size=8), st.integers(0, 200)).map(
    lambda parts: parts[0][: parts[2]] + parts[1] + parts[0][parts[2] :]
)
messages = st.one_of(st.binary(max_size=300), serialized_frames, damaged_frames)


def complete_login() -> Login:
    return Login(
        identity_key=os.urandom(32), client_nonce=os.urandom(32), signature=os.urandom(64)
    )


def lengths_of(frame: ParsedFrame) -> list[int]:
    """Returns the length of every field that a frame table gives a length."""
    match frame:
        case Login():
            return [len(frame.identity_key), len(frame.client_nonce), len(frame.signature)]
        case UploadBundle():
            signed_prekey = frame.signed_prekey
            return [
                len(frame.identity_dh_key),
                len(frame.identity_dh_signature),
                len(signed_prekey.key),
                len(signed_prekey.signature),
                *(len(prekey.key) for prekey in frame.one_time_prekeys),
            ]
        case FetchBundle():
            return [len(frame.identity)]
        case Send():
            return [len(frame.message_id), len(frame.recipient)]
        case Ack():
            return [
                length
                for message in frame.messages
                for length in (len(message.message_id), len(message.sender))
            ]
        case StartBlob():
            return [len(frame.blob_id), len(frame.recipient)]
        case PutBlob():
            return [len(frame.blob_id)]
        case FetchBlob() | DeleteBlob():
            return [len(frame.blob_id), len(frame.uploader)]


def test_complete_login_is_returned_with_its_fields() -> None:
    login = complete_login()

    parsed = parse_client_frame(ClientFrame(login=login).SerializeToString())

    assert parsed == login


def test_complete_upload_is_returned_with_its_fields() -> None:
    upload = build_upload(os.urandom(32), [0, 2**32 - 1])

    parsed = parse_client_frame(ClientFrame(upload_bundle=upload).SerializeToString())

    assert parsed == upload


def test_upload_without_one_time_prekeys_is_complete() -> None:
    upload = build_upload(os.urandom(32))

    parsed = parse_client_frame(ClientFrame(upload_bundle=upload).SerializeToString())

    assert parsed == upload


def test_complete_fetch_is_returned_with_its_field() -> None:
    fetch = FetchBundle(identity=os.urandom(32))

    parsed = parse_client_frame(ClientFrame(fetch_bundle=fetch).SerializeToString())

    assert parsed == fetch


@pytest.mark.parametrize(
    ("field", "length"),
    [
        ("identity_key", 0),
        ("identity_key", 31),
        ("identity_key", 33),
        ("client_nonce", 0),
        ("client_nonce", 31),
        ("client_nonce", 33),
        ("signature", 0),
        ("signature", 63),
        ("signature", 65),
    ],
)
def test_login_with_a_field_of_another_length_is_malformed(field: str, length: int) -> None:
    login = complete_login()
    setattr(login, field, os.urandom(length))

    with pytest.raises(MalformedFrameError):
        parse_client_frame(ClientFrame(login=login).SerializeToString())


def the_upload(upload: UploadBundle) -> object:
    return upload


def the_signed_prekey(upload: UploadBundle) -> object:
    return upload.signed_prekey


def the_first_one_time_prekey(upload: UploadBundle) -> object:
    return upload.one_time_prekeys[0]


def the_last_one_time_prekey(upload: UploadBundle) -> object:
    return upload.one_time_prekeys[-1]


@pytest.mark.parametrize(
    ("holder_of", "field", "length"),
    [
        (the_upload, "identity_dh_key", 0),
        (the_upload, "identity_dh_key", 31),
        (the_upload, "identity_dh_key", 33),
        (the_upload, "identity_dh_signature", 0),
        (the_upload, "identity_dh_signature", 63),
        (the_upload, "identity_dh_signature", 65),
        (the_signed_prekey, "key", 0),
        (the_signed_prekey, "key", 31),
        (the_signed_prekey, "key", 33),
        (the_signed_prekey, "signature", 0),
        (the_signed_prekey, "signature", 63),
        (the_signed_prekey, "signature", 65),
        (the_first_one_time_prekey, "key", 31),
        (the_last_one_time_prekey, "key", 0),
        (the_last_one_time_prekey, "key", 33),
    ],
)
def test_upload_with_a_field_of_another_length_is_malformed(
    holder_of: Callable[[UploadBundle], object], field: str, length: int
) -> None:
    upload = build_upload(os.urandom(32), [1, 2, 3])
    setattr(holder_of(upload), field, os.urandom(length))

    with pytest.raises(MalformedFrameError):
        parse_client_frame(ClientFrame(upload_bundle=upload).SerializeToString())


def test_upload_without_a_signed_prekey_is_malformed() -> None:
    upload = build_upload(os.urandom(32))
    upload.ClearField("signed_prekey")

    with pytest.raises(MalformedFrameError):
        parse_client_frame(ClientFrame(upload_bundle=upload).SerializeToString())


@pytest.mark.parametrize("payload_length", [1, MAX_PAYLOAD_BYTES])
def test_complete_send_is_returned_with_its_fields(payload_length: int) -> None:
    send = Send(
        message_id=os.urandom(16), recipient=os.urandom(32), payload=os.urandom(payload_length)
    )

    parsed = parse_client_frame(ClientFrame(send=send).SerializeToString())

    assert parsed == send


@pytest.mark.parametrize("payload_length", [0, MAX_PAYLOAD_BYTES + 1])
def test_send_with_a_payload_out_of_bounds_is_malformed(payload_length: int) -> None:
    send = Send(
        message_id=os.urandom(16), recipient=os.urandom(32), payload=bytes(payload_length)
    )

    with pytest.raises(MalformedFrameError):
        parse_client_frame(ClientFrame(send=send).SerializeToString())


def test_ack_without_a_pair_is_malformed() -> None:
    with pytest.raises(MalformedFrameError):
        parse_client_frame(ClientFrame(ack=Ack()).SerializeToString())


@pytest.mark.parametrize("length", [0, 31, 33])
def test_fetch_with_an_identity_of_another_length_is_malformed(length: int) -> None:
    fetch = FetchBundle(identity=os.urandom(length))

    with pytest.raises(MalformedFrameError):
        parse_client_frame(ClientFrame(fetch_bundle=fetch).SerializeToString())


def complete_blob_frames() -> list[ClientFrame]:
    blob_id, key = os.urandom(16), os.urandom(32)
    return [
        ClientFrame(start_blob=StartBlob(blob_id=blob_id, recipient=key, length=2**32 - 1)),
        ClientFrame(put_blob=PutBlob(blob_id=blob_id, offset=0, data=b"x")),
        ClientFrame(
            put_blob=PutBlob(blob_id=blob_id, offset=7, data=os.urandom(BLOB_CHUNK_BYTES))
        ),
        ClientFrame(fetch_blob=FetchBlob(blob_id=blob_id, uploader=key, offset=0, length=1)),
        ClientFrame(
            fetch_blob=FetchBlob(
                blob_id=blob_id, uploader=key, offset=2**32 - 1, length=BLOB_CHUNK_BYTES
            )
        ),
        ClientFrame(delete_blob=DeleteBlob(blob_id=blob_id, uploader=key)),
    ]


@pytest.mark.parametrize("frame", complete_blob_frames())
def test_complete_blob_frame_is_returned_with_its_fields(frame: ClientFrame) -> None:
    parsed = parse_client_frame(frame.SerializeToString())

    assert parsed == getattr(frame, str(frame.WhichOneof("frame")))


def spoiled_blob_frames() -> list[ClientFrame]:
    blob_id, key = os.urandom(16), os.urandom(32)
    too_long = os.urandom(BLOB_CHUNK_BYTES + 1)
    return [
        ClientFrame(start_blob=StartBlob(blob_id=blob_id[:15], recipient=key, length=1)),
        ClientFrame(start_blob=StartBlob(blob_id=blob_id, recipient=key[:31], length=1)),
        ClientFrame(start_blob=StartBlob(blob_id=blob_id, recipient=key, length=0)),
        ClientFrame(put_blob=PutBlob(blob_id=blob_id + b"x", offset=0, data=b"x")),
        ClientFrame(put_blob=PutBlob(blob_id=blob_id, offset=0, data=b"")),
        ClientFrame(put_blob=PutBlob(blob_id=blob_id, offset=0, data=too_long)),
        ClientFrame(fetch_blob=FetchBlob(blob_id=b"", uploader=key, offset=0, length=1)),
        ClientFrame(fetch_blob=FetchBlob(blob_id=blob_id, uploader=b"", offset=0, length=1)),
        ClientFrame(fetch_blob=FetchBlob(blob_id=blob_id, uploader=key, offset=0, length=0)),
        ClientFrame(
            fetch_blob=FetchBlob(
                blob_id=blob_id, uploader=key, offset=0, length=BLOB_CHUNK_BYTES + 1
            )
        ),
        ClientFrame(delete_blob=DeleteBlob(blob_id=blob_id[:15], uploader=key)),
        ClientFrame(delete_blob=DeleteBlob(blob_id=blob_id, uploader=key + b"x")),
    ]


@pytest.mark.parametrize("frame", spoiled_blob_frames())
def test_blob_frame_that_breaks_its_table_is_malformed(frame: ClientFrame) -> None:
    with pytest.raises(MalformedFrameError):
        parse_client_frame(frame.SerializeToString())


@pytest.mark.parametrize(
    "message",
    [
        b"",
        b"\xff",
        b"\x0a\x00",
        b"\x08\x05",
        b"\x12\x00",
        b"\x1a\x00",
        b"\x22\x00",
        b"\x0a\x22\x0a\x20",
    ],
    ids=[
        "empty",
        "no-protobuf",
        "login-without-fields",
        "login-as-a-number",
        "upload-without-fields",
        "fetch-without-fields",
        "member-of-a-later-schema",
        "cut-off",
    ],
)
def test_message_without_a_complete_frame_is_malformed(message: bytes) -> None:
    with pytest.raises(MalformedFrameError):
        parse_client_frame(message)


def test_field_that_the_schema_does_not_have_is_ignored() -> None:
    login = complete_login()
    frame = ClientFrame(login=login)
    frame.login.MergeFromString(UNKNOWN_FIELD)
    frame.MergeFromString(UNKNOWN_FIELD)

    parsed = parse_client_frame(frame.SerializeToString())

    assert isinstance(parsed, Login)
    assert parsed.identity_key == login.identity_key
    assert parsed.client_nonce == login.client_nonce
    assert parsed.signature == login.signature


@given(messages)
def test_any_bytes_give_a_complete_frame_or_the_protocol_error(message: bytes) -> None:
    try:
        frame = parse_client_frame(message)
    except MalformedFrameError:
        return

    expected = {
        Login: [32, 32, 64],
        FetchBundle: [32],
        Send: [16, 32],
        StartBlob: [16, 32],
        PutBlob: [16],
        FetchBlob: [16, 32],
        DeleteBlob: [16, 32],
    }.get(type(frame))
    if isinstance(frame, UploadBundle):
        assert frame.HasField("signed_prekey")
        expected = [32, 64, 32, 64, *[32] * len(frame.one_time_prekeys)]
    if isinstance(frame, Send):
        assert 1 <= len(frame.payload) <= MAX_PAYLOAD_BYTES
    if isinstance(frame, StartBlob):
        assert frame.length >= 1
    if isinstance(frame, PutBlob):
        assert 1 <= len(frame.data) <= BLOB_CHUNK_BYTES
    if isinstance(frame, FetchBlob):
        assert 1 <= frame.length <= BLOB_CHUNK_BYTES
    if isinstance(frame, Ack):
        assert frame.messages
        expected = [16, 32] * len(frame.messages)
    assert lengths_of(frame) == expected


def test_largest_put_blob_and_blob_data_fit_the_largest_frame() -> None:
    blob_id, key, data = os.urandom(16), os.urandom(32), os.urandom(BLOB_CHUNK_BYTES)
    put = ClientFrame(put_blob=PutBlob(blob_id=blob_id, offset=2**32 - 1, data=data))
    blob_data = ServerFrame(
        blob_data=BlobData(blob_id=blob_id, uploader=key, offset=2**32 - 1, data=data)
    )

    overheads = [
        len(frame.SerializeToString()) - BLOB_CHUNK_BYTES for frame in (put, blob_data)
    ]

    assert overheads == [32, 66]
    assert all(BLOB_CHUNK_BYTES + overhead <= MAX_FRAME_BYTES for overhead in overheads)
