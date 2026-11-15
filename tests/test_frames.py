import os

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sotto.proto.sotto_pb2 import ClientFrame, Login
from sotto.relay.frames import MalformedFrameError, parse_client_frame

UNKNOWN_FIELD = b"\x7a\x03new"

fields = st.binary(max_size=80)
logins = st.builds(Login, identity_key=fields, client_nonce=fields, signature=fields)
complete_logins = st.builds(
    Login,
    identity_key=st.binary(min_size=32, max_size=32),
    client_nonce=st.binary(min_size=32, max_size=32),
    signature=st.binary(min_size=64, max_size=64),
)
serialized_frames = st.one_of(logins, complete_logins).map(
    lambda login: ClientFrame(login=login).SerializeToString()
)
damaged_frames = st.tuples(serialized_frames, st.binary(max_size=8), st.integers(0, 200)).map(
    lambda parts: parts[0][: parts[2]] + parts[1] + parts[0][parts[2] :]
)
messages = st.one_of(st.binary(max_size=300), serialized_frames, damaged_frames)


def complete_login() -> Login:
    return Login(
        identity_key=os.urandom(32), client_nonce=os.urandom(32), signature=os.urandom(64)
    )


def test_complete_login_is_returned_with_its_fields() -> None:
    login = complete_login()

    parsed = parse_client_frame(ClientFrame(login=login).SerializeToString())

    assert parsed == login


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


@pytest.mark.parametrize(
    "message",
    [b"", b"\xff", b"\x0a\x00", b"\x08\x05", b"\x12\x00", b"\x0a\x22\x0a\x20"],
    ids=[
        "empty",
        "no-protobuf",
        "login-without-fields",
        "login-as-a-number",
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

    assert parsed.identity_key == login.identity_key
    assert parsed.client_nonce == login.client_nonce
    assert parsed.signature == login.signature


@given(messages)
def test_any_bytes_give_a_complete_frame_or_the_protocol_error(message: bytes) -> None:
    try:
        login = parse_client_frame(message)
    except MalformedFrameError:
        return

    lengths = (len(login.identity_key), len(login.client_nonce), len(login.signature))
    assert lengths == (32, 32, 64)
