"""The parse step of docs/protocol.md, section 7.3, for the frames that a client sends."""

from google.protobuf.message import DecodeError

from sotto.crypto.identity import KEY_LENGTH, NONCE_LENGTH, SIGNATURE_LENGTH
from sotto.proto.sotto_pb2 import ClientFrame, Login

MAX_FRAME_BYTES = 65536


class MalformedFrameError(Exception):
    """A binary message is a malformed frame by section 7.3."""


def parse_client_frame(message: bytes) -> Login:
    """Returns the frame that a binary message holds, complete by the table of the frame.

    Raises:
        MalformedFrameError: The message is a malformed frame.
    """
    envelope = ClientFrame()
    try:
        envelope.ParseFromString(message)
    except DecodeError as error:
        raise MalformedFrameError("the message is not a ClientFrame") from error

    if envelope.WhichOneof("frame") != "login":
        raise MalformedFrameError("no frame of the schema is set")

    login = envelope.login
    _require_length("identity_key", login.identity_key, KEY_LENGTH)
    _require_length("client_nonce", login.client_nonce, NONCE_LENGTH)
    _require_length("signature", login.signature, SIGNATURE_LENGTH)
    return login


def _require_length(field: str, value: bytes, length: int) -> None:
    if len(value) != length:
        raise MalformedFrameError(f"{field} is {len(value)} bytes long, not {length}")
