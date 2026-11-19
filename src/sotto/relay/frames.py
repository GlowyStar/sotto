"""The parse step of docs/protocol.md, section 7.3, for the frames that a client sends."""

from google.protobuf.message import DecodeError

from sotto.crypto.identity import (
    KEM_PUBLIC_KEY_LENGTH,
    KEY_LENGTH,
    NONCE_LENGTH,
    SIGNATURE_LENGTH,
)
from sotto.proto.sotto_pb2 import (
    Ack,
    ClientFrame,
    DeleteBlob,
    FetchBlob,
    FetchBundle,
    Login,
    PutBlob,
    Send,
    StartBlob,
    UploadBundle,
)

MAX_FRAME_BYTES = 65536
MESSAGE_ID_LENGTH = 16
# What the envelope and the other fields of a Send or a Deliver add is at most 64 bytes.
MAX_PAYLOAD_BYTES = MAX_FRAME_BYTES - 64
BLOB_ID_LENGTH = 16
# What the envelope and the other fields of a PutBlob or a BlobData add is at most 128 bytes.
BLOB_CHUNK_BYTES = MAX_FRAME_BYTES - 128

type BlobFrame = StartBlob | PutBlob | FetchBlob | DeleteBlob
type ParsedFrame = Login | UploadBundle | FetchBundle | Send | Ack | BlobFrame


class MalformedFrameError(Exception):
    """A binary message is a malformed frame by section 7.3."""


def parse_client_frame(message: bytes) -> ParsedFrame:
    """Returns the frame that a binary message holds, complete by the table of the frame.

    Raises:
        MalformedFrameError: The message is a malformed frame.
    """
    envelope = ClientFrame()
    try:
        envelope.ParseFromString(message)
    except DecodeError as error:
        raise MalformedFrameError("the message is not a ClientFrame") from error

    match envelope.WhichOneof("frame"):
        case "login":
            _check_login(envelope.login)
            return envelope.login
        case "upload_bundle":
            _check_upload_bundle(envelope.upload_bundle)
            return envelope.upload_bundle
        case "fetch_bundle":
            _require_length("identity", envelope.fetch_bundle.identity, KEY_LENGTH)
            return envelope.fetch_bundle
        case "send":
            _check_send(envelope.send)
            return envelope.send
        case "ack":
            _check_ack(envelope.ack)
            return envelope.ack
        case "start_blob":
            _check_start_blob(envelope.start_blob)
            return envelope.start_blob
        case "put_blob":
            _check_put_blob(envelope.put_blob)
            return envelope.put_blob
        case "fetch_blob":
            _check_fetch_blob(envelope.fetch_blob)
            return envelope.fetch_blob
        case "delete_blob":
            _require_length("blob_id", envelope.delete_blob.blob_id, BLOB_ID_LENGTH)
            _require_length("uploader", envelope.delete_blob.uploader, KEY_LENGTH)
            return envelope.delete_blob
        case _:
            raise MalformedFrameError("no frame of the schema is set")


def _check_login(login: Login) -> None:
    _require_length("identity_key", login.identity_key, KEY_LENGTH)
    _require_length("client_nonce", login.client_nonce, NONCE_LENGTH)
    _require_length("signature", login.signature, SIGNATURE_LENGTH)


def _check_upload_bundle(upload: UploadBundle) -> None:
    _require_length("identity_dh_key", upload.identity_dh_key, KEY_LENGTH)
    _require_length("identity_dh_signature", upload.identity_dh_signature, SIGNATURE_LENGTH)

    # An absent signed prekey reads as one with empty fields.
    signed_prekey = upload.signed_prekey
    _require_length("signed_prekey.key", signed_prekey.key, KEY_LENGTH)
    _require_length("signed_prekey.signature", signed_prekey.signature, SIGNATURE_LENGTH)

    for prekey in upload.one_time_prekeys:
        _require_length("one_time_prekeys[].key", prekey.key, KEY_LENGTH)

    pq_prekeys = [("pq_one_time_prekeys[]", prekey) for prekey in upload.pq_one_time_prekeys]
    if upload.HasField("pq_prekey"):
        pq_prekeys.append(("pq_prekey", upload.pq_prekey))
    for field, pq_prekey in pq_prekeys:
        _require_length(f"{field}.key", pq_prekey.key, KEM_PUBLIC_KEY_LENGTH)
        _require_length(f"{field}.signature", pq_prekey.signature, SIGNATURE_LENGTH)


def _check_send(send: Send) -> None:
    _require_length("message_id", send.message_id, MESSAGE_ID_LENGTH)
    _require_length("recipient", send.recipient, KEY_LENGTH)
    if not 1 <= len(send.payload) <= MAX_PAYLOAD_BYTES:
        raise MalformedFrameError(
            f"payload is {len(send.payload)} bytes long, not 1 to {MAX_PAYLOAD_BYTES}"
        )


def _check_ack(ack: Ack) -> None:
    if not ack.messages:
        raise MalformedFrameError("the ack names no message")
    for message in ack.messages:
        _require_length("messages[].message_id", message.message_id, MESSAGE_ID_LENGTH)
        _require_length("messages[].sender", message.sender, KEY_LENGTH)


def _check_start_blob(start: StartBlob) -> None:
    _require_length("blob_id", start.blob_id, BLOB_ID_LENGTH)
    _require_length("recipient", start.recipient, KEY_LENGTH)
    if start.length == 0:
        raise MalformedFrameError("length is 0")


def _check_put_blob(put: PutBlob) -> None:
    _require_length("blob_id", put.blob_id, BLOB_ID_LENGTH)
    _require_chunk_length("data", len(put.data))


def _check_fetch_blob(fetch: FetchBlob) -> None:
    _require_length("blob_id", fetch.blob_id, BLOB_ID_LENGTH)
    _require_length("uploader", fetch.uploader, KEY_LENGTH)
    _require_chunk_length("length", fetch.length)


def _require_chunk_length(field: str, length: int) -> None:
    if not 1 <= length <= BLOB_CHUNK_BYTES:
        raise MalformedFrameError(f"{field} is {length} bytes, not 1 to {BLOB_CHUNK_BYTES}")


def _require_length(field: str, value: bytes, length: int) -> None:
    if len(value) != length:
        raise MalformedFrameError(f"{field} is {len(value)} bytes long, not {length}")
