from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ErrorCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ERROR_CODE_UNSPECIFIED: _ClassVar[ErrorCode]
    UNKNOWN_RECIPIENT: _ClassVar[ErrorCode]
    QUEUE_FULL: _ClassVar[ErrorCode]
    STORAGE_FULL: _ClassVar[ErrorCode]
    RATE_LIMITED: _ClassVar[ErrorCode]
    NOT_FOUND: _ClassVar[ErrorCode]
    BAD_BUNDLE: _ClassVar[ErrorCode]
    IDENTITY_KEY_MISMATCH: _ClassVar[ErrorCode]
    QUOTA_FULL: _ClassVar[ErrorCode]
    BLOB_TOO_LARGE: _ClassVar[ErrorCode]
ERROR_CODE_UNSPECIFIED: ErrorCode
UNKNOWN_RECIPIENT: ErrorCode
QUEUE_FULL: ErrorCode
STORAGE_FULL: ErrorCode
RATE_LIMITED: ErrorCode
NOT_FOUND: ErrorCode
BAD_BUNDLE: ErrorCode
IDENTITY_KEY_MISMATCH: ErrorCode
QUOTA_FULL: ErrorCode
BLOB_TOO_LARGE: ErrorCode

class ClientFrame(_message.Message):
    __slots__ = ("login", "upload_bundle", "fetch_bundle", "send", "ack", "start_blob", "put_blob", "fetch_blob", "delete_blob")
    LOGIN_FIELD_NUMBER: _ClassVar[int]
    UPLOAD_BUNDLE_FIELD_NUMBER: _ClassVar[int]
    FETCH_BUNDLE_FIELD_NUMBER: _ClassVar[int]
    SEND_FIELD_NUMBER: _ClassVar[int]
    ACK_FIELD_NUMBER: _ClassVar[int]
    START_BLOB_FIELD_NUMBER: _ClassVar[int]
    PUT_BLOB_FIELD_NUMBER: _ClassVar[int]
    FETCH_BLOB_FIELD_NUMBER: _ClassVar[int]
    DELETE_BLOB_FIELD_NUMBER: _ClassVar[int]
    login: Login
    upload_bundle: UploadBundle
    fetch_bundle: FetchBundle
    send: Send
    ack: Ack
    start_blob: StartBlob
    put_blob: PutBlob
    fetch_blob: FetchBlob
    delete_blob: DeleteBlob
    def __init__(self, login: _Optional[_Union[Login, _Mapping]] = ..., upload_bundle: _Optional[_Union[UploadBundle, _Mapping]] = ..., fetch_bundle: _Optional[_Union[FetchBundle, _Mapping]] = ..., send: _Optional[_Union[Send, _Mapping]] = ..., ack: _Optional[_Union[Ack, _Mapping]] = ..., start_blob: _Optional[_Union[StartBlob, _Mapping]] = ..., put_blob: _Optional[_Union[PutBlob, _Mapping]] = ..., fetch_blob: _Optional[_Union[FetchBlob, _Mapping]] = ..., delete_blob: _Optional[_Union[DeleteBlob, _Mapping]] = ...) -> None: ...

class ServerFrame(_message.Message):
    __slots__ = ("hello", "logged_in", "bundle_stored", "bundle", "stored", "deliver", "error", "blob_stored", "blob_data")
    HELLO_FIELD_NUMBER: _ClassVar[int]
    LOGGED_IN_FIELD_NUMBER: _ClassVar[int]
    BUNDLE_STORED_FIELD_NUMBER: _ClassVar[int]
    BUNDLE_FIELD_NUMBER: _ClassVar[int]
    STORED_FIELD_NUMBER: _ClassVar[int]
    DELIVER_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    BLOB_STORED_FIELD_NUMBER: _ClassVar[int]
    BLOB_DATA_FIELD_NUMBER: _ClassVar[int]
    hello: Hello
    logged_in: LoggedIn
    bundle_stored: BundleStored
    bundle: Bundle
    stored: Stored
    deliver: Deliver
    error: Error
    blob_stored: BlobStored
    blob_data: BlobData
    def __init__(self, hello: _Optional[_Union[Hello, _Mapping]] = ..., logged_in: _Optional[_Union[LoggedIn, _Mapping]] = ..., bundle_stored: _Optional[_Union[BundleStored, _Mapping]] = ..., bundle: _Optional[_Union[Bundle, _Mapping]] = ..., stored: _Optional[_Union[Stored, _Mapping]] = ..., deliver: _Optional[_Union[Deliver, _Mapping]] = ..., error: _Optional[_Union[Error, _Mapping]] = ..., blob_stored: _Optional[_Union[BlobStored, _Mapping]] = ..., blob_data: _Optional[_Union[BlobData, _Mapping]] = ...) -> None: ...

class Hello(_message.Message):
    __slots__ = ("version", "nonce")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    NONCE_FIELD_NUMBER: _ClassVar[int]
    version: int
    nonce: bytes
    def __init__(self, version: _Optional[int] = ..., nonce: _Optional[bytes] = ...) -> None: ...

class Login(_message.Message):
    __slots__ = ("identity_key", "client_nonce", "signature")
    IDENTITY_KEY_FIELD_NUMBER: _ClassVar[int]
    CLIENT_NONCE_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    identity_key: bytes
    client_nonce: bytes
    signature: bytes
    def __init__(self, identity_key: _Optional[bytes] = ..., client_nonce: _Optional[bytes] = ..., signature: _Optional[bytes] = ...) -> None: ...

class LoggedIn(_message.Message):
    __slots__ = ("one_time_prekey_count", "blob_max_bytes")
    ONE_TIME_PREKEY_COUNT_FIELD_NUMBER: _ClassVar[int]
    BLOB_MAX_BYTES_FIELD_NUMBER: _ClassVar[int]
    one_time_prekey_count: int
    blob_max_bytes: int
    def __init__(self, one_time_prekey_count: _Optional[int] = ..., blob_max_bytes: _Optional[int] = ...) -> None: ...

class SignedPrekey(_message.Message):
    __slots__ = ("id", "key", "signature")
    ID_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    id: int
    key: bytes
    signature: bytes
    def __init__(self, id: _Optional[int] = ..., key: _Optional[bytes] = ..., signature: _Optional[bytes] = ...) -> None: ...

class OneTimePrekey(_message.Message):
    __slots__ = ("id", "key")
    ID_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    id: int
    key: bytes
    def __init__(self, id: _Optional[int] = ..., key: _Optional[bytes] = ...) -> None: ...

class UploadBundle(_message.Message):
    __slots__ = ("identity_dh_key", "identity_dh_signature", "signed_prekey", "one_time_prekeys")
    IDENTITY_DH_KEY_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_DH_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    SIGNED_PREKEY_FIELD_NUMBER: _ClassVar[int]
    ONE_TIME_PREKEYS_FIELD_NUMBER: _ClassVar[int]
    identity_dh_key: bytes
    identity_dh_signature: bytes
    signed_prekey: SignedPrekey
    one_time_prekeys: _containers.RepeatedCompositeFieldContainer[OneTimePrekey]
    def __init__(self, identity_dh_key: _Optional[bytes] = ..., identity_dh_signature: _Optional[bytes] = ..., signed_prekey: _Optional[_Union[SignedPrekey, _Mapping]] = ..., one_time_prekeys: _Optional[_Iterable[_Union[OneTimePrekey, _Mapping]]] = ...) -> None: ...

class BundleStored(_message.Message):
    __slots__ = ("one_time_prekey_count",)
    ONE_TIME_PREKEY_COUNT_FIELD_NUMBER: _ClassVar[int]
    one_time_prekey_count: int
    def __init__(self, one_time_prekey_count: _Optional[int] = ...) -> None: ...

class FetchBundle(_message.Message):
    __slots__ = ("identity",)
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    identity: bytes
    def __init__(self, identity: _Optional[bytes] = ...) -> None: ...

class Bundle(_message.Message):
    __slots__ = ("identity", "identity_dh_key", "identity_dh_signature", "signed_prekey", "one_time_prekey")
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_DH_KEY_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_DH_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    SIGNED_PREKEY_FIELD_NUMBER: _ClassVar[int]
    ONE_TIME_PREKEY_FIELD_NUMBER: _ClassVar[int]
    identity: bytes
    identity_dh_key: bytes
    identity_dh_signature: bytes
    signed_prekey: SignedPrekey
    one_time_prekey: OneTimePrekey
    def __init__(self, identity: _Optional[bytes] = ..., identity_dh_key: _Optional[bytes] = ..., identity_dh_signature: _Optional[bytes] = ..., signed_prekey: _Optional[_Union[SignedPrekey, _Mapping]] = ..., one_time_prekey: _Optional[_Union[OneTimePrekey, _Mapping]] = ...) -> None: ...

class Send(_message.Message):
    __slots__ = ("message_id", "recipient", "payload")
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    RECIPIENT_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    message_id: bytes
    recipient: bytes
    payload: bytes
    def __init__(self, message_id: _Optional[bytes] = ..., recipient: _Optional[bytes] = ..., payload: _Optional[bytes] = ...) -> None: ...

class Stored(_message.Message):
    __slots__ = ("message_id",)
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    message_id: bytes
    def __init__(self, message_id: _Optional[bytes] = ...) -> None: ...

class Deliver(_message.Message):
    __slots__ = ("message_id", "sender", "payload")
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    SENDER_FIELD_NUMBER: _ClassVar[int]
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    message_id: bytes
    sender: bytes
    payload: bytes
    def __init__(self, message_id: _Optional[bytes] = ..., sender: _Optional[bytes] = ..., payload: _Optional[bytes] = ...) -> None: ...

class MessageRef(_message.Message):
    __slots__ = ("message_id", "sender")
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    SENDER_FIELD_NUMBER: _ClassVar[int]
    message_id: bytes
    sender: bytes
    def __init__(self, message_id: _Optional[bytes] = ..., sender: _Optional[bytes] = ...) -> None: ...

class Ack(_message.Message):
    __slots__ = ("messages",)
    MESSAGES_FIELD_NUMBER: _ClassVar[int]
    messages: _containers.RepeatedCompositeFieldContainer[MessageRef]
    def __init__(self, messages: _Optional[_Iterable[_Union[MessageRef, _Mapping]]] = ...) -> None: ...

class Error(_message.Message):
    __slots__ = ("code", "message_id", "identity", "blob_id")
    CODE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    BLOB_ID_FIELD_NUMBER: _ClassVar[int]
    code: ErrorCode
    message_id: bytes
    identity: bytes
    blob_id: bytes
    def __init__(self, code: _Optional[_Union[ErrorCode, str]] = ..., message_id: _Optional[bytes] = ..., identity: _Optional[bytes] = ..., blob_id: _Optional[bytes] = ...) -> None: ...

class StartBlob(_message.Message):
    __slots__ = ("blob_id", "recipient", "length")
    BLOB_ID_FIELD_NUMBER: _ClassVar[int]
    RECIPIENT_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    blob_id: bytes
    recipient: bytes
    length: int
    def __init__(self, blob_id: _Optional[bytes] = ..., recipient: _Optional[bytes] = ..., length: _Optional[int] = ...) -> None: ...

class PutBlob(_message.Message):
    __slots__ = ("blob_id", "offset", "data")
    BLOB_ID_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    blob_id: bytes
    offset: int
    data: bytes
    def __init__(self, blob_id: _Optional[bytes] = ..., offset: _Optional[int] = ..., data: _Optional[bytes] = ...) -> None: ...

class BlobStored(_message.Message):
    __slots__ = ("blob_id", "stored_length")
    BLOB_ID_FIELD_NUMBER: _ClassVar[int]
    STORED_LENGTH_FIELD_NUMBER: _ClassVar[int]
    blob_id: bytes
    stored_length: int
    def __init__(self, blob_id: _Optional[bytes] = ..., stored_length: _Optional[int] = ...) -> None: ...

class FetchBlob(_message.Message):
    __slots__ = ("blob_id", "uploader", "offset", "length")
    BLOB_ID_FIELD_NUMBER: _ClassVar[int]
    UPLOADER_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    blob_id: bytes
    uploader: bytes
    offset: int
    length: int
    def __init__(self, blob_id: _Optional[bytes] = ..., uploader: _Optional[bytes] = ..., offset: _Optional[int] = ..., length: _Optional[int] = ...) -> None: ...

class BlobData(_message.Message):
    __slots__ = ("blob_id", "uploader", "offset", "data")
    BLOB_ID_FIELD_NUMBER: _ClassVar[int]
    UPLOADER_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    blob_id: bytes
    uploader: bytes
    offset: int
    data: bytes
    def __init__(self, blob_id: _Optional[bytes] = ..., uploader: _Optional[bytes] = ..., offset: _Optional[int] = ..., data: _Optional[bytes] = ...) -> None: ...

class DeleteBlob(_message.Message):
    __slots__ = ("blob_id", "uploader")
    BLOB_ID_FIELD_NUMBER: _ClassVar[int]
    UPLOADER_FIELD_NUMBER: _ClassVar[int]
    blob_id: bytes
    uploader: bytes
    def __init__(self, blob_id: _Optional[bytes] = ..., uploader: _Optional[bytes] = ...) -> None: ...

class PeerMessage(_message.Message):
    __slots__ = ("version", "initial_header", "header", "ciphertext")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    INITIAL_HEADER_FIELD_NUMBER: _ClassVar[int]
    HEADER_FIELD_NUMBER: _ClassVar[int]
    CIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
    version: int
    initial_header: InitialHeader
    header: bytes
    ciphertext: bytes
    def __init__(self, version: _Optional[int] = ..., initial_header: _Optional[_Union[InitialHeader, _Mapping]] = ..., header: _Optional[bytes] = ..., ciphertext: _Optional[bytes] = ...) -> None: ...

class InitialHeader(_message.Message):
    __slots__ = ("identity_dh_key", "identity_dh_signature", "ephemeral_key", "signed_prekey_id", "one_time_prekey_id")
    IDENTITY_DH_KEY_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_DH_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    EPHEMERAL_KEY_FIELD_NUMBER: _ClassVar[int]
    SIGNED_PREKEY_ID_FIELD_NUMBER: _ClassVar[int]
    ONE_TIME_PREKEY_ID_FIELD_NUMBER: _ClassVar[int]
    identity_dh_key: bytes
    identity_dh_signature: bytes
    ephemeral_key: bytes
    signed_prekey_id: int
    one_time_prekey_id: int
    def __init__(self, identity_dh_key: _Optional[bytes] = ..., identity_dh_signature: _Optional[bytes] = ..., ephemeral_key: _Optional[bytes] = ..., signed_prekey_id: _Optional[int] = ..., one_time_prekey_id: _Optional[int] = ...) -> None: ...

class Content(_message.Message):
    __slots__ = ("text", "attachment", "profile")
    TEXT_FIELD_NUMBER: _ClassVar[int]
    ATTACHMENT_FIELD_NUMBER: _ClassVar[int]
    PROFILE_FIELD_NUMBER: _ClassVar[int]
    text: str
    attachment: Attachment
    profile: Profile
    def __init__(self, text: _Optional[str] = ..., attachment: _Optional[_Union[Attachment, _Mapping]] = ..., profile: _Optional[_Union[Profile, _Mapping]] = ...) -> None: ...

class Attachment(_message.Message):
    __slots__ = ("blob_id", "key", "size", "digest", "media_type", "file_name", "width", "height", "thumbnail", "caption")
    BLOB_ID_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    DIGEST_FIELD_NUMBER: _ClassVar[int]
    MEDIA_TYPE_FIELD_NUMBER: _ClassVar[int]
    FILE_NAME_FIELD_NUMBER: _ClassVar[int]
    WIDTH_FIELD_NUMBER: _ClassVar[int]
    HEIGHT_FIELD_NUMBER: _ClassVar[int]
    THUMBNAIL_FIELD_NUMBER: _ClassVar[int]
    CAPTION_FIELD_NUMBER: _ClassVar[int]
    blob_id: bytes
    key: bytes
    size: int
    digest: bytes
    media_type: str
    file_name: str
    width: int
    height: int
    thumbnail: bytes
    caption: str
    def __init__(self, blob_id: _Optional[bytes] = ..., key: _Optional[bytes] = ..., size: _Optional[int] = ..., digest: _Optional[bytes] = ..., media_type: _Optional[str] = ..., file_name: _Optional[str] = ..., width: _Optional[int] = ..., height: _Optional[int] = ..., thumbnail: _Optional[bytes] = ..., caption: _Optional[str] = ...) -> None: ...

class Profile(_message.Message):
    __slots__ = ("name", "avatar")
    NAME_FIELD_NUMBER: _ClassVar[int]
    AVATAR_FIELD_NUMBER: _ClassVar[int]
    name: str
    avatar: Attachment
    def __init__(self, name: _Optional[str] = ..., avatar: _Optional[_Union[Attachment, _Mapping]] = ...) -> None: ...
