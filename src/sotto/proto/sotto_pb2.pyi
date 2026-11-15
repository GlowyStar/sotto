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
ERROR_CODE_UNSPECIFIED: ErrorCode
UNKNOWN_RECIPIENT: ErrorCode
QUEUE_FULL: ErrorCode
STORAGE_FULL: ErrorCode
RATE_LIMITED: ErrorCode
NOT_FOUND: ErrorCode
BAD_BUNDLE: ErrorCode
IDENTITY_KEY_MISMATCH: ErrorCode

class ClientFrame(_message.Message):
    __slots__ = ("login", "upload_bundle", "fetch_bundle")
    LOGIN_FIELD_NUMBER: _ClassVar[int]
    UPLOAD_BUNDLE_FIELD_NUMBER: _ClassVar[int]
    FETCH_BUNDLE_FIELD_NUMBER: _ClassVar[int]
    login: Login
    upload_bundle: UploadBundle
    fetch_bundle: FetchBundle
    def __init__(self, login: _Optional[_Union[Login, _Mapping]] = ..., upload_bundle: _Optional[_Union[UploadBundle, _Mapping]] = ..., fetch_bundle: _Optional[_Union[FetchBundle, _Mapping]] = ...) -> None: ...

class ServerFrame(_message.Message):
    __slots__ = ("hello", "logged_in", "bundle_stored", "bundle", "error")
    HELLO_FIELD_NUMBER: _ClassVar[int]
    LOGGED_IN_FIELD_NUMBER: _ClassVar[int]
    BUNDLE_STORED_FIELD_NUMBER: _ClassVar[int]
    BUNDLE_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    hello: Hello
    logged_in: LoggedIn
    bundle_stored: BundleStored
    bundle: Bundle
    error: Error
    def __init__(self, hello: _Optional[_Union[Hello, _Mapping]] = ..., logged_in: _Optional[_Union[LoggedIn, _Mapping]] = ..., bundle_stored: _Optional[_Union[BundleStored, _Mapping]] = ..., bundle: _Optional[_Union[Bundle, _Mapping]] = ..., error: _Optional[_Union[Error, _Mapping]] = ...) -> None: ...

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
    __slots__ = ("one_time_prekey_count",)
    ONE_TIME_PREKEY_COUNT_FIELD_NUMBER: _ClassVar[int]
    one_time_prekey_count: int
    def __init__(self, one_time_prekey_count: _Optional[int] = ...) -> None: ...

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

class Error(_message.Message):
    __slots__ = ("code", "message_id", "identity")
    CODE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    code: ErrorCode
    message_id: bytes
    identity: bytes
    def __init__(self, code: _Optional[_Union[ErrorCode, str]] = ..., message_id: _Optional[bytes] = ..., identity: _Optional[bytes] = ...) -> None: ...
