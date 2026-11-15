from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
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
    __slots__ = ("login",)
    LOGIN_FIELD_NUMBER: _ClassVar[int]
    login: Login
    def __init__(self, login: _Optional[_Union[Login, _Mapping]] = ...) -> None: ...

class ServerFrame(_message.Message):
    __slots__ = ("hello", "logged_in", "error")
    HELLO_FIELD_NUMBER: _ClassVar[int]
    LOGGED_IN_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    hello: Hello
    logged_in: LoggedIn
    error: Error
    def __init__(self, hello: _Optional[_Union[Hello, _Mapping]] = ..., logged_in: _Optional[_Union[LoggedIn, _Mapping]] = ..., error: _Optional[_Union[Error, _Mapping]] = ...) -> None: ...

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

class Error(_message.Message):
    __slots__ = ("code", "message_id", "identity")
    CODE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    IDENTITY_FIELD_NUMBER: _ClassVar[int]
    code: ErrorCode
    message_id: bytes
    identity: bytes
    def __init__(self, code: _Optional[_Union[ErrorCode, str]] = ..., message_id: _Optional[bytes] = ..., identity: _Optional[bytes] = ...) -> None: ...
