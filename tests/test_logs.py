import base64
import json
import logging
import os
import sys
from datetime import datetime, timedelta

import pytest
from relay_harness import Wire, find_leaks

from sotto.proto.sotto_pb2 import ClientFrame, Login
from sotto.relay.logs import JsonFormatter


def test_record_becomes_one_json_line() -> None:
    record = logging.LogRecord(
        "sotto.relay", logging.INFO, __file__, 1, "listening on %s", ("127.0.0.1",), None
    )

    line = JsonFormatter().format(record)

    entry = json.loads(line)
    assert "\n" not in line
    assert entry["level"] == "INFO"
    assert entry["logger"] == "sotto.relay"
    assert entry["message"] == "listening on 127.0.0.1"
    assert datetime.fromisoformat(entry["time"]).utcoffset() == timedelta(0)


def record_of_a_failure(failure: BaseException) -> logging.LogRecord:
    try:
        raise failure
    except type(failure):
        raised = sys.exc_info()
    return logging.LogRecord("sotto.relay", logging.ERROR, __file__, 1, "failed", None, raised)


def test_traceback_stays_inside_the_line() -> None:
    line = JsonFormatter().format(record_of_a_failure(RuntimeError("first\nsecond")))

    assert "\n" not in line
    assert "in record_of_a_failure\n" in json.loads(line)["exception"]


def test_text_of_an_exception_stays_out_of_the_line() -> None:
    key = os.urandom(32)
    failure = record_of_a_failure(KeyError(key))

    exception = json.loads(JsonFormatter().format(failure))["exception"]

    assert exception.endswith("KeyError")
    assert find_leaks([failure], Wire(messages=[key])) == []


def test_record_of_a_connection_carries_its_id() -> None:
    record = logging.LogRecord(
        "websockets.server", logging.INFO, __file__, 1, "logged in", None, None
    )
    record.connection = "0f" * 16

    assert json.loads(JsonFormatter().format(record))["connection"] == "0f" * 16


LOGIN = Login(
    identity_key=os.urandom(32), client_nonce=os.urandom(32), signature=os.urandom(64)
)
FRAME = ClientFrame(login=LOGIN).SerializeToString()
WAYS_TO_LOG_A_LOGIN = {
    "hex": FRAME.hex(),
    "uppercase-hex": FRAME.hex().upper(),
    "frame-at-debug": f"< BINARY {FRAME[:16].hex(' ')} ... {FRAME[-8:].hex(' ')} [137 bytes]",
    "repr": repr(FRAME),
    "base64": base64.b64encode(FRAME).decode(),
    "printed-message": str(LOGIN),
    "user-id": f"logged in as {LOGIN.identity_key.hex()}",
    "base64-of-the-signature": base64.b64encode(LOGIN.signature).decode(),
    "half-a-nonce": LOGIN.client_nonce[:16].hex(),
}


def logged(message: str, *arguments: object) -> logging.LogRecord:
    return logging.LogRecord(
        "sotto.relay", logging.INFO, __file__, 1, message, arguments, None
    )


@pytest.mark.parametrize("text", WAYS_TO_LOG_A_LOGIN.values(), ids=WAYS_TO_LOG_A_LOGIN.keys())
def test_scan_finds_bytes_of_the_wire_in_a_log_line(text: str) -> None:
    leaks = find_leaks([logged("refused: %s", text)], Wire(messages=[FRAME]))

    assert len(leaks) == 1


@pytest.mark.parametrize("address", ["127.0.0.1:50123", "('127.0.0.1', 50123)"])
def test_scan_finds_the_address_of_a_client_in_a_log_line(address: str) -> None:
    wire = Wire(client_addresses=["127.0.0.1:50123", "'127.0.0.1', 50123"])

    assert len(find_leaks([logged("connection from %s", address)], wire)) == 1


def test_scan_passes_the_lines_of_a_login() -> None:
    wire = Wire(messages=[FRAME], client_addresses=["127.0.0.1:50123", "'127.0.0.1', 50123"])
    lines = [
        logged("server listening on %s", "127.0.0.1:8765"),
        logged("connection open"),
        logged("logged in"),
        logged("closing with %d %s", 3000, "LOGIN_REFUSED"),
        logged("id %s", LOGIN.identity_key.hex()[:14]),
    ]

    assert find_leaks(lines, wire) == []
