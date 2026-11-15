import json
import logging
import sys
from datetime import datetime, timedelta

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


def test_traceback_stays_inside_the_line() -> None:
    try:
        raise RuntimeError("first\nsecond")
    except RuntimeError:
        failure = sys.exc_info()
    record = logging.LogRecord(
        "sotto.relay", logging.ERROR, __file__, 1, "failed", None, failure
    )

    line = JsonFormatter().format(record)

    assert "\n" not in line
    assert "RuntimeError: first\nsecond" in json.loads(line)["exception"]
