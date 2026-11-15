import json
import logging
import sys
import traceback
from collections.abc import MutableMapping
from datetime import UTC, datetime
from types import TracebackType
from typing import Any, override

type ExceptionInfo = (
    tuple[type[BaseException], BaseException, TracebackType | None] | tuple[None, None, None]
)


class JsonFormatter(logging.Formatter):
    @override
    def format(self, record: logging.LogRecord) -> str:
        logged_at = datetime.fromtimestamp(record.created, UTC)
        entry = {
            "time": logged_at.isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        connection = getattr(record, "connection", None)
        if connection is not None:
            entry["connection"] = connection
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(entry)

    @override
    def formatException(self, ei: ExceptionInfo) -> str:
        # The text of an exception can hold what a client sent (a KeyError prints its key),
        # so a line gets the stack and the type of the exception only.
        exception_type, _, stack = ei
        if exception_type is None:
            return ""
        return "".join(traceback.format_tb(stack)) + exception_type.__qualname__


class ConnectionLogger(logging.LoggerAdapter[logging.Logger]):
    """Names the connection of a record by the random id that websockets gave it."""

    @override
    def process(
        self, msg: object, kwargs: MutableMapping[str, Any]
    ) -> tuple[object, MutableMapping[str, Any]]:
        try:
            websocket = kwargs["extra"]["websocket"]
        except KeyError:
            return msg, kwargs

        # The id is read now, because websockets hands over a weak reference to the
        # connection, which is dead when a record is formatted after the connection.
        kwargs["extra"] = {"connection": websocket.id.hex}
        return msg, kwargs


def configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler])
