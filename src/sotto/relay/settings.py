import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Self

# Rule 4 of docs/protocol.md, section 8.2.
SERVER_NAME = re.compile(r"[a-z0-9._:-]{1,255}")
# BLOB_MAX_BYTES travels as a uint32 in LoggedIn (docs/protocol.md, section 7.7).
MAX_UINT32 = 2**32 - 1


@dataclass(frozen=True, slots=True)
class Settings:
    database: Path
    host: str = "127.0.0.1"
    port: int = 8765
    name: str = "127.0.0.1"
    login_deadline_seconds: float = 10
    one_time_prekey_cap: int = 100
    max_pages: int = 2097152
    message_ttl_seconds: int = 2592000
    sweep_interval_seconds: float = 60
    queue_max_messages: int = 1000
    queue_max_bytes: int = 16777216
    frame_bucket_size: int = 60
    frame_refill_seconds: float = 1
    handout_bucket_size: int = 20
    handout_refill_seconds: float = 300
    blob_max_bytes: int = 104883216
    blob_quota_bytes: int = 268435456
    blob_ttl_seconds: int = 3196800
    metrics_port: int | None = None

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> Self:
        database = environ.get("RELAY_DATABASE", "")
        if not database:
            raise ValueError("RELAY_DATABASE is not set")
        defaults = cls(database=Path(database))

        host = environ.get("RELAY_HOST", defaults.host)
        if not host:
            raise ValueError("RELAY_HOST is empty")

        port = environ.get("RELAY_PORT", str(defaults.port))
        if not port.isdecimal():
            raise ValueError(f"RELAY_PORT is not a port number: {port!r}")

        metrics_port = environ.get("RELAY_METRICS_PORT")
        if metrics_port is not None and not metrics_port.isdecimal():
            raise ValueError(f"RELAY_METRICS_PORT is not a port number: {metrics_port!r}")

        blob_max_bytes = _read_whole_number_above_0(
            environ, "RELAY_BLOB_MAX_BYTES", defaults.blob_max_bytes
        )
        if blob_max_bytes > MAX_UINT32:
            raise ValueError(f"RELAY_BLOB_MAX_BYTES is above {MAX_UINT32}: {blob_max_bytes}")

        name = environ.get("RELAY_NAME", defaults.name)
        if SERVER_NAME.fullmatch(name) is None:
            raise ValueError(f"RELAY_NAME is not a server name: {name!r}")

        return cls(
            database=defaults.database,
            host=host,
            port=int(port),
            name=name,
            login_deadline_seconds=_read_whole_number_above_0(
                environ, "RELAY_LOGIN_DEADLINE_SECONDS", defaults.login_deadline_seconds
            ),
            one_time_prekey_cap=_read_whole_number_above_0(
                environ, "RELAY_ONE_TIME_PREKEY_CAP", defaults.one_time_prekey_cap
            ),
            max_pages=_read_whole_number_above_0(
                environ, "RELAY_MAX_PAGES", defaults.max_pages
            ),
            message_ttl_seconds=_read_whole_number_above_0(
                environ, "RELAY_MESSAGE_TTL_SECONDS", defaults.message_ttl_seconds
            ),
            sweep_interval_seconds=_read_whole_number_above_0(
                environ, "RELAY_SWEEP_INTERVAL_SECONDS", defaults.sweep_interval_seconds
            ),
            queue_max_messages=_read_whole_number_above_0(
                environ, "RELAY_QUEUE_MAX_MESSAGES", defaults.queue_max_messages
            ),
            queue_max_bytes=_read_whole_number_above_0(
                environ, "RELAY_QUEUE_MAX_BYTES", defaults.queue_max_bytes
            ),
            frame_bucket_size=_read_whole_number_above_0(
                environ, "RELAY_FRAME_BUCKET_SIZE", defaults.frame_bucket_size
            ),
            frame_refill_seconds=_read_whole_number_above_0(
                environ, "RELAY_FRAME_REFILL_SECONDS", defaults.frame_refill_seconds
            ),
            handout_bucket_size=_read_whole_number_above_0(
                environ, "RELAY_HANDOUT_BUCKET_SIZE", defaults.handout_bucket_size
            ),
            handout_refill_seconds=_read_whole_number_above_0(
                environ, "RELAY_HANDOUT_REFILL_SECONDS", defaults.handout_refill_seconds
            ),
            blob_max_bytes=blob_max_bytes,
            blob_quota_bytes=_read_whole_number_above_0(
                environ, "RELAY_BLOB_QUOTA_BYTES", defaults.blob_quota_bytes
            ),
            blob_ttl_seconds=_read_whole_number_above_0(
                environ, "RELAY_BLOB_TTL_SECONDS", defaults.blob_ttl_seconds
            ),
            metrics_port=None if metrics_port is None else int(metrics_port),
        )


def _read_whole_number_above_0(environ: Mapping[str, str], name: str, default: float) -> int:
    text = environ.get(name, str(default))
    is_no_whole_number_above_0 = not (text.isdecimal() and int(text) > 0)
    if is_no_whole_number_above_0:
        raise ValueError(f"{name} is not a whole number above 0: {text!r}")
    return int(text)
