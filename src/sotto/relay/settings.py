import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Self

# Rule 4 of docs/protocol.md, section 8.2.
SERVER_NAME = re.compile(r"[a-z0-9._:-]{1,255}")


@dataclass(frozen=True, slots=True)
class Settings:
    database: Path
    host: str = "127.0.0.1"
    port: int = 8765
    name: str = "127.0.0.1"
    login_deadline_seconds: float = 10
    one_time_prekey_cap: int = 100
    max_pages: int = 262144

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
        )


def _read_whole_number_above_0(environ: Mapping[str, str], name: str, default: float) -> int:
    text = environ.get(name, str(default))
    is_no_whole_number_above_0 = not (text.isdecimal() and int(text) > 0)
    if is_no_whole_number_above_0:
        raise ValueError(f"{name} is not a whole number above 0: {text!r}")
    return int(text)
