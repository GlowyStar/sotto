import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Self

# Rule 4 of docs/protocol.md, section 8.2.
SERVER_NAME = re.compile(r"[a-z0-9._:-]{1,255}")


@dataclass(frozen=True, slots=True)
class Settings:
    host: str = "127.0.0.1"
    port: int = 8765
    name: str = "127.0.0.1"
    login_deadline_seconds: float = 10

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> Self:
        defaults = cls()

        host = environ.get("RELAY_HOST", defaults.host)
        if not host:
            raise ValueError("RELAY_HOST is empty")

        port = environ.get("RELAY_PORT", str(defaults.port))
        if not port.isdecimal():
            raise ValueError(f"RELAY_PORT is not a port number: {port!r}")

        name = environ.get("RELAY_NAME", defaults.name)
        if SERVER_NAME.fullmatch(name) is None:
            raise ValueError(f"RELAY_NAME is not a server name: {name!r}")

        deadline = environ.get(
            "RELAY_LOGIN_DEADLINE_SECONDS", str(defaults.login_deadline_seconds)
        )
        gives_no_time = not deadline.isdecimal() or int(deadline) == 0
        if gives_no_time:
            raise ValueError(
                f"RELAY_LOGIN_DEADLINE_SECONDS is not a whole number above 0: {deadline!r}"
            )

        return cls(host=host, port=int(port), name=name, login_deadline_seconds=int(deadline))
