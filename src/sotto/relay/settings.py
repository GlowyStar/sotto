from collections.abc import Mapping
from dataclasses import dataclass
from typing import Self


@dataclass(frozen=True, slots=True)
class Settings:
    host: str = "127.0.0.1"
    port: int = 8765

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> Self:
        defaults = cls()

        host = environ.get("RELAY_HOST", defaults.host)
        if not host:
            raise ValueError("RELAY_HOST is empty")

        port = environ.get("RELAY_PORT", str(defaults.port))
        if not port.isdecimal():
            raise ValueError(f"RELAY_PORT is not a port number: {port!r}")

        return cls(host=host, port=int(port))
