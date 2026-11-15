"""What the relay tests share: a relay in the process, a client without rules, the log scan."""

import asyncio
import base64
import json
import logging
import os
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Iterator, Sequence
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field

from google.protobuf import text_encoding
from websockets.asyncio.client import ClientConnection
from websockets.exceptions import ConnectionClosed

from sotto.crypto.identity import (
    KEY_LENGTH,
    NONCE_LENGTH,
    derive_identity_key,
    derive_x25519_public_key,
    sign_identity_dh_key,
    sign_login,
    sign_signed_prekey,
)
from sotto.proto.sotto_pb2 import (
    ClientFrame,
    FetchBundle,
    Hello,
    Login,
    OneTimePrekey,
    Send,
    ServerFrame,
    SignedPrekey,
    UploadBundle,
)
from sotto.relay.logs import JsonFormatter
from sotto.relay.server import serve_relay
from sotto.relay.settings import Settings

PATIENCE_SECONDS = 5
WINDOW_BYTES = 8
BASE64_WINDOW_BYTES = 9


@asynccontextmanager
async def running_relay(
    settings: Settings, *, clock: Callable[[], float] = time.time
) -> AsyncIterator[str]:
    async with serve_relay(settings, clock=clock) as server:
        port = server.sockets[0].getsockname()[1]
        yield f"ws://127.0.0.1:{port}"


def make_public_key() -> bytes:
    return derive_x25519_public_key(os.urandom(KEY_LENGTH))


def build_upload(seed: bytes, one_time_prekey_ids: Sequence[int] = ()) -> UploadBundle:
    """Builds a bundle of new keys that the identity of `seed` signed; a test spoils it."""
    identity_dh_key = make_public_key()
    signed_prekey = make_public_key()
    return UploadBundle(
        identity_dh_key=identity_dh_key,
        identity_dh_signature=sign_identity_dh_key(seed, identity_dh_key=identity_dh_key),
        signed_prekey=SignedPrekey(
            id=int.from_bytes(os.urandom(4)),
            key=signed_prekey,
            signature=sign_signed_prekey(seed, signed_prekey=signed_prekey),
        ),
        one_time_prekeys=[
            OneTimePrekey(id=prekey_id, key=make_public_key())
            for prekey_id in one_time_prekey_ids
        ],
    )


@dataclass(frozen=True, slots=True)
class Wire:
    """What the raw clients of a test put on the wire, and where they sat."""

    messages: list[bytes] = field(default_factory=list)
    client_addresses: list[str] = field(default_factory=list)


async def receive_frame(websocket: ClientConnection, wire: Wire) -> ServerFrame:
    async with asyncio.timeout(PATIENCE_SECONDS):
        message = await websocket.recv(decode=False)
    wire.messages.append(message)
    return ServerFrame.FromString(message)


@dataclass(frozen=True, slots=True)
class RawClient:
    """A client that builds its frames by hand, so that it can break every rule."""

    websocket: ClientConnection
    hello: Hello
    server_name: str
    wire: Wire

    def login(self, seed: bytes) -> ClientFrame:
        """Builds the Login that this connection accepts; a test spoils its fields."""
        client_nonce = os.urandom(NONCE_LENGTH)
        signature = sign_login(
            seed,
            server_name=self.server_name,
            server_nonce=self.hello.nonce,
            client_nonce=client_nonce,
        )
        login = Login(
            identity_key=derive_identity_key(seed),
            client_nonce=client_nonce,
            signature=signature,
        )
        return ClientFrame(login=login)

    async def send(self, message: ClientFrame | bytes | str | list[bytes]) -> None:
        """Sends a frame, a binary or a text message, or a binary message in fragments."""
        if isinstance(message, ClientFrame):
            message = message.SerializeToString()
        if isinstance(message, str):
            self.wire.messages.append(message.encode())
        elif isinstance(message, bytes):
            self.wire.messages.append(message)
        else:
            self.wire.messages.extend(message)
        await self.websocket.send(message)

    async def receive(self) -> ServerFrame:
        return await receive_frame(self.websocket, self.wire)

    async def log_in(self, seed: bytes) -> ServerFrame:
        await self.send(self.login(seed))
        return await self.receive()

    async def ask(self, frame: UploadBundle | FetchBundle | Send) -> ServerFrame:
        """Sends a frame that has an answer and returns the next frame of the relay."""
        match frame:
            case UploadBundle():
                await self.send(ClientFrame(upload_bundle=frame))
            case FetchBundle():
                await self.send(ClientFrame(fetch_bundle=frame))
            case Send():
                await self.send(ClientFrame(send=frame))
        return await self.receive()

    async def frames_until_close(self) -> tuple[list[ServerFrame], int | None]:
        """Returns every frame that the relay still sends and the code it closes with."""
        frames = []
        async with asyncio.timeout(PATIENCE_SECONDS):
            with suppress(ConnectionClosed):
                while True:
                    frames.append(await self.receive())
        return frames, self.websocket.close_code


type OpenClient = Callable[[str], Awaitable[RawClient]]


def written_forms(crossed: bytes) -> Iterator[str]:
    """Yields the texts that give away eight bytes in a row of a message, nine in base64.

    The forms are hex, hex with spaces as websockets prints a frame at DEBUG, the escapes
    of `repr(bytes)`, the escapes of a printed protobuf message, and base64.
    """
    for start in range(len(crossed) - WINDOW_BYTES + 1):
        window = crossed[start : start + WINDOW_BYTES]
        yield window.hex()
        yield window.hex(" ")
        yield repr(window)[2:-1]
        yield text_encoding.CEscape(window, as_utf8=False)

    for start in range(len(crossed) - BASE64_WINDOW_BYTES + 1):
        window = crossed[start : start + BASE64_WINDOW_BYTES]
        yield base64.b64encode(window).decode()


def find_leaks(records: Iterable[logging.LogRecord], wire: Wire) -> list[str]:
    """Returns the lines, as the relay prints them, that hold bytes or an address of `wire`."""
    formatter = JsonFormatter()
    lines = [formatter.format(record) for record in records]
    forbidden = {form for crossed in wire.messages for form in written_forms(crossed)}
    forbidden.update(wire.client_addresses)

    leaks = []
    for line in lines:
        # The values and not the line, because JSON doubles the backslashes of an escape.
        text = "\n".join(str(value) for value in json.loads(line).values())
        # Hex is searched whatever its case; the other forms have one spelling.
        searched = text + "\n" + text.lower()
        if any(form in searched for form in forbidden):
            leaks.append(line)
    return leaks
