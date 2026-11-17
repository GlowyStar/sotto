"""The network client against a relay in the process: a proxy that can tamper with
frames, a transport that runs for a block, and waits for events and states."""

import asyncio
import socket
from collections.abc import AsyncIterator, Callable, Coroutine
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path

from websockets.asyncio.client import ClientConnection, connect
from websockets.asyncio.server import ServerConnection, serve
from websockets.exceptions import ConnectionClosed

from sotto.client.session import Client
from sotto.client.transport import Connected, Event, Incoming, Transport
from sotto.proto.sotto_pb2 import ClientFrame, ServerFrame

PATIENCE_SECONDS = 10

type Message = bytes | str
type Edit = Callable[[int, Message], Message | list[Message] | None]
type MakeClient = Callable[[str], Client]


class Cut(Exception):
    """Raised by an edit of the proxy: the connection ends without its frame."""


def unchanged(connection: int, message: Message) -> Message | None:
    return message


@dataclass
class TamperingProxy:
    """Stands between one client and the relay; edits see the number of the connection."""

    relay_url: str
    to_client: Edit = unchanged
    to_relay: Edit = unchanged
    sent_to_relay: list[tuple[int, bytes]] = field(default_factory=list)
    client_close_codes: list[int | None] = field(default_factory=list)
    downstreams: list[ServerConnection] = field(default_factory=list)
    connections: int = 0

    def kinds(self, connection: int | None = None) -> list[str | None]:
        """The kinds of the frames sent to the relay, on one connection or on all."""
        return [
            client_kind_of(sent)
            for number, sent in self.sent_to_relay
            if connection in (None, number)
        ]

    async def handle(self, downstream: ServerConnection) -> None:
        self.connections += 1
        self.downstreams.append(downstream)
        number = self.connections
        async with connect(f"{self.relay_url}/ws", proxy=None, max_size=None) as upstream:
            try:
                async with asyncio.TaskGroup() as pumps:
                    pumps.create_task(self._pump_to_relay(downstream, upstream, number))
                    pumps.create_task(self._pump_to_client(upstream, downstream, number))
            except* Cut:
                await downstream.close(1011)

    async def _pump_to_relay(
        self, downstream: ServerConnection, upstream: ClientConnection, number: int
    ) -> None:
        with suppress(ConnectionClosed):
            async for message in downstream:
                edited = self.to_relay(number, message)
                if isinstance(edited, bytes):
                    self.sent_to_relay.append((number, edited))
                if isinstance(edited, bytes | str):
                    await upstream.send(edited)
        self.client_close_codes.append(downstream.close_code)
        await upstream.close()

    async def _pump_to_client(
        self, upstream: ClientConnection, downstream: ServerConnection, number: int
    ) -> None:
        with suppress(ConnectionClosed):
            async for message in upstream:
                edited = self.to_client(number, message)
                if isinstance(edited, bytes | str):
                    edited = [edited]
                for one in edited or []:
                    await downstream.send(one)
        code = upstream.close_code
        await downstream.close(_sendable(code))


def _sendable(code: int | None) -> int:
    """The close code of the relay, or 1011 where a close frame cannot carry it."""
    if code is None:
        return 1011
    if 1000 <= code <= 1003 or 1007 <= code <= 1011 or 3000 <= code <= 4999:
        return code
    return 1011


@asynccontextmanager
async def tampering_proxy(proxy: TamperingProxy) -> AsyncIterator[str]:
    async with serve(proxy.handle, "127.0.0.1", 0, max_size=None, compression=None) as server:
        port = server.sockets[0].getsockname()[1]
        yield f"ws://127.0.0.1:{port}/ws"


@asynccontextmanager
async def running(
    client: Client, url: str, *, received_files: Path | None = None
) -> AsyncIterator[Transport]:
    """A transport whose task runs, connected, until the block ends."""
    transport = Transport(client, url, received_files=received_files)
    task = asyncio.create_task(transport.run())
    try:
        await next_event(transport, Connected)
        yield transport
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task


async def next_event[E: Event](transport: Transport, kind: type[E]) -> E:
    async with asyncio.timeout(PATIENCE_SECONDS):
        while True:
            event = await transport.events.get()
            if isinstance(event, kind):
                return event


async def next_text(transport: Transport) -> tuple[bytes, str | None]:
    """The next Incoming that shows a text or a failure, past receipts and duplicates."""
    while True:
        incoming = await next_event(transport, Incoming)
        received = incoming.received
        if received.text is not None or received.result not in (None, "DUPLICATE"):
            return incoming.sender, received.text


async def until(condition: Callable[[], bool]) -> None:
    async with asyncio.timeout(PATIENCE_SECONDS):
        while not condition():  # noqa: ASYNC110 - the state is in a store, not an event
            await asyncio.sleep(0.05)


def is_registered(client: Client) -> Callable[[], bool]:
    """True once the relay confirmed the bundle of the client."""

    def check() -> bool:
        newest = client.store.newest_signed_prekey()
        return newest is not None and newest.confirmed

    return check


def texts_received(client: Client) -> list[str]:
    rows = client.store.connection.execute(
        "SELECT text FROM messages WHERE direction = 'in' ORDER BY rowid"
    ).fetchall()
    return [text for (text,) in rows]


def receipt_of(client: Client, text: str) -> str | None:
    """The receipt that reached the own message of the client with this text."""
    row = client.store.connection.execute(
        "SELECT s.receipt FROM messages m "
        "JOIN message_states s USING (contact, direction, message_id) "
        "WHERE m.direction = 'out' AND m.text = ?",
        (text,),
    ).fetchone()
    return None if row is None else row[0]


def kind_of(message: Message) -> str | None:
    if isinstance(message, str):
        return None
    kind: str | None = ServerFrame.FromString(message).WhichOneof("frame")
    return kind


def client_kind_of(message: Message) -> str | None:
    if isinstance(message, str):
        return None
    kind: str | None = ClientFrame.FromString(message).WhichOneof("frame")
    return kind


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


class AsyncTasks:
    """Tasks of a test, cancelled when its block ends."""

    def __init__(self) -> None:
        self.tasks: list[asyncio.Task[None]] = []

    async def __aenter__(self) -> AsyncTasks:
        return self

    async def __aexit__(self, *_: object) -> None:
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)

    def start(self, *coroutines: Coroutine[object, object, None]) -> None:
        for coroutine in coroutines:
            self.tasks.append(asyncio.create_task(coroutine))
