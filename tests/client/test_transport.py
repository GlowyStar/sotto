"""The network client against a relay in the process, with a proxy that can tamper."""

import asyncio
import socket
import time
from collections.abc import AsyncIterator, Callable, Coroutine, Iterator
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field, replace
from pathlib import Path

import pytest
from client_harness import Clock, befriend
from relay_harness import OpenClient, make_public_key, messages_in, running_relay
from websockets.asyncio.client import ClientConnection, connect
from websockets.asyncio.server import ServerConnection, serve
from websockets.exceptions import ConnectionClosed

from sotto.client.session import SEEN_ID_SECONDS, SIGNED_PREKEY_GRACE_SECONDS, Client
from sotto.client.store import Store
from sotto.client.transport import (
    Action,
    Connected,
    Event,
    Incoming,
    RefusedError,
    Stopped,
    Transport,
    UrlRefusedError,
    back_off_seconds,
    close_action,
    error_action,
    retry_seconds,
    server_name_of,
)
from sotto.crypto.identity import BadBundleError
from sotto.proto.sotto_pb2 import (
    ClientFrame,
    Error,
    ErrorCode,
    LoggedIn,
    PeerMessage,
    ServerFrame,
    Stored,
    UploadBundle,
)
from sotto.relay.server import CloseCode
from sotto.relay.settings import Settings

PATIENCE_SECONDS = 10
MARKER = "sotto marker 4f1c9e"

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


@pytest.fixture
def make_client(tmp_path: Path) -> Iterator[MakeClient]:
    """Opens the client of a name under the test folder; a second call is a restart."""
    stores: list[Store] = []

    def open_client(name: str) -> Client:
        store = Store(tmp_path / name / "store.db")
        stores.append(store)
        return Client(store)

    yield open_client
    for store in stores:
        store.close()


@asynccontextmanager
async def running(client: Client, url: str) -> AsyncIterator[Transport]:
    """A transport whose task runs, connected, until the block ends."""
    transport = Transport(client, url)
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
    incoming = await next_event(transport, Incoming)
    return incoming.sender, incoming.received.text


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


async def test_two_clients_exchange_texts_in_both_directions(
    relay_url: str, make_client: MakeClient
) -> None:
    alice, bob = make_client("alice"), make_client("bob")
    befriend(alice, bob)
    url = f"{relay_url}/ws"

    async with running(bob, url) as bob_link, running(alice, url) as alice_link:
        await until(is_registered(bob))
        await alice_link.send_text(bob.identity_key, "hello bob")
        assert await next_text(bob_link) == (alice.identity_key, "hello bob")
        await bob_link.send_text(alice.identity_key, "hello alice")
        assert await next_text(alice_link) == (bob.identity_key, "hello alice")

    assert alice.outbox() == bob.outbox() == []


async def test_offline_peer_receives_after_it_starts(
    relay_url: str, make_client: MakeClient
) -> None:
    alice, bob = make_client("alice"), make_client("bob")
    befriend(alice, bob)
    url = f"{relay_url}/ws"
    async with running(bob, url):
        await until(is_registered(bob))

    async with running(alice, url) as alice_link:
        await alice_link.send_text(bob.identity_key, "while you were away")
        await until(lambda: alice.outbox() == [])

    async with running(bob, url) as bob_link:
        assert await next_text(bob_link) == (alice.identity_key, "while you were away")


async def test_relay_restarted_in_the_middle_of_a_conversation_loses_nothing(
    settings: Settings, make_client: MakeClient
) -> None:
    settings = replace(settings, port=free_port())
    alice, bob = make_client("alice"), make_client("bob")
    befriend(alice, bob)
    async with AsyncTasks() as tasks:
        async with running_relay(settings) as url:
            alice_link = Transport(alice, f"{url}/ws")
            bob_link = Transport(bob, f"{url}/ws")
            tasks.start(bob_link.run(), alice_link.run())
            await next_event(bob_link, Connected)
            await next_event(alice_link, Connected)
            await until(is_registered(bob))
            await alice_link.send_text(bob.identity_key, "before")
            assert await next_text(bob_link) == (alice.identity_key, "before")

        await alice_link.send_text(bob.identity_key, "during")
        assert len(alice.outbox()) == 1

        async with running_relay(settings):
            assert await next_text(bob_link) == (alice.identity_key, "during")
            await bob_link.send_text(alice.identity_key, "after")
            assert await next_text(alice_link) == (bob.identity_key, "after")
            await until(lambda: alice.outbox() == bob.outbox() == [])


async def test_client_killed_between_commit_and_stored_delivers_one_text(
    relay_url: str, make_client: MakeClient
) -> None:
    alice, bob = make_client("alice"), make_client("bob")
    befriend(alice, bob)
    url = f"{relay_url}/ws"
    cut = asyncio.Event()

    def cut_at_the_first_stored(connection: int, message: Message) -> Message | None:
        if kind_of(message) == "stored" and not cut.is_set():
            cut.set()
            raise Cut
        return message

    async with running(bob, url) as bob_link:
        await until(is_registered(bob))
        proxy = TamperingProxy(relay_url, to_client=cut_at_the_first_stored)
        async with tampering_proxy(proxy) as proxy_url, running(alice, proxy_url) as link:
            await link.send_text(bob.identity_key, "once")
            await asyncio.wait_for(cut.wait(), PATIENCE_SECONDS)
        assert len(alice.outbox()) == 1

        alice.store.close()
        restarted = make_client("alice")
        async with running(restarted, url):
            await until(lambda: restarted.outbox() == [])

        assert await next_text(bob_link) == (alice.identity_key, "once")
        await asyncio.sleep(0.5)
    assert texts_received(bob) == ["once"]


async def test_connection_cut_between_deliver_and_ack_gives_one_text(
    relay_url: str, settings: Settings, make_client: MakeClient
) -> None:
    alice, bob = make_client("alice"), make_client("bob")
    befriend(alice, bob)
    url = f"{relay_url}/ws"

    def cut_at_the_first_ack(connection: int, message: Message) -> Message | None:
        if client_kind_of(message) == "ack" and connection == 1:
            raise Cut
        return message

    proxy = TamperingProxy(relay_url, to_relay=cut_at_the_first_ack)
    async with tampering_proxy(proxy) as proxy_url, running(bob, proxy_url) as bob_link:
        await until(is_registered(bob))
        async with running(alice, url) as alice_link:
            await alice_link.send_text(bob.identity_key, "only once")
        assert await next_text(bob_link) == (alice.identity_key, "only once")
        copy = await next_event(bob_link, Incoming)
        await until(lambda: messages_in(settings) == [])

    assert copy.received.result == "DUPLICATE"
    assert texts_received(bob) == ["only once"]


async def test_marker_text_is_in_no_frame_log_or_file_of_the_relay(
    relay_url: str,
    settings: Settings,
    make_client: MakeClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    alice, bob = make_client("alice"), make_client("bob")
    befriend(alice, bob)
    proxy = TamperingProxy(relay_url)
    forms = [MARKER.encode(encoding) for encoding in ("utf-8", "utf-16-le", "utf-16-be")]

    def traces() -> list[str]:
        files = [
            settings.database.with_name(settings.database.name + end)
            for end in ("", "-wal", "-shm")
        ]
        contents = [path.read_bytes() for path in files if path.exists()]
        contents += [sent for _, sent in proxy.sent_to_relay]
        contents.append(caplog.text.encode("utf-8"))
        return [
            form.decode("ascii", "replace")
            for form in forms
            for content in contents
            if form in content
        ]

    async with tampering_proxy(proxy) as proxy_url:
        async with running(bob, proxy_url):
            await until(is_registered(bob))
        async with running(alice, proxy_url) as alice_link:
            await alice_link.send_text(bob.identity_key, MARKER)
            await until(lambda: alice.outbox() == [])
        assert len(messages_in(settings)) == 1
        assert traces() == []

        async with running(bob, proxy_url) as bob_link:
            assert await next_text(bob_link) == (alice.identity_key, MARKER)
            await until(lambda: messages_in(settings) == [])
    assert traces() == []


def swap_the_sender(sender: bytes) -> Callable[[ServerFrame], None]:
    def edit(frame: ServerFrame) -> None:
        frame.deliver.sender = sender

    return edit


def flip_a_ciphertext_byte(frame: ServerFrame) -> None:
    envelope = PeerMessage.FromString(frame.deliver.payload)
    ciphertext = bytearray(envelope.ciphertext)
    ciphertext[-1] ^= 1
    envelope.ciphertext = bytes(ciphertext)
    frame.deliver.payload = envelope.SerializeToString()


@pytest.mark.parametrize(
    ("tampering", "result"),
    [("swapped sender", "NO_SESSION"), ("flipped ciphertext byte", "DECRYPT_FAILED")],
)
async def test_tampered_deliver_gives_no_text_and_no_new_handshake(
    relay_url: str, make_client: MakeClient, tampering: str, result: str
) -> None:
    alice, bob, carol = make_client("alice"), make_client("bob"), make_client("carol")
    befriend(alice, bob)
    bob.add_contact(carol.identity_key.hex())
    edit = {
        "swapped sender": swap_the_sender(carol.identity_key),
        "flipped ciphertext byte": flip_a_ciphertext_byte,
    }[tampering]
    tampering_on = False

    def tamper(connection: int, message: Message) -> Message | None:
        if not tampering_on or kind_of(message) != "deliver":
            return message
        assert isinstance(message, bytes)
        frame = ServerFrame.FromString(message)
        edit(frame)
        return frame.SerializeToString()

    proxy = TamperingProxy(relay_url, to_client=tamper)
    url = f"{relay_url}/ws"
    async with tampering_proxy(proxy) as proxy_url, running(bob, proxy_url) as bob_link:
        await until(is_registered(bob))
        async with running(alice, url) as alice_link:
            await alice_link.send_text(bob.identity_key, "first")
            assert await next_text(bob_link) == (alice.identity_key, "first")
            await bob_link.send_text(alice.identity_key, "reply")
            assert await next_text(alice_link) == (bob.identity_key, "reply")
            sessions = (
                len(alice.store.sessions(bob.identity_key)),
                len(bob.store.sessions(alice.identity_key)),
            )

            tampering_on = True
            await alice_link.send_text(bob.identity_key, "tampered")
            tampered = await next_event(bob_link, Incoming)
            tampering_on = False
            await alice_link.send_text(bob.identity_key, "untouched")
            assert await next_text(bob_link) == (alice.identity_key, "untouched")

    assert (tampered.received.text, tampered.received.result) == (None, result)
    assert texts_received(bob) == ["first", "untouched"]
    assert sessions == (
        len(alice.store.sessions(bob.identity_key)),
        len(bob.store.sessions(alice.identity_key)),
    )
    assert bob.store.sessions(carol.identity_key) == []
    assert "fetch_bundle" not in proxy.kinds()


async def test_substituted_bundle_is_refused_and_nothing_is_sent(
    relay_url: str, make_client: MakeClient
) -> None:
    alice, bob = make_client("alice"), make_client("bob")
    befriend(alice, bob)

    def substitute(connection: int, message: Message) -> Message | None:
        if kind_of(message) != "bundle":
            return message
        assert isinstance(message, bytes)
        frame = ServerFrame.FromString(message)
        other = make_public_key()
        frame.bundle.signed_prekey.key = other
        return frame.SerializeToString()

    proxy = TamperingProxy(relay_url, to_client=substitute)
    async with running(bob, f"{relay_url}/ws"):
        await until(is_registered(bob))
    async with tampering_proxy(proxy) as proxy_url, running(alice, proxy_url) as alice_link:
        with pytest.raises(BadBundleError):
            await alice_link.send_text(bob.identity_key, "never sent")

    assert alice.store.sessions(bob.identity_key) == []
    assert alice.outbox() == []
    assert "send" not in proxy.kinds()


@pytest.mark.parametrize(
    ("broken", "close_code"),
    [(b"\xff\xff", 1008), (b"", 1008), ("a text message", 1003), (bytes(65537), 1009)],
)
async def test_broken_server_frame_closes_with_its_code_and_the_client_reconnects(
    relay_url: str, make_client: MakeClient, broken: Message, close_code: int
) -> None:
    def break_the_hello(connection: int, message: Message) -> Message | None:
        return broken if connection == 1 else message

    proxy = TamperingProxy(relay_url, to_client=break_the_hello)
    async with tampering_proxy(proxy) as proxy_url, running(make_client("alice"), proxy_url):
        pass

    assert proxy.client_close_codes[0] == close_code
    assert proxy.connections == 2


async def test_unknown_relay_version_ends_with_1000_and_stops(
    relay_url: str, make_client: MakeClient
) -> None:
    def raise_the_version(connection: int, message: Message) -> Message | None:
        if kind_of(message) != "hello":
            return message
        assert isinstance(message, bytes)
        frame = ServerFrame.FromString(message)
        frame.hello.version = 2
        return frame.SerializeToString()

    proxy = TamperingProxy(relay_url, to_client=raise_the_version)
    async with tampering_proxy(proxy) as proxy_url:
        transport = Transport(make_client("alice"), proxy_url)
        await asyncio.wait_for(transport.run(), PATIENCE_SECONDS)

    assert transport.events.get_nowait() == Stopped(
        reason="the relay speaks protocol version 2"
    )
    assert proxy.client_close_codes == [1000]
    assert proxy.connections == 1


async def test_replaced_client_stops(
    relay_url: str, make_client: MakeClient, open_client: OpenClient
) -> None:
    alice = make_client("alice")
    transport = Transport(alice, f"{relay_url}/ws")
    task = asyncio.create_task(transport.run())
    await next_event(transport, Connected)
    identity = alice.store.identity()
    assert identity is not None

    raw = await open_client(relay_url)
    assert (await raw.log_in(identity.seed)).WhichOneof("frame") == "logged_in"
    await asyncio.wait_for(task, PATIENCE_SECONDS)

    stopped = await next_event(transport, Stopped)
    assert stopped.reason == "the relay closed the connection with 4001"


@pytest.mark.parametrize(
    ("code", "action"),
    [
        *[(code, Action.STOP) for code in (1003, 1008, 1009, 3000, 4001)],
        *[(code, Action.RETRY) for code in (1000, 1001, 1006, 1011, 3008, 4999, None)],
    ],
)
def test_close_codes_get_the_action_of_section_11_3(code: int | None, action: Action) -> None:
    assert close_action(code) is action
    assert {close.value for close in CloseCode} >= {1003, 1008, 1009, 3000, 4001, 1001, 3008}


@pytest.mark.parametrize(
    ("code", "action"),
    [
        (ErrorCode.UNKNOWN_RECIPIENT, Action.STOP),
        (ErrorCode.QUEUE_FULL, Action.BACK_OFF),
        (ErrorCode.STORAGE_FULL, Action.BACK_OFF),
        (ErrorCode.RATE_LIMITED, Action.BACK_OFF),
        (ErrorCode.NOT_FOUND, Action.STOP),
        (ErrorCode.BAD_BUNDLE, Action.STOP),
        (ErrorCode.IDENTITY_KEY_MISMATCH, Action.STOP),
        (0, Action.STOP),
        (99, Action.STOP),
    ],
)
def test_error_codes_get_the_action_of_section_11_2(code: int, action: Action) -> None:
    assert error_action(code) is action


async def test_rate_limited_send_is_sent_again_after_the_back_off(
    settings: Settings, make_client: MakeClient
) -> None:
    alice, bob = make_client("alice"), make_client("bob")
    befriend(alice, bob)
    limited = replace(settings, frame_bucket_size=3, frame_refill_seconds=1)
    async with running_relay(limited) as relay_url:
        url = f"{relay_url}/ws"
        async with running(bob, url) as bob_link, running(alice, url) as alice_link:
            await until(is_registered(bob))
            await until(is_registered(alice))
            await alice_link.send_text(bob.identity_key, "one")
            await alice_link.send_text(bob.identity_key, "two")
            assert await next_text(bob_link) == (alice.identity_key, "one")
            assert await next_text(bob_link) == (alice.identity_key, "two")
            await until(lambda: alice.outbox() == [])


async def test_fetch_of_an_unregistered_contact_is_refused(
    relay_url: str, make_client: MakeClient
) -> None:
    alice, carol = make_client("alice"), make_client("carol")
    alice.add_contact(carol.identity_key.hex())

    async with running(alice, f"{relay_url}/ws") as alice_link:
        with pytest.raises(RefusedError) as refused:
            await alice_link.send_text(carol.identity_key, "nobody home")

    assert refused.value.result == "NOT_FOUND"
    assert alice.outbox() == []


async def test_proxy_of_the_environment_is_not_used(
    relay_url: str, make_client: MakeClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    for variable in ("http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(variable, "http://127.0.0.1:9")
        monkeypatch.setenv(variable.upper(), "http://127.0.0.1:9")
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)

    async with running(make_client("alice"), f"{relay_url}/ws") as transport:
        assert transport.server_name == "127.0.0.1"


@pytest.mark.parametrize(
    ("url", "insecure", "server_name"),
    [
        ("wss://Relay.Example.org:8443/ws", False, "relay.example.org"),
        ("ws://127.0.0.1:8765/ws", False, "127.0.0.1"),
        ("ws://127.200.3.4/ws", False, "127.200.3.4"),
        ("ws://localhost:8765/ws", False, "localhost"),
        ("ws://[::1]:8765/ws", False, "::1"),
        ("ws://[0:0:0:0:0:0:0:1]/ws", False, "0:0:0:0:0:0:0:1"),
        ("ws://127.1:8765/ws", False, None),
        ("ws://0127.0.0.1/ws", False, None),
        ("ws://relay.example.org/ws", False, None),
        ("ws://relay.example.org/ws", True, "relay.example.org"),
        ("ws://127.1:8765/ws", True, "127.1"),
        ("wss://%72elay.example.org/ws", True, None),
        ("wss://xn--rlay-6oa.example.org/ws", False, "xn--rlay-6oa.example.org"),
        ("https://relay.example.org/ws", True, None),
        ("ws:///ws", True, None),
    ],
)
def test_url_rules_of_sections_8_2_and_23_1(
    url: str, insecure: bool, server_name: str | None
) -> None:
    if server_name is None:
        with pytest.raises(UrlRefusedError):
            server_name_of(url, insecure=insecure)
        return
    assert server_name_of(url, insecure=insecure) == server_name


def test_waits_follow_the_schedules() -> None:
    longest = [retry_seconds(attempt, jitter=lambda upper: upper) for attempt in range(1, 9)]
    shortest = [back_off_seconds(refusals, jitter=lambda upper: 0) for refusals in range(1, 9)]

    assert longest == [1.5, 3, 6, 12, 24, 48, 90, 90]
    assert shortest == [1, 2, 4, 8, 16, 32, 60, 60]
    assert retry_seconds(10_000, jitter=lambda upper: 0) == 60


def uploads(proxy: TamperingProxy) -> list[UploadBundle]:
    return [
        ClientFrame.FromString(sent).upload_bundle
        for _, sent in proxy.sent_to_relay
        if client_kind_of(sent) == "upload_bundle"
    ]


@pytest.mark.parametrize(
    "case", ["LoggedIn first", "second Hello", "second LoggedIn", "Stored before the LoggedIn"]
)
async def test_frame_out_of_its_state_closes_with_1008(
    relay_url: str, make_client: MakeClient, case: str
) -> None:
    logged_in = ServerFrame(logged_in=LoggedIn()).SerializeToString()
    stored = ServerFrame(stored=Stored(message_id=bytes(16))).SerializeToString()

    def misplace(connection: int, message: Message) -> Message | list[Message] | None:
        if connection != 1:
            return message
        match case, kind_of(message):
            case "LoggedIn first", "hello":
                return logged_in
            case "second Hello", "hello":
                return [message, message]
            case "second LoggedIn", "logged_in":
                return [message, message]
            case "Stored before the LoggedIn", "logged_in":
                return [stored, message]
        return message

    proxy = TamperingProxy(relay_url, to_client=misplace)
    async with tampering_proxy(proxy) as proxy_url, running(make_client("alice"), proxy_url):
        await until(lambda: proxy.connections == 2)

    assert proxy.client_close_codes[0] == 1008
    assert proxy.connections == 2


async def test_answer_that_matches_no_request_is_ignored(
    relay_url: str, make_client: MakeClient
) -> None:
    alice, bob = make_client("alice"), make_client("bob")
    befriend(alice, bob)
    strays = [
        ServerFrame(stored=Stored(message_id=bytes(16))),
        ServerFrame(error=Error(code=ErrorCode.UNKNOWN_RECIPIENT, message_id=bytes(16))),
        ServerFrame(error=Error(code=ErrorCode.NOT_FOUND, identity=bytes(32))),
    ]

    def add_strays(connection: int, message: Message) -> Message | list[Message] | None:
        if kind_of(message) != "logged_in":
            return message
        return [message, *(stray.SerializeToString() for stray in strays)]

    proxy = TamperingProxy(relay_url, to_client=add_strays)
    async with running(bob, f"{relay_url}/ws") as bob_link:
        await until(is_registered(bob))
        async with tampering_proxy(proxy) as proxy_url, running(alice, proxy_url) as link:
            await link.send_text(bob.identity_key, "still here")
            assert await next_text(bob_link) == (alice.identity_key, "still here")
            await until(lambda: alice.outbox() == [])

    assert proxy.connections == 1


async def test_steps_after_the_login_upload_once_then_send_the_outbox(
    relay_url: str, make_client: MakeClient
) -> None:
    clock = Clock(now=int(time.time()))
    alice = Client(make_client("alice").store, clock=clock)
    bob = make_client("bob")
    befriend(alice, bob)
    proxy = TamperingProxy(relay_url)

    async with running(bob, f"{relay_url}/ws") as bob_link, tampering_proxy(proxy) as url:
        await until(is_registered(bob))
        async with running(alice, url) as alice_link:
            await alice_link.send_text(bob.identity_key, "first")
            assert await next_text(bob_link) == (alice.identity_key, "first")
            await bob_link.send_text(alice.identity_key, "reply")
            assert await next_text(alice_link) == (bob.identity_key, "reply")

        clock.advance(SEEN_ID_SECONDS)
        alice.send_text(bob.identity_key, "second")
        async with running(alice, url):
            await until(lambda: alice.outbox() == [])
        async with running(alice, url):
            await asyncio.sleep(0.5)

    assert proxy.kinds(1)[:4] == ["login", "upload_bundle", "fetch_bundle", "send"]
    assert proxy.kinds(2) == ["login", "upload_bundle", "send"]
    assert proxy.kinds(3) == ["login"]
    first, rotated = uploads(proxy)
    assert (len(first.one_time_prekeys), len(rotated.one_time_prekeys)) == (100, 0)
    assert first.signed_prekey.id != rotated.signed_prekey.id
    assert alice.store.connection.execute("SELECT count(*) FROM seen_ids").fetchone() == (0,)

    identity = alice.store.identity()
    assert identity is not None
    private_keys = [identity.seed, identity.identity_dh_private_key]
    for table in ("signed_prekeys", "one_time_prekeys"):
        rows = alice.store.connection.execute(f"SELECT private_key FROM {table}")  # noqa: S608
        private_keys += [key for (key,) in rows]
    sent = [frame for _, frame in proxy.sent_to_relay]
    assert [key for key in private_keys for frame in sent if key in frame] == []


@pytest.mark.parametrize("ending", ["no answer", "Back off"])
async def test_upload_open_when_the_connection_ends_is_not_sent_again(
    relay_url: str, make_client: MakeClient, ending: str
) -> None:
    refusal = ServerFrame(error=Error(code=ErrorCode.RATE_LIMITED)).SerializeToString()

    def end_the_first_upload(connection: int, message: Message) -> Message | None:
        if connection != 1 or kind_of(message) != "bundle_stored":
            return message
        if ending == "no answer":
            raise Cut
        return refusal

    alice = make_client("alice")
    proxy = TamperingProxy(relay_url, to_client=end_the_first_upload)
    async with tampering_proxy(proxy) as proxy_url, running(alice, proxy_url):
        if ending == "Back off":
            await until(lambda: len(proxy.downstreams) == 1)
            await asyncio.sleep(0.2)
            await proxy.downstreams[0].close(1011)
        await until(is_registered(alice))

    first, rebuilt = uploads(proxy)
    assert proxy.kinds(1) == ["login", "upload_bundle"]
    assert (len(first.one_time_prekeys), len(rebuilt.one_time_prekeys)) == (100, 0)
    assert first.signed_prekey == rebuilt.signed_prekey
    kept = 100 if ending == "no answer" else 0
    assert alice.store.one_time_prekey_count() == kept


async def test_expired_signed_prekey_is_deleted_at_start_before_any_dial(
    make_client: MakeClient,
) -> None:
    clock = Clock()
    alice = Client(make_client("alice").store, clock=clock)
    alice.make_prekeys(0)
    clock.advance(1)
    alice.make_prekeys(0)
    clock.advance(SIGNED_PREKEY_GRACE_SECONDS + 1)

    def signed_prekeys() -> int:
        row = alice.store.connection.execute("SELECT count(*) FROM signed_prekeys").fetchone()
        count: int = row[0]
        return count

    assert signed_prekeys() == 2
    transport = Transport(alice, f"ws://127.0.0.1:{free_port()}/ws")
    task = asyncio.create_task(transport.run())
    try:
        await until(lambda: signed_prekeys() == 1)
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
    events = [transport.events.get_nowait() for _ in range(transport.events.qsize())]
    assert not any(isinstance(event, Connected) for event in events)


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
