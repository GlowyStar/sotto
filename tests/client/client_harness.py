"""Clients on stores under a test folder, joined by a dictionary in place of the relay."""

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from hashlib import sha256
from pathlib import Path
from typing import Any

from sotto.client.session import Client, Delivered, Outgoing, PrekeyUpload, Received
from sotto.client.store import Store
from sotto.crypto.identity import Bundle
from sotto.proto.sotto_pb2 import PeerMessage


class Randomness:
    """Random bytes that a test can repeat: SHA-256 of a label and a counter."""

    def __init__(self, label: str) -> None:
        self.label = label.encode()
        self.count = 0

    def __call__(self, length: int) -> bytes:
        output = b""
        while len(output) < length:
            self.count += 1
            output += sha256(self.label + self.count.to_bytes(8)).digest()
        return output[:length]


@dataclass
class Clock:
    """The one clock of every client of a test; the test moves it by hand."""

    now: int = 1_800_000_000

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += seconds


@dataclass
class Clients:
    """Makes clients under one folder and closes their stores at the end of a test."""

    folder: Path
    stores: list[Store] = field(default_factory=list)
    clock: Clock = field(default_factory=Clock)

    def open(self, name: str) -> Client:
        """Opens the client of a name; a second call is a restart on the same store."""
        store = Store(self.folder / name / "store.db")
        self.stores.append(store)
        return Client(store, random_bytes=Randomness(name), clock=self.clock)

    def close(self) -> None:
        for store in self.stores:
            store.close()


@dataclass
class Relay:
    """The relay as a dictionary: prekeys to hand out and a queue per recipient."""

    prekeys: dict[bytes, PrekeyUpload] = field(default_factory=dict)
    queues: dict[bytes, list[Delivered]] = field(default_factory=dict)

    def publish(self, client: Client, *, one_time_count: int = 1) -> None:
        self.prekeys[client.identity_key] = client.make_prekeys(one_time_count)

    def fetch(self, identity: bytes) -> Bundle:
        """Hands out the bundle with the first one-time prekey, which leaves the relay."""
        upload = self.prekeys[identity]
        one_time_prekeys = upload.one_time_prekeys
        self.prekeys[identity] = replace(upload, one_time_prekeys=one_time_prekeys[1:])
        return Bundle(
            identity=identity,
            identity_dh_key=upload.identity_dh_key,
            identity_dh_signature=upload.identity_dh_signature,
            signed_prekey=upload.signed_prekey,
            one_time_prekey=one_time_prekeys[0] if one_time_prekeys else None,
        )

    def send(self, sender: Client, outgoing: Outgoing) -> Delivered:
        delivered = Delivered(
            sender=sender.identity_key,
            message_id=outgoing.message_id,
            payload=outgoing.payload,
        )
        self.queues.setdefault(outgoing.recipient, []).append(delivered)
        return delivered

    def deliver(self, client: Client) -> list[Received]:
        """Delivers the queue of a client in order and empties it."""
        queue = self.queues.pop(client.identity_key, [])
        return [client.receive(delivered) for delivered in queue]


def befriend(first: Client, second: Client) -> None:
    first.add_contact(second.identity_key.hex())
    second.add_contact(first.identity_key.hex())


def send(relay: Relay, sender: Client, recipient: Client, text: str) -> Delivered:
    """L1 at the sender, with a bundle from the relay when it has no session."""
    bundle = None
    if not sender.has_session(recipient.identity_key):
        bundle = relay.fetch(recipient.identity_key)
    outgoing = sender.send_text(recipient.identity_key, text, bundle=bundle)
    return relay.send(sender, outgoing)


def rows(store: Store) -> dict[str, list[tuple[Any, ...]]]:
    """Every row of every table, to compare a store before and after."""
    tables = store.connection.execute(
        "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name"
    ).fetchall()
    return {
        name: store.connection.execute(f'SELECT * FROM "{name}"').fetchall()  # noqa: S608
        for (name,) in tables
    }


def files_holding(folder: Path, value: bytes) -> list[str]:
    """The files of a client folder that hold the value, as bytes or as hex text."""
    holding = []
    for path in folder.iterdir():
        content = path.read_bytes()
        holds_the_bytes = value in content
        holds_the_hex = value.hex().encode() in content
        if holds_the_bytes or holds_the_hex:
            holding.append(path.name)
    return sorted(holding)


def texts(received: list[Received]) -> list[str | None]:
    return [one.text for one in received]


def edit_envelope(delivered: Delivered, edit: Callable[[PeerMessage], None]) -> Delivered:
    envelope = PeerMessage.FromString(delivered.payload)
    edit(envelope)
    return replace(delivered, payload=envelope.SerializeToString())
