"""The command line of the client: `sotto`, one data directory per identity.

Peer text reaches the terminal only through `printable`. No command takes the seed as an
argument or prints it (docs/protocol.md, section 22.4).
"""

import argparse
import asyncio
import re
import sys
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from sotto.client.envelope import TextTooLongError
from sotto.client.session import Client, OwnIdentityError
from sotto.client.store import Store, StoreModeError
from sotto.client.transport import (
    Connected,
    Event,
    Incoming,
    Refused,
    RefusedError,
    Retrying,
    Stopped,
    Transport,
    UrlRefusedError,
)
from sotto.crypto.identity import CryptoError, encode_user_id

DEFAULT_RELAY = "ws://127.0.0.1:8765/ws"
DEFAULT_DATA_DIRECTORY = Path.home() / ".sotto"
STORE_NAME = "store.db"
QUIT = "/quit"
QUIT_GRACE_SECONDS = 2
CONTACT_NAME = re.compile(r"[A-Za-z0-9_.-]{1,32}")
BIDI_CONTROLS = frozenset(
    chr(code)
    for code in (0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A))
)
LINE_SEPARATORS = frozenset((chr(0x2028), chr(0x2029)))
SILENT_RESULTS = frozenset({"DUPLICATE", "NOT_A_CONTACT"})


class CommandError(Exception):
    """A command cannot run; the text is for the person at the terminal."""


def printable(text: str) -> str:
    """The text with C0, DEL, C1, bidi controls and line separators written as escapes."""
    return "".join(_escape(character) for character in text)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        return int(arguments.command(arguments))
    except CommandError as error:
        print(f"sotto: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sotto", description="End-to-end encrypted chat through a sotto relay."
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA_DIRECTORY,
        help="the directory of the identity (default: %(default)s)",
    )
    commands = parser.add_subparsers(required=True)

    init = commands.add_parser("init", help="make a new identity and print its user id")
    init.set_defaults(command=_init)
    show_id = commands.add_parser("id", help="print the user id of the identity")
    show_id.set_defaults(command=_show_id)

    add = commands.add_parser("add", help="add a contact by its user id under a local name")
    add.add_argument("name", help="a local name: letters, digits, '.', '_' or '-'")
    add.add_argument("user_id", help="the 64-character user id of the contact")
    add.set_defaults(command=_add)
    contacts = commands.add_parser("contacts", help="list the contacts")
    contacts.set_defaults(command=_contacts)

    chat = commands.add_parser("chat", help="chat with a contact; /quit or end of input ends")
    chat.add_argument("name", help="the local name of the contact")
    _add_relay_options(chat)
    chat.set_defaults(command=_chat)
    reset = commands.add_parser("reset", help="start a new session with a contact")
    reset.add_argument("name", help="the local name of the contact")
    _add_relay_options(reset)
    reset.set_defaults(command=_reset)
    return parser


def _add_relay_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--relay", default=DEFAULT_RELAY, help="the URL of the relay (default: %(default)s)"
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="allow a ws:// URL to a host that is not a loopback host: no TLS",
    )


def _init(arguments: argparse.Namespace) -> int:
    path = arguments.data_dir / STORE_NAME
    if path.exists():
        raise CommandError(f"{arguments.data_dir} already holds an identity")
    store = _open_store(path)
    try:
        client = Client(store)
        print(encode_user_id(client.identity_key))
    finally:
        store.close()
    return 0


def _show_id(arguments: argparse.Namespace) -> int:
    with _client(arguments) as client:
        print(encode_user_id(client.identity_key))
    return 0


def _add(arguments: argparse.Namespace) -> int:
    if CONTACT_NAME.fullmatch(arguments.name) is None:
        raise CommandError("a name is 1 to 32 letters, digits, '.', '_' or '-'")
    with _client(arguments) as client:
        if arguments.name in _names(client).values():
            raise CommandError(f"the name {arguments.name} is taken")
        try:
            contact = client.add_contact(arguments.user_id, name=arguments.name)
        except CryptoError as error:
            raise CommandError("that is not a user id") from error
        except OwnIdentityError as error:
            raise CommandError("that is the id of this identity") from error
        print(f"{_names(client)[contact]} {encode_user_id(contact)}")
    return 0


def _contacts(arguments: argparse.Namespace) -> int:
    with _client(arguments) as client:
        for contact, name in _names(client).items():
            print(f"{name} {encode_user_id(contact)}")
    return 0


def _chat(arguments: argparse.Namespace) -> int:
    with _client(arguments) as client:
        contact = _contact_named(client, arguments.name)
        transport = _transport(client, arguments)
        return asyncio.run(_run_chat(transport, contact))


def _reset(arguments: argparse.Namespace) -> int:
    with _client(arguments) as client:
        contact = _contact_named(client, arguments.name)
        transport = _transport(client, arguments)
        return asyncio.run(_run_reset(transport, contact, arguments.name))


async def _run_chat(transport: Transport, contact: bytes) -> int:
    lines: asyncio.Queue[str | None] = asyncio.Queue()
    leaving = asyncio.Event()
    _read_lines_in_the_background(lines, leaving)
    names = _names(transport.client)
    async with asyncio.TaskGroup() as tasks:
        connection = tasks.create_task(transport.run())
        printer = tasks.create_task(_print_events(transport, names))
        typing = tasks.create_task(_send_lines(transport, contact, lines))
        quitting = tasks.create_task(leaving.wait())
        await asyncio.wait({connection, quitting}, return_when="FIRST_COMPLETED")
        stopped = connection.done()
        if not stopped:
            # The lines typed before /quit go out, unless a send waits for the relay.
            await asyncio.wait({typing}, timeout=QUIT_GRACE_SECONDS)
        for task in (printer, connection, typing, quitting):
            task.cancel()
    _print_waiting_events(transport, names)
    return 1 if stopped else 0


async def _run_reset(transport: Transport, contact: bytes, name: str) -> int:
    # No task group: a refused reset is an answer here, not a failure of the group.
    connection = asyncio.create_task(transport.run())
    reset = asyncio.create_task(transport.reset_session(contact))
    await asyncio.wait({connection, reset}, return_when="FIRST_COMPLETED")
    connection.cancel()
    reset.cancel()
    await asyncio.wait({connection, reset})
    _print_waiting_events(transport, _names(transport.client))

    if reset.cancelled():
        return 1
    try:
        missing = reset.result()
    except RefusedError as error:
        raise CommandError(f"the relay has no bundle of {name}: {error.result}") from error
    except CryptoError as error:
        raise CommandError(f"the bundle of {name} is refused: {error.result}") from error
    print(f"a new session with {name} starts with the next message")
    if missing:
        print(f"{name}: {missing} earlier messages can never be read")
    return 0


async def _send_lines(
    transport: Transport, contact: bytes, lines: asyncio.Queue[str | None]
) -> None:
    while (line := await lines.get()) is not None:
        if not line:
            continue
        try:
            await transport.send_text(contact, line)
        except TextTooLongError:
            _say("not sent: the text is too long")
        except RefusedError as error:
            _say(f"not sent: the relay refused the bundle ({error.result})")
        except CryptoError as error:
            _say(f"not sent: {error.result}")


async def _print_events(transport: Transport, names: dict[bytes, str]) -> None:
    while True:
        _print_event(await transport.events.get(), names)


def _print_waiting_events(transport: Transport, names: dict[bytes, str]) -> None:
    while not transport.events.empty():
        _print_event(transport.events.get_nowait(), names)


def _print_event(event: Event, names: dict[bytes, str]) -> None:
    match event:
        case Connected():
            _say("connected")
        case Incoming(sender=sender, received=received):
            name = names.get(sender) or encode_user_id(sender)
            if received.missing:
                _say(f"{name}: {received.missing} earlier messages can never be read")
            if received.text is not None:
                _say(f"{name}: {printable(received.text)}")
            elif received.result not in SILENT_RESULTS:
                _say(f"{name}: a message could not be read ({received.result})")
        case Refused(result=result, contact=None):
            _say(f"the relay refused the prekey upload ({result})")
        case Refused(result=result, contact=bytes() as contact):
            name = names.get(contact) or encode_user_id(contact)
            _say(f"not sent to {name}: the relay refused it ({result})")
        case Retrying(seconds=seconds):
            _say(f"not connected; next attempt in {seconds:.0f} s")
        case Stopped(reason=reason):
            _say(f"stopped: {reason}")


def _say(line: str) -> None:
    print(line, flush=True)


def _read_lines_in_the_background(
    lines: asyncio.Queue[str | None], leaving: asyncio.Event
) -> None:
    """Feeds stdin to the queue from a daemon thread, which never holds up the exit.

    /quit or the end of input puts None after the lines and sets `leaving`.
    """
    loop = asyncio.get_running_loop()

    def read() -> None:
        try:
            for line in sys.stdin:
                text = line.rstrip("\r\n")
                if text == QUIT:
                    break
                loop.call_soon_threadsafe(lines.put_nowait, text)
            loop.call_soon_threadsafe(lines.put_nowait, None)
            loop.call_soon_threadsafe(leaving.set)
        except RuntimeError:
            # The loop closed while a line was on its way.
            return

    threading.Thread(target=read, daemon=True).start()


@contextmanager
def _client(arguments: argparse.Namespace) -> Iterator[Client]:
    """The client of the data directory, its store closed at the end."""
    path = arguments.data_dir / STORE_NAME
    if not path.exists():
        raise CommandError(f"{arguments.data_dir} holds no identity; run sotto init")
    store = _open_store(path)
    try:
        yield Client(store)
    finally:
        store.close()


def _open_store(path: Path) -> Store:
    try:
        return Store(path)
    except StoreModeError as error:
        raise CommandError(f"{path.parent} or its store is open to others: {error}") from error


def _transport(client: Client, arguments: argparse.Namespace) -> Transport:
    try:
        return Transport(client, arguments.relay, insecure=arguments.insecure)
    except UrlRefusedError as error:
        raise CommandError(f"the relay URL is refused: {error}") from error


def _names(client: Client) -> dict[bytes, str]:
    return {contact: name or "" for contact, name in client.store.contacts()}


def _contact_named(client: Client, name: str) -> bytes:
    for contact, contact_name in client.store.contacts():
        if contact_name == name:
            return contact
    raise CommandError(f"no contact is named {name}; sotto add names one")


def _escape(character: str) -> str:
    code = ord(character)
    is_c0_or_del = code < 0x20 or code == 0x7F
    is_c1 = 0x80 <= code <= 0x9F
    if is_c0_or_del or is_c1:
        return f"\\x{code:02x}"
    if character in BIDI_CONTROLS or character in LINE_SEPARATORS:
        return f"\\u{code:04x}"
    return character
