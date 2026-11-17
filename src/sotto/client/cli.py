"""The command line of the client: `sotto`, one data directory per identity.

Peer text reaches the terminal only through `printable`. No command takes the seed as an
argument or prints it (docs/protocol.md, section 22.4). Received files go into the folder
`received` of the data directory (section 32.2). The profile of part 4 is set offline and
goes to the contacts at the next connection; the local name of a contact is the name used.
"""

import argparse
import asyncio
import os
import re
import sys
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from sotto.client.envelope import MAX_AVATAR_BYTES, TextTooLongError, is_control
from sotto.client.files import FILE_MODE
from sotto.client.session import Client, FileState, OwnIdentityError
from sotto.client.store import ContactProfile, Store, StoreModeError
from sotto.client.transport import (
    Connected,
    Event,
    FileUpdate,
    Incoming,
    Refused,
    RefusedError,
    Retrying,
    Stopped,
    TransferFailed,
    Transport,
    UrlRefusedError,
)
from sotto.crypto.identity import CryptoError, encode_user_id

DEFAULT_RELAY = "ws://127.0.0.1:8765/ws"
DEFAULT_DATA_DIRECTORY = Path.home() / ".sotto"
STORE_NAME = "store.db"
RECEIVED_FILES = "received"
PROGRESS_STEPS = 10
SENDING_ENDS = frozenset({FileState.SENT, FileState.NOT_SENT})
QUIT = "/quit"
QUIT_GRACE_SECONDS = 2
CONTACT_NAME = re.compile(r"[A-Za-z0-9_.-]{1,32}")
# UNKNOWN_CONTENT may be a later member of Content that is no message (section 20.3).
SILENT_RESULTS = frozenset({"DUPLICATE", "NOT_A_CONTACT", "UNKNOWN_CONTENT"})

type Commands = argparse._SubParsersAction[argparse.ArgumentParser]


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

    send_file = commands.add_parser(
        "send-file", help="send a file to a contact and wait until it is sent or not sent"
    )
    send_file.add_argument("name", help="the local name of the contact")
    send_file.add_argument("path", type=Path, help="the file, up to 100 MiB")
    send_file.add_argument("--caption", default="", help="a text shown with the file")
    _add_relay_options(send_file)
    send_file.set_defaults(command=_send_file)
    _add_profile_commands(commands)
    return parser


def _add_profile_commands(commands: Commands) -> None:
    profile = commands.add_parser(
        "profile", help="set, show or clear the name and the avatar your contacts see"
    )
    actions = profile.add_subparsers(required=True)

    set_profile = actions.add_parser(
        "set", help="set the name, the avatar or both; it goes out at the next chat"
    )
    set_profile.add_argument("--name", help="the name your contacts see, up to 256 bytes")
    avatar = set_profile.add_mutually_exclusive_group()
    avatar.add_argument("--avatar", type=Path, help="a JPEG or PNG picture, up to 1 MiB")
    avatar.add_argument("--no-avatar", action="store_true", help="remove the avatar")
    set_profile.set_defaults(command=_set_profile)

    show = actions.add_parser("show", help="print your profile or the one a contact sent")
    show.add_argument("name", nargs="?", help="the local name of a contact")
    show.add_argument("--avatar-to", type=Path, help="write the avatar into this new file")
    show.set_defaults(command=_show_profile)

    clear = actions.add_parser("clear", help="clear the name and the avatar")
    clear.set_defaults(command=_clear_profile)


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
            sent = client.store.profile(contact)
            note = "" if sent is None else f" {_profile_note(client, sent)}"
            print(f"{name} {encode_user_id(contact)}{note}")
    return 0


def _set_profile(arguments: argparse.Namespace) -> int:
    has_a_change = arguments.name is not None or arguments.avatar or arguments.no_avatar
    if not has_a_change:
        raise CommandError("give --name, --avatar or --no-avatar")
    with _client(arguments) as client:
        own = client.own_profile()
        name, avatar = own.name, own.avatar
        if arguments.name is not None:
            name = arguments.name
        if arguments.no_avatar:
            avatar = None
        if arguments.avatar is not None:
            avatar = _read_avatar(arguments.avatar)
        _save_profile(client, name, avatar)
    return 0


def _clear_profile(arguments: argparse.Namespace) -> int:
    with _client(arguments) as client:
        _save_profile(client, "", None)
    return 0


def _show_profile(arguments: argparse.Namespace) -> int:
    with _client(arguments) as client:
        if arguments.name is None:
            own = client.own_profile()
            name, avatar = own.name, own.avatar
            has_avatar = avatar is not None
            avatar_note = f"avatar {own.media_type}" if has_avatar else "no avatar"
        else:
            contact = _contact_named(client, arguments.name)
            sent = client.store.profile(contact)
            if sent is None:
                print(f"{arguments.name} sent no profile")
                return 0
            name, avatar = sent.name, sent.avatar
            has_avatar = sent.avatar_file is not None
            avatar_note = _avatar_note(client, sent)

        is_the_empty_profile = not name and not has_avatar
        if is_the_empty_profile:
            print("no profile")
        else:
            print(f'name "{printable(name)}"' if name else "no name")
            size = "" if avatar is None else f", {len(avatar)} bytes"
            print(f"{avatar_note}{size}")
        if arguments.avatar_to is not None:
            _write_avatar(arguments.avatar_to, avatar)
    return 0


def _chat(arguments: argparse.Namespace) -> int:
    with _client(arguments) as client:
        contact = _contact_named(client, arguments.name)
        transport = _transport(client, arguments)
        return asyncio.run(_run_chat(transport, contact))


def _send_file(arguments: argparse.Namespace) -> int:
    with _client(arguments) as client:
        contact = _contact_named(client, arguments.name)
        transport = _transport(client, arguments)
        return asyncio.run(
            _run_send_file(transport, contact, arguments.path, arguments.caption)
        )


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


async def _run_send_file(
    transport: Transport, contact: bytes, path: Path, caption: str
) -> int:
    """Sends a file and prints the events until it is sent or not sent. A file whose
    sending stops with the command goes on at the next `chat` or `send-file`."""
    names = _names(transport.client)
    progress: dict[bytes, int] = {}
    connection = asyncio.create_task(transport.run())
    sending = asyncio.create_task(transport.send_file(contact, path, caption=caption))
    try:
        await asyncio.wait({connection, sending}, return_when="FIRST_COMPLETED")
        if not sending.done():
            _print_waiting_events(transport, names)
            return 1
        try:
            blob_id = sending.result()
        except CryptoError as error:
            raise CommandError(f"not sent: {error.result}") from error
        except OSError as error:
            raise CommandError(f"cannot read {path}: {error.strerror}") from error
        except ValueError as error:
            raise CommandError("not sent: the caption is too long") from error

        while True:
            event = await transport.events.get()
            _print_event(event, names, progress)
            if isinstance(event, Stopped | TransferFailed):
                return 1
            if not isinstance(event, FileUpdate) or event.blob_id != blob_id:
                continue
            if event.state in SENDING_ENDS:
                return 0 if event.state == FileState.SENT else 1
    finally:
        connection.cancel()
        sending.cancel()
        await asyncio.wait({connection, sending})


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
    progress: dict[bytes, int] = {}
    while True:
        _print_event(await transport.events.get(), names, progress)


def _print_waiting_events(transport: Transport, names: dict[bytes, str]) -> None:
    while not transport.events.empty():
        _print_event(transport.events.get_nowait(), names, {})


def _print_event(event: Event, names: dict[bytes, str], progress: dict[bytes, int]) -> None:
    """Prints an event; `progress` keeps the tenth of each transfer last printed."""
    match event:
        case Connected():
            _say("connected")
        case Incoming(sender=sender, received=received):
            name = names.get(sender) or encode_user_id(sender)
            if received.missing:
                _say(f"{name}: {received.missing} earlier messages can never be read")
            if received.text is not None:
                _say(f"{name}: {printable(received.text)}")
            elif received.profile is not None:
                profile = received.profile
                has_avatar = profile.HasField("avatar")
                _say(f"{name}: {_describe_profile(profile.name, has_avatar=has_avatar)}")
            elif received.attachment is not None:
                attachment = received.attachment
                caption = f": {printable(attachment.caption)}" if attachment.caption else ""
                _say(
                    f"{name}: file {printable(attachment.file_name)}, "
                    f"{attachment.size} bytes{caption}"
                )
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
        case TransferFailed(reason=reason):
            _say(f"a transfer stopped and goes on after the next login: {reason}")
        case FileUpdate():
            _print_file_update(
                event, names.get(event.contact) or encode_user_id(event.contact), progress
            )


def _print_file_update(update: FileUpdate, name: str, progress: dict[bytes, int]) -> None:
    if update.avatar:
        _print_avatar_update(update, name)
        return
    file_name = printable(update.file_name)
    match update.state:
        case FileState.SENDING | FileState.RECEIVING:
            tenth = PROGRESS_STEPS * update.done // max(update.total, 1)
            if progress.get(update.blob_id) == tenth:
                return
            progress[update.blob_id] = tenth
            percent = 100 * tenth // PROGRESS_STEPS
            _say(f"{update.state} {file_name}, {name}: {percent}%")
        case FileState.RECEIVED:
            _say(f"{name}: {file_name} saved as {printable(str(update.path))}")
        case FileState.SENT:
            _say(f"sent {file_name} to {name}")
        case _:
            _say(f"{update.state}: {file_name}, {name} ({update.result})")


def _print_avatar_update(update: FileUpdate, name: str) -> None:
    """Only the end of an avatar transfer that failed: the profile line said the rest."""
    match update.state:
        case FileState.NOT_SENT:
            _say(f"your avatar was not sent to {name} ({update.result})")
        case FileState.NOT_RECEIVED | FileState.NOT_AVAILABLE:
            _say(f"{name}: the avatar {update.state} ({update.result})")


def _describe_profile(name: str, *, has_avatar: bool) -> str:
    is_the_empty_profile = not name and not has_avatar
    if is_the_empty_profile:
        return "profile cleared"
    named = f'profile "{printable(name)}"' if name else "profile without a name"
    return f"{named}, {'with an avatar' if has_avatar else 'no avatar'}"


def _profile_note(client: Client, sent: ContactProfile) -> str:
    """The profile a contact sent, for a line that starts with the local name."""
    named = f'"{printable(sent.name)}"' if sent.name else "without a name"
    return f"profile {named}, {_avatar_note(client, sent)}"


def _avatar_note(client: Client, sent: ContactProfile) -> str:
    if sent.avatar_file is None:
        return "no avatar"
    if sent.avatar is not None:
        return "avatar received"
    file = client.store.file(sent.avatar_file)
    state = FileState.OFFERED if file is None else file.state
    return f"avatar {state}"


def _read_avatar(path: Path) -> bytes:
    """At most one byte more than MAX_AVATAR_BYTES, enough for the check of the client."""
    try:
        with path.open("rb") as file:
            return file.read(MAX_AVATAR_BYTES + 1)
    except OSError as error:
        raise CommandError(f"cannot read {path}: {error.strerror}") from error


def _save_profile(client: Client, name: str, avatar: bytes | None) -> None:
    try:
        client.set_profile(name, avatar)
    except CryptoError as error:
        raise CommandError(f"the profile is not set: {error.result}") from error
    print(_describe_profile(name, has_avatar=avatar is not None))
    print("it goes to your contacts at the next chat")


def _write_avatar(path: Path, avatar: bytes | None) -> None:
    if avatar is None:
        raise CommandError("there is no avatar to write")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
    except OSError as error:
        raise CommandError(f"cannot write {path}: {error.strerror}") from error
    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(avatar)
    except OSError as error:
        path.unlink(missing_ok=True)
        raise CommandError(f"cannot write {path}: {error.strerror}") from error


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
        return Transport(
            client,
            arguments.relay,
            insecure=arguments.insecure,
            received_files=arguments.data_dir / RECEIVED_FILES,
        )
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
    if not is_control(character):
        return character
    code = ord(character)
    if code <= 0xFF:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}"
