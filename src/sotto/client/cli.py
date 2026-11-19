"""The command line of the client: `sotto`, one data directory per identity.

Peer text reaches the terminal only through `printable`. No command takes the seed as an
argument or prints it (docs/protocol.md, section 22.4). Received files go into the folder
`received` of the data directory (section 32.2). The profile of part 4 is set offline and
goes to the contacts at the next connection; the local name of a contact is the name used.
`chat` prints every message with its number in the log, which the commands of part 5 take
(section 39), and counts a message as read once it printed it. At a terminal `chat`
edits the typed line in place under what it prints; from a pipe it reads plain lines.
"""

import argparse
import asyncio
import codecs
import os
import re
import signal
import sys
import termios
import threading
import tty
import unicodedata
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from sotto.client.envelope import MAX_AVATAR_BYTES, TextTooLongError, is_control
from sotto.client.files import FILE_MODE
from sotto.client.session import Client, FileState, OwnIdentityError, Quoted, Received
from sotto.client.store import ContactProfile, Store, StoreModeError
from sotto.client.transport import (
    Connected,
    Event,
    Expired,
    FileUpdate,
    Incoming,
    Refused,
    RefusedError,
    Retrying,
    Sent,
    Stopped,
    TransferFailed,
    Transport,
    UrlRefusedError,
    Written,
)
from sotto.crypto.identity import CryptoError, encode_user_id
from sotto.crypto.safety_number import qr_payload, safety_number

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
CHAT_COMMANDS = (
    "commands: /reply N text, /edit N text, /delete N, /timer [off|30s|5m|1h|1d|1w], /quit"
)
# One row of an 80-column terminal.
CHAT_HINT = "Enter sends, /quit leaves; /reply N text, /edit N text, /delete N, /timer 1h|off"
PROMPT = "> "
READ_BYTES = 4096
FALLBACK_COLUMNS = 80
# A key as a terminal sends it: a CSI or SS3 sequence, Alt with b, f or Backspace, or a
# character; a lone Esc is a control character like any other.
KEY = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1bO.|\x1b[bf\x7f]|.", re.DOTALL)
UNFINISHED_KEY = re.compile(r"\x1b(\[[0-?]*[ -/]*|O)?\Z")
TIMER = re.compile(r"([0-9]{1,7})([smhdw])")
TIMER_UNITS = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
QUOTE_SHOWN = 60
GROUP_DIGITS = 5
ROW_DIGITS = 20

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

    receipts = commands.add_parser(
        "read-receipts", help="show, or turn on or off, the read receipts contacts get"
    )
    receipts.add_argument("state", nargs="?", choices=("on", "off"))
    receipts.set_defaults(command=_read_receipts)

    verify = commands.add_parser(
        "verify", help="show the safety number of a contact; mark it verified or clear that"
    )
    verify.add_argument("name", help="the local name of the contact")
    verify.add_argument("action", nargs="?", choices=("mark", "clear"))
    verify.set_defaults(command=_verify)
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
            mark = " verified" if client.store.is_verified(contact) else ""
            note = "" if sent is None else f" {_profile_note(client, sent)}"
            print(f"{name} {encode_user_id(contact)}{mark}{note}")
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


def _verify(arguments: argparse.Namespace) -> int:
    with _client(arguments) as client:
        contact = _contact_named(client, arguments.name)
        if arguments.action == "mark":
            client.mark_verified(contact)
        elif arguments.action == "clear":
            client.clear_verified(contact)
        else:
            _print_safety_number(client, contact, arguments.name)
        state = "verified" if client.store.is_verified(contact) else "not verified"
        print(f"{arguments.name} is {state}")
    return 0


def _print_safety_number(client: Client, contact: bytes, name: str) -> None:
    number = safety_number(client.identity_key, contact)
    print(f"safety number with {name}:")
    for row in range(0, len(number), ROW_DIGITS):
        groups = range(row, row + ROW_DIGITS, GROUP_DIGITS)
        print(" ".join(number[start : start + GROUP_DIGITS] for start in groups))
    print(f"qr payload: {qr_payload(client.identity_key, contact)}")


def _read_receipts(arguments: argparse.Namespace) -> int:
    with _client(arguments) as client:
        if arguments.state is not None:
            client.set_read_receipts(on=arguments.state == "on")
        print(f"read receipts: {'on' if client.read_receipts() else 'off'}")
    return 0


def _chat(arguments: argparse.Namespace) -> int:
    with _client(arguments) as client:
        contact = _contact_named(client, arguments.name)
        transport = _transport(client, arguments)
        _say(f"timer: {describe_timer(client.timer(contact))}")
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
    names = _names(transport.client)
    with _typed_lines(lines, leaving):
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


def describe_timer(seconds: int) -> str:
    """`off`, or the seconds in the largest unit of TIMER_UNITS that divides them."""
    if seconds == 0:
        return "off"
    for unit, unit_seconds in TIMER_UNITS.items():
        if seconds % unit_seconds == 0:
            return f"{seconds // unit_seconds}{unit}"
    return f"{seconds}s"


def parse_timer(text: str) -> int:
    """The seconds of `off` or of a number with a unit of TIMER_UNITS, such as `5m`.

    Raises:
        CommandError: The text is neither.
    """
    if text == "off":
        return 0
    match = TIMER.fullmatch(text)
    if match is None:
        raise CommandError(CHAT_COMMANDS)
    return int(match.group(1)) * TIMER_UNITS[match.group(2)]


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
            _show(transport, event, names, progress)
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
            await _run_line(transport, contact, line)
        except CommandError as error:
            _say(str(error))
        except TextTooLongError:
            _say("not sent: the text is too long")
        except RefusedError as error:
            _say(f"not sent: the relay refused the bundle ({error.result})")
        except CryptoError as error:
            _say(f"not sent: {error.result}")


async def _run_line(transport: Transport, contact: bytes, line: str) -> None:
    """Sends a typed line as a text, or runs the chat command of part 5 it starts with.

    Raises:
        CommandError: The line is a command that does not parse.
    """
    if not line.startswith("/"):
        await transport.send_text(contact, line)
        return

    command, _, rest = line.partition(" ")
    match command:
        case "/reply":
            number, text = _number_and_text(rest)
            await transport.send_text(contact, text, reply_to=number)
        case "/edit":
            number, text = _number_and_text(rest)
            await transport.edit(contact, number, text)
            _say(f"#{number} you edited: {printable(text)}")
        case "/delete":
            number = _number(rest)
            await transport.delete(contact, number)
            _say(f"#{number} deleted for both")
        case "/timer":
            if rest:
                await transport.set_timer(contact, parse_timer(rest))
            _say(f"timer: {describe_timer(transport.client.timer(contact))}")
        case _:
            raise CommandError(CHAT_COMMANDS)


def _number_and_text(rest: str) -> tuple[int, str]:
    number, _, text = rest.partition(" ")
    if not text:
        raise CommandError(CHAT_COMMANDS)
    return _number(number), text


def _number(text: str) -> int:
    if not text.isdecimal():
        raise CommandError(CHAT_COMMANDS)
    return int(text)


async def _print_events(transport: Transport, names: dict[bytes, str]) -> None:
    """Prints the events of a chat, and the hint once after the first `connected` when the
    line is typed at a terminal."""
    progress: dict[bytes, int] = {}
    hint_is_due = _typed is not None
    while True:
        event = await transport.events.get()
        _show(transport, event, names, progress)
        hint_now = hint_is_due and isinstance(event, Connected)
        if hint_now:
            _say(CHAT_HINT)
            hint_is_due = False


def _print_waiting_events(transport: Transport, names: dict[bytes, str]) -> None:
    while not transport.events.empty():
        _show(transport, transport.events.get_nowait(), names, {})


def _show(
    transport: Transport, event: Event, names: dict[bytes, str], progress: dict[bytes, int]
) -> None:
    """Prints an event; a message of the chat that it printed counts as read (39.5)."""
    _print_event(event, names, progress)
    if not isinstance(event, Incoming):
        return
    number = event.received.number
    if number is not None and event.received.is_a_new_message:
        transport.mark_read(event.sender, number)


def _print_event(event: Event, names: dict[bytes, str], progress: dict[bytes, int]) -> None:
    """Prints an event; `progress` keeps the tenth of each transfer last printed."""
    match event:
        case Connected():
            _say("connected")
        case Incoming(sender=sender, received=received):
            name = names.get(sender) or encode_user_id(sender)
            if received.missing:
                _say(f"{name}: {received.missing} earlier messages can never be read")
            _print_received(received, name)
        case Written():
            reply = "" if event.reply_to is None else f", replying to #{event.reply_to}"
            head = _message_head(event.number, "you", event.expires_after)
            _say(f"{head}{reply}: {printable(event.text)}")
        case Sent(number=number):
            _say(f"#{number} sent")
        case Expired(numbers=numbers):
            for number in numbers:
                _say(f"#{number} disappeared")
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


def _print_received(received: Received, name: str) -> None:
    """One line for a message, a change of part 5 or a failure; several for a receipt."""
    if received.edited:
        _say(f"#{received.number} {name} edited: {printable(received.text or '')}")
    elif received.deleted:
        _say(f"#{received.number} {name} deleted the message")
    elif received.marked:
        for number in received.marked:
            _say(f"#{number} {'read' if received.read else 'delivered'}")
    elif received.timer is not None:
        _say(f"{name} set the timer: {describe_timer(received.timer)}")
    elif received.text is not None:
        _say(f"{_received_head(received, name)}: {printable(received.text)}")
    elif received.profile is not None:
        profile = received.profile
        has_avatar = profile.HasField("avatar")
        _say(f"{name}: {_describe_profile(profile.name, has_avatar=has_avatar)}")
    elif received.attachment is not None:
        attachment = received.attachment
        caption = f": {printable(attachment.caption)}" if attachment.caption else ""
        _say(
            f"{_received_head(received, name)}: file {printable(attachment.file_name)}, "
            f"{attachment.size} bytes{caption}"
        )
    elif received.result is not None and received.result not in SILENT_RESULTS:
        _say(f"{name}: a message could not be read ({received.result})")


def _received_head(received: Received, name: str) -> str:
    head = _message_head(received.number, name, received.expires_after)
    if received.quote is None:
        return head
    return f"{head}, replying to {_describe_quote(received.quote)}"


def _message_head(number: int | None, who: str, expires_after: int) -> str:
    """`#12 alice`, with the timer of the message as `(1h)` behind it when it has one."""
    head = who if number is None else f"#{number} {who}"
    if expires_after:
        head += f" ({describe_timer(expires_after)})"
    return head


def _describe_quote(quote: Quoted) -> str:
    if quote.text is None:
        return "a message that is gone"
    shown = quote.text[:QUOTE_SHOWN] + ("..." if len(quote.text) > QUOTE_SHOWN else "")
    text = f'"{printable(shown)}"'
    return text if quote.number is None else f"#{quote.number} {text}"


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
    if _typed is None:
        print(line, flush=True)
        return
    # The typed line gives its row to the printed one and is drawn again under it.
    print(f"\r\x1b[K{line}\n{_typed.drawn(_columns())}", end="", flush=True)


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


class TypedLine:
    """The line typed at a terminal and the cursor in it, edited by the keys of an
    Emacs-style line editor."""

    def __init__(self) -> None:
        self.text = ""
        self.cursor = 0

    def press(self, key: str) -> str | None:
        """Applies one key as `KEY` cuts them; returns the line that Enter ends.

        A key it does not know changes nothing, and a control character is never typed.
        """
        text, cursor = self.text, self.cursor
        match key:
            case "\r" | "\n":
                self.text, self.cursor = "", 0
                return text
            case "\x7f" | "\x08":
                start = max(cursor - 1, 0)
                text, cursor = text[:start] + text[cursor:], start
            case "\x04" | "\x1b[3~":
                text = text[:cursor] + text[cursor + 1 :]
            case "\x17" | "\x1b\x7f":
                start = _previous_word(text, cursor)
                text, cursor = text[:start] + text[cursor:], start
            case "\x15":
                text, cursor = text[cursor:], 0
            case "\x0b":
                text = text[:cursor]
            case "\x02" | "\x1b[D" | "\x1bOD":
                cursor = max(cursor - 1, 0)
            case "\x06" | "\x1b[C" | "\x1bOC":
                cursor = min(cursor + 1, len(text))
            case "\x1bb" | "\x1b[1;3D" | "\x1b[1;5D":
                cursor = _previous_word(text, cursor)
            case "\x1bf" | "\x1b[1;3C" | "\x1b[1;5C":
                cursor = _next_word(text, cursor)
            case "\x01" | "\x1b[H" | "\x1bOH" | "\x1b[1~" | "\x1b[7~":
                cursor = 0
            case "\x05" | "\x1b[F" | "\x1bOF" | "\x1b[4~" | "\x1b[8~":
                cursor = len(text)
            case _ if len(key) == 1 and not is_control(key):
                text, cursor = text[:cursor] + key + text[cursor:], cursor + 1
        self.text, self.cursor = text, cursor
        return None

    def drawn(self, columns: int) -> str:
        """The prompt and the part of the line around the cursor that fits one row, then
        the cursor in its place. A long line scrolls sideways and never wraps, because a
        line printed above a wrapped one would split it."""
        room = columns - len(PROMPT) - 1
        widths = [_width(character) for character in self.text]
        start, before = self.cursor, 0
        for width in reversed(widths[: self.cursor]):
            if before + width > room:
                break
            start -= 1
            before += width
        end, used = self.cursor, before
        for width in widths[self.cursor :]:
            if used + width > room:
                break
            end += 1
            used += width
        return f"\r{PROMPT}{self.text[start:end]}\x1b[K\r\x1b[{len(PROMPT) + before}C"


_typed: TypedLine | None = None


@contextmanager
def _typed_lines(lines: asyncio.Queue[str | None], leaving: asyncio.Event) -> Iterator[None]:
    """Feeds the lines the user types to the queue, then None, and sets `leaving` at /quit
    or the end of input: edited in place when stdin and stdout are a terminal, read as
    they come otherwise."""
    stdin_is_piped = not sys.stdin.isatty()
    stdout_is_piped = not sys.stdout.isatty()
    if stdin_is_piped or stdout_is_piped:
        _read_lines_in_the_background(lines, leaving)
        yield
        return

    global _typed
    descriptor = sys.stdin.fileno()
    saved = tty.setcbreak(descriptor, termios.TCSANOW)
    _typed = TypedLine()
    try:
        _read_keys_in_the_loop(descriptor, _typed, lines, leaving)
        yield
    finally:
        loop = asyncio.get_running_loop()
        loop.remove_reader(descriptor)
        loop.remove_signal_handler(signal.SIGTERM)
        _typed = None
        print("\r\x1b[K", end="", flush=True)
        termios.tcsetattr(descriptor, termios.TCSADRAIN, saved)


def _read_keys_in_the_loop(
    descriptor: int,
    typed: TypedLine,
    lines: asyncio.Queue[str | None],
    leaving: asyncio.Event,
) -> None:
    """Reads the keys of a terminal in cbreak mode in the event loop and draws the typed
    line after each read; the lines go to the queue as `_read_lines_in_the_background`
    puts them. SIGTERM ends the input as /quit does, so the terminal gets its modes back."""
    loop = asyncio.get_running_loop()
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    unfinished = ""

    def end_the_input() -> None:
        loop.remove_reader(descriptor)
        lines.put_nowait(None)
        leaving.set()

    def read() -> None:
        nonlocal unfinished
        try:
            data = os.read(descriptor, READ_BYTES)
        except BlockingIOError:
            return
        except OSError:
            data = b""
        if not data:
            end_the_input()
            return
        keys = unfinished + decoder.decode(data)
        complete = UNFINISHED_KEY.sub("", keys, count=1)
        unfinished = keys[len(complete) :]
        if _take_keys(typed, complete, lines):
            print(typed.drawn(_columns()), end="", flush=True)
        else:
            end_the_input()

    loop.add_reader(descriptor, read)
    loop.add_signal_handler(signal.SIGTERM, end_the_input)


def _columns() -> int:
    """The width of the terminal; a pseudo-terminal that was never given a size has 0."""
    return os.get_terminal_size(sys.stdout.fileno()).columns or FALLBACK_COLUMNS


def _take_keys(typed: TypedLine, keys: str, lines: asyncio.Queue[str | None]) -> bool:
    """Presses the keys and queues each line that Enter ends; False once /quit or Ctrl-D
    on an empty line ends the input."""
    for key in KEY.findall(keys):
        ends_the_input = key == "\x04" and not typed.text
        if ends_the_input:
            return False
        line = typed.press(key)
        if line == QUIT:
            return False
        if line is not None:
            lines.put_nowait(line)
    return True


def _previous_word(text: str, cursor: int) -> int:
    return len(re.sub(r"\w*\W*\Z", "", text[:cursor], count=1))


def _next_word(text: str, cursor: int) -> int:
    return len(text) - len(re.sub(r"\A\W*\w*", "", text[cursor:], count=1))


def _width(character: str) -> int:
    """The columns a terminal gives a character: none for a combining mark, two for a
    wide one."""
    if unicodedata.category(character) in ("Mn", "Me", "Cf"):
        return 0
    return 2 if unicodedata.east_asian_width(character) in ("W", "F") else 1


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
