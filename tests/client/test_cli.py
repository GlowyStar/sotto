import asyncio
import os
import pty
import re
import signal
import sys
import termios
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from sotto.client.cli import (
    CHAT_HINT,
    DEFAULT_RELAY,
    KEY,
    PROMPT,
    RECEIVED_FILES,
    CommandError,
    TypedLine,
    _print_event,
    _read_keys_in_the_loop,
    describe_timer,
    main,
    parse_timer,
    printable,
)
from sotto.client.envelope import MAX_AVATAR_BYTES
from sotto.client.session import FileState, Quoted, Received
from sotto.client.store import Store
from sotto.client.transport import (
    Event,
    Expired,
    FileUpdate,
    Incoming,
    Sent,
    Written,
    is_loopback,
    server_name_of,
)
from sotto.crypto.identity import decode_user_id
from sotto.crypto.safety_number import safety_number
from sotto.proto.sotto_pb2 import Attachment, Profile

PATIENCE_SECONDS = 10
SOTTO = Path(sys.executable).with_name("sotto")
JPEG = b"\xff\xd8\xff\xe0" + bytes(range(256)) * 40
ROW_OF_GROUPS = re.compile(r"[0-9]{5} [0-9]{5} [0-9]{5} [0-9]{5}")


def test_peer_text_is_printed_with_control_characters_escaped() -> None:
    text = "\x1b[2J\x1b]0;title\x07 \u202eevil\u2069\x9b\x00\x7f\nnext\u2028"

    assert printable(text) == (
        "\\x1b[2J\\x1b]0;title\\x07 \\u202eevil\\u2069\\x9b\\x00\\x7f\\x0anext\\u2028"
    )
    assert (
        printable("plain text, \u00e9t\u00e9 \U0001f600")
        == "plain text, \u00e9t\u00e9 \U0001f600"
    )


def test_peer_file_name_and_caption_are_printed_with_control_characters_escaped(
    capsys: pytest.CaptureFixture[str],
) -> None:
    sender = bytes(32)
    attachment = Attachment(size=5, file_name="\x1b[2Jcat\u202e.jpg", caption="\x07hi\n")
    received = Received(ack=True, text=None, result=None, attachment=attachment)
    update = FileUpdate(
        contact=sender,
        blob_id=bytes(16),
        file_name=attachment.file_name,
        state=FileState.NOT_RECEIVED,
        result="BAD_BLOB",
    )

    _print_event(Incoming(sender=sender, received=received), {sender: "alice"}, {})
    _print_event(update, {sender: "alice"}, {})

    assert capsys.readouterr().out.splitlines() == [
        "alice: file \\x1b[2Jcat\\u202e.jpg, 5 bytes: \\x07hi\\x0a",
        "could not be received: \\x1b[2Jcat\\u202e.jpg, alice (BAD_BLOB)",
    ]


def test_ws_url_off_loopback_is_refused_without_insecure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    alice, bob = tmp_path / "alice", tmp_path / "bob"
    assert main(["--data-dir", str(alice), "init"]) == 0
    assert main(["--data-dir", str(bob), "init"]) == 0
    bob_id = capsys.readouterr().out.split()[1]
    assert main(["--data-dir", str(alice), "add", "bob", bob_id]) == 0
    capsys.readouterr()

    chat = ["--data-dir", str(alice), "chat", "bob", "--relay", "ws://relay.example.org/ws"]
    assert main(chat) == 1

    assert "refused" in capsys.readouterr().err
    assert is_loopback(server_name_of(DEFAULT_RELAY, insecure=False))


def test_seed_is_neither_an_argument_nor_printed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    alice, bob = tmp_path / "alice", tmp_path / "bob"
    main(["--data-dir", str(alice), "init"])
    main(["--data-dir", str(bob), "init"])
    bob_id = capsys.readouterr().out.split()[1]
    main(["--data-dir", str(alice), "add", "bob", bob_id])
    main(["--data-dir", str(alice), "id"])
    main(["--data-dir", str(alice), "contacts"])
    commands = ("init", "id", "add", "contacts", "chat", "reset", "send-file", "profile")
    for command in (*commands, "verify"):
        with pytest.raises(SystemExit):
            main([command, "--help"])
    output = capsys.readouterr()

    store = Store(alice / "store.db")
    identity = store.identity()
    store.close()
    assert identity is not None
    printed = output.out + output.err
    assert identity.seed.hex() not in printed
    assert identity.identity_dh_private_key.hex() not in printed
    assert "seed" not in printed.lower()


@dataclass(frozen=True, slots=True)
class Terminal:
    """A `sotto chat` process driven through its standard input and output."""

    process: asyncio.subprocess.Process

    async def expect(self, line: str) -> None:
        assert self.process.stdout is not None
        async with asyncio.timeout(PATIENCE_SECONDS):
            while (printed := await self.process.stdout.readline()) != b"":
                if printed.decode().rstrip("\n") == line:
                    return
        raise AssertionError(f"the chat ended without printing {line!r}")

    async def type(self, line: str) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(f"{line}\n".encode())
        await self.process.stdin.drain()

    async def quit(self) -> None:
        await self.type("/quit")
        async with asyncio.timeout(PATIENCE_SECONDS):
            assert await self.process.wait() == 0


async def sotto(data_directory: Path, *arguments: str) -> str:
    process = await asyncio.create_subprocess_exec(
        SOTTO,
        "--data-dir",
        data_directory,
        *arguments,
        stdout=asyncio.subprocess.PIPE,
    )
    async with asyncio.timeout(PATIENCE_SECONDS):
        output, _ = await process.communicate()
    assert process.returncode == 0
    return output.decode().strip()


async def open_chat(data_directory: Path, name: str, url: str) -> Terminal:
    process = await asyncio.create_subprocess_exec(
        SOTTO,
        "--data-dir",
        data_directory,
        "chat",
        name,
        "--relay",
        url,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
    )
    terminal = Terminal(process)
    await terminal.expect("connected")
    return terminal


@pytest.mark.stand
async def test_two_processes_chat_through_the_relay(relay_url: str, tmp_path: Path) -> None:
    url = f"{relay_url}/ws"
    alice, bob = tmp_path / "alice", tmp_path / "bob"
    alice_id = await sotto(alice, "init")
    bob_id = await sotto(bob, "init")
    await sotto(alice, "add", "bob", bob_id)
    await sotto(bob, "add", "alice", alice_id)

    bob_chat = await open_chat(bob, "alice", url)
    alice_chat = await open_chat(alice, "bob", url)
    await alice_chat.type("hello bob")
    await bob_chat.expect("#1 alice: hello bob")
    await bob_chat.type("hi alice")
    await alice_chat.expect("#2 bob: hi alice")

    await alice_chat.quit()
    await bob_chat.type("are you there?")
    alice_chat = await open_chat(alice, "bob", url)
    await alice_chat.expect("#3 bob: are you there?")

    await alice_chat.quit()
    await bob_chat.quit()


@pytest.mark.stand
async def test_file_sent_by_one_process_is_saved_by_the_chat_of_the_other(
    relay_url: str, tmp_path: Path
) -> None:
    url = f"{relay_url}/ws"
    alice, bob = tmp_path / "alice", tmp_path / "bob"
    alice_id = await sotto(alice, "init")
    bob_id = await sotto(bob, "init")
    await sotto(alice, "add", "bob", bob_id)
    await sotto(bob, "add", "alice", alice_id)
    photo = tmp_path / "photo.jpg"
    photo.write_bytes(os.urandom(150_000))

    bob_chat = await open_chat(bob, "alice", url)
    sent = await sotto(
        alice, "send-file", "bob", str(photo), "--caption", "hi", "--relay", url
    )
    await bob_chat.expect("#1 alice: file photo.jpg, 150000 bytes: hi")
    saved = bob / RECEIVED_FILES / "photo.jpg"
    await bob_chat.expect(f"alice: photo.jpg saved as {saved}")
    await bob_chat.quit()

    assert sent.splitlines()[-1] == "sent photo.jpg to bob"
    assert saved.read_bytes() == photo.read_bytes()


def run(capsys: pytest.CaptureFixture[str], data_directory: Path, *arguments: str) -> str:
    """Runs a command that has to succeed and returns what it printed."""
    assert main(["--data-dir", str(data_directory), *arguments]) == 0
    return capsys.readouterr().out


def refused(capsys: pytest.CaptureFixture[str], data_directory: Path, *arguments: str) -> str:
    """Runs a command that has to fail and returns its message."""
    assert main(["--data-dir", str(data_directory), *arguments]) == 1
    return capsys.readouterr().err


def test_profile_set_show_and_clear(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    alice = tmp_path / "alice"
    picture, written = tmp_path / "me.jpg", tmp_path / "out.jpg"
    picture.write_bytes(JPEG)
    run(capsys, alice, "init")

    empty = run(capsys, alice, "profile", "show")
    set_both = run(
        capsys, alice, "profile", "set", "--name", "Alice A.", "--avatar", str(picture)
    )
    shown = run(capsys, alice, "profile", "show", "--avatar-to", str(written))
    renamed = run(capsys, alice, "profile", "set", "--name", "Alice B.")
    without_avatar = run(capsys, alice, "profile", "set", "--no-avatar")
    shown_again = run(capsys, alice, "profile", "show")
    cleared = run(capsys, alice, "profile", "clear")
    after_the_clear = run(capsys, alice, "profile", "show")
    nothing_to_set = refused(capsys, alice, "profile", "set")
    taken = refused(capsys, alice, "profile", "show", "--avatar-to", str(written))

    assert empty == "no profile\n"
    assert set_both.splitlines() == [
        'profile "Alice A.", with an avatar',
        "it goes to your contacts at the next chat",
    ]
    assert shown.splitlines() == ['name "Alice A."', f"avatar image/jpeg, {len(JPEG)} bytes"]
    assert written.read_bytes() == JPEG
    assert renamed.splitlines()[0] == 'profile "Alice B.", with an avatar'
    assert without_avatar.splitlines()[0] == 'profile "Alice B.", no avatar'
    assert shown_again.splitlines() == ['name "Alice B."', "no avatar"]
    assert cleared.splitlines()[0] == "profile cleared"
    assert after_the_clear == "no profile\n"
    assert "--name" in nothing_to_set
    assert "there is no avatar" in taken


def test_profile_set_refuses_an_avatar_too_large_or_not_an_image(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    alice = tmp_path / "alice"
    large, gif = tmp_path / "large.jpg", tmp_path / "cat.jpg"
    large.write_bytes(JPEG[:4] + bytes(MAX_AVATAR_BYTES))
    gif.write_bytes(b"GIF89a" + bytes(100))
    run(capsys, alice, "init")
    run(capsys, alice, "profile", "set", "--name", "Alice")

    too_large = refused(capsys, alice, "profile", "set", "--avatar", str(large))
    not_an_image = refused(capsys, alice, "profile", "set", "--avatar", str(gif))
    missing = refused(capsys, alice, "profile", "set", "--avatar", str(tmp_path / "none"))
    bad_name = refused(capsys, alice, "profile", "set", "--name", "Al\x1bice")
    long_name = refused(capsys, alice, "profile", "set", "--name", "x" * 257)
    shown = run(capsys, alice, "profile", "show")

    assert "AVATAR_TOO_LARGE" in too_large
    assert "NOT_AN_IMAGE" in not_an_image
    assert "cannot read" in missing
    assert "BAD_PROFILE_NAME" in bad_name
    assert "BAD_PROFILE_NAME" in long_name
    assert shown.splitlines() == ['name "Alice"', "no avatar"]


def received_profile(data_directory: Path, user_id: str, name: str) -> None:
    """Writes a profile into the store as if the contact of the id had sent it."""
    store = Store(data_directory / "store.db")
    with store.transaction():
        store.set_profile(decode_user_id(user_id), name, avatar_file=None)
    store.close()


def test_contacts_show_the_name_a_contact_sent_next_to_the_local_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    alice, bob, carol = tmp_path / "alice", tmp_path / "bob", tmp_path / "carol"
    alice_id = run(capsys, alice, "init").strip()
    carol_id = run(capsys, carol, "init").strip()
    run(capsys, bob, "init")
    run(capsys, bob, "add", "alice", alice_id)
    run(capsys, bob, "add", "carol", carol_id)
    received_profile(bob, alice_id, "Carol")

    listed = run(capsys, bob, "contacts")
    shown = run(capsys, bob, "profile", "show", "alice")
    not_sent = run(capsys, bob, "profile", "show", "carol")

    assert listed.splitlines() == [
        f'alice {alice_id} profile "Carol", no avatar',
        f"carol {carol_id}",
    ]
    assert shown.splitlines() == ['name "Carol"', "no avatar"]
    assert not_sent == "carol sent no profile\n"


def test_peer_profile_name_is_printed_with_control_characters_escaped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    alice, bob = tmp_path / "alice", tmp_path / "bob"
    alice_id = run(capsys, alice, "init").strip()
    run(capsys, bob, "init")
    run(capsys, bob, "add", "alice", alice_id)
    received_profile(bob, alice_id, "\x1b[2JAl\u202eice")
    sender = decode_user_id(alice_id)
    received = Received(
        ack=True, text=None, result=None, profile=Profile(name="\x1b[2JAl\u202eice")
    )

    _print_event(Incoming(sender=sender, received=received), {sender: "alice"}, {})
    printed = capsys.readouterr().out
    listed = run(capsys, bob, "contacts")

    assert printed == 'alice: profile "\\x1b[2JAl\\u202eice", no avatar\n'
    assert listed == f'alice {alice_id} profile "\\x1b[2JAl\\u202eice", no avatar\n'


def test_unknown_content_prints_nothing(capsys: pytest.CaptureFixture[str]) -> None:
    sender = bytes(32)
    unknown = Received(ack=True, text=None, result="UNKNOWN_CONTENT")
    broken = Received(ack=True, text=None, result="BAD_CONTENT")

    _print_event(Incoming(sender=sender, received=unknown), {sender: "alice"}, {})
    _print_event(Incoming(sender=sender, received=broken), {sender: "alice"}, {})

    assert capsys.readouterr().out == "alice: a message could not be read (BAD_CONTENT)\n"


@pytest.mark.stand
async def test_chat_prints_one_line_when_the_contact_profile_changes(
    relay_url: str, tmp_path: Path
) -> None:
    url = f"{relay_url}/ws"
    alice, bob = tmp_path / "alice", tmp_path / "bob"
    picture, written = tmp_path / "me.jpg", tmp_path / "alice.jpg"
    picture.write_bytes(JPEG)
    alice_id = await sotto(alice, "init")
    bob_id = await sotto(bob, "init")
    await sotto(alice, "add", "bob", bob_id)
    await sotto(bob, "add", "alice", alice_id)
    await sotto(alice, "profile", "set", "--name", "Alice A.", "--avatar", str(picture))

    bob_chat = await open_chat(bob, "alice", url)
    alice_chat = await open_chat(alice, "bob", url)
    await alice_chat.type("hello bob")
    await bob_chat.expect("#1 alice: hello bob")
    await bob_chat.expect('alice: profile "Alice A.", with an avatar')
    await alice_chat.quit()
    await sotto(alice, "profile", "set", "--name", "Alice B.")
    alice_chat = await open_chat(alice, "bob", url)
    await bob_chat.expect('alice: profile "Alice B.", with an avatar')
    await bob_chat.type("nice")
    await alice_chat.expect("#2 bob: nice")
    await alice_chat.quit()
    await bob_chat.quit()
    listed = await sotto(bob, "contacts")
    await sotto(bob, "profile", "show", "alice", "--avatar-to", str(written))

    assert listed == f'alice {alice_id} profile "Alice B.", avatar received'
    assert written.read_bytes() == JPEG


def test_chat_prints_numbers_marks_and_one_line_per_change(
    capsys: pytest.CaptureFixture[str],
) -> None:
    sender = bytes(32)
    names = {sender: "alice"}
    quote = Quoted(number=3, text="\x1b[2Jquoted")
    events: list[Event] = [
        Written(contact=sender, number=4, text="hi", reply_to=None, expires_after=0),
        Sent(number=4),
        Incoming(
            sender=sender,
            received=Received(ack=True, text=None, result=None, marked=(4,), read=False),
        ),
        Incoming(
            sender=sender,
            received=Received(ack=True, text=None, result=None, marked=(4, 5), read=True),
        ),
        Incoming(
            sender=sender,
            received=Received(
                ack=True,
                text="yes\u202e",
                result=None,
                number=6,
                quote=quote,
                expires_after=60,
            ),
        ),
        Incoming(
            sender=sender,
            received=Received(
                ack=True,
                text="ok",
                result=None,
                number=7,
                quote=Quoted(number=None, text=None),
            ),
        ),
        Incoming(
            sender=sender,
            received=Received(ack=True, text="\x07new", result=None, number=6, edited=True),
        ),
        Incoming(
            sender=sender,
            received=Received(ack=True, text=None, result=None, number=6, deleted=True),
        ),
        Incoming(
            sender=sender, received=Received(ack=True, text=None, result=None, timer=300)
        ),
        Incoming(sender=sender, received=Received(ack=True, text=None, result=None, timer=0)),
        Incoming(sender=sender, received=Received(ack=True, text=None, result=None)),
        Expired(numbers=(4, 6)),
    ]

    for event in events:
        _print_event(event, names, {})

    assert capsys.readouterr().out.splitlines() == [
        "#4 you: hi",
        "#4 sent",
        "#4 delivered",
        "#4 read",
        "#5 read",
        '#6 alice (1m), replying to #3 "\\x1b[2Jquoted": yes\\u202e',
        "#7 alice, replying to a message that is gone: ok",
        "#6 alice edited: \\x07new",
        "#6 alice deleted the message",
        "alice set the timer: 5m",
        "alice set the timer: off",
        "#4 disappeared",
        "#6 disappeared",
    ]


def test_timer_is_parsed_and_described() -> None:
    assert [parse_timer(text) for text in ("off", "30s", "5m", "1h", "1d", "4w")] == [
        0,
        30,
        300,
        3600,
        86400,
        2419200,
    ]
    assert [describe_timer(seconds) for seconds in (0, 30, 90, 3600, 7200, 604800)] == [
        "off",
        "30s",
        "90s",
        "1h",
        "2h",
        "1w",
    ]
    for text in ("", "1", "h", "1y", "-1h", "1.5h"):
        with pytest.raises(CommandError):
            parse_timer(text)


def test_read_receipts_are_shown_and_turned_off_and_on(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    alice = tmp_path / "alice"
    run(capsys, alice, "init")

    shown = run(capsys, alice, "read-receipts")
    off = run(capsys, alice, "read-receipts", "off")
    on = run(capsys, alice, "read-receipts", "on")

    assert (shown, off, on) == (
        "read receipts: on\n",
        "read receipts: off\n",
        "read receipts: on\n",
    )


def test_verify_shows_one_number_on_both_sides_then_marks_and_clears(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    alice, bob = tmp_path / "alice", tmp_path / "bob"
    alice_id = run(capsys, alice, "init").strip()
    bob_id = run(capsys, bob, "init").strip()
    run(capsys, alice, "add", "bob", bob_id)
    run(capsys, bob, "add", "alice", alice_id)

    at_alice = run(capsys, alice, "verify", "bob").splitlines()
    at_bob = run(capsys, bob, "verify", "alice").splitlines()
    marked = run(capsys, alice, "verify", "bob", "mark")
    listed = run(capsys, alice, "contacts")
    shown_marked = run(capsys, alice, "verify", "bob").splitlines()[-1]
    cleared = run(capsys, alice, "verify", "bob", "clear")
    listed_after_the_clear = run(capsys, alice, "contacts")
    unknown = refused(capsys, alice, "verify", "carol")

    number = safety_number(decode_user_id(alice_id), decode_user_id(bob_id))
    prefix, own_half, contact_half = at_alice[4].removeprefix("qr payload: ").split(" ")
    assert at_alice[0] == "safety number with bob:"
    assert all(ROW_OF_GROUPS.fullmatch(row) for row in at_alice[1:4])
    assert "".join(at_alice[1:4]).replace(" ", "") == number
    assert at_bob[1:4] == at_alice[1:4]
    assert at_bob[4] == f"qr payload: {prefix} {contact_half} {own_half}"
    assert (at_alice[5], at_bob[5]) == ("bob is not verified", "alice is not verified")
    assert marked == "bob is verified\n"
    assert listed == f"bob {bob_id} verified\n"
    assert shown_marked == "bob is verified"
    assert cleared == "bob is not verified\n"
    assert listed_after_the_clear == f"bob {bob_id}\n"
    assert "no contact is named carol" in unknown


def texts_in(data_directory: Path) -> list[str]:
    store = Store(data_directory / "store.db")
    rows = store.connection.execute("SELECT text FROM messages ORDER BY position").fetchall()
    store.close()
    return [text for (text,) in rows]


@pytest.mark.stand
async def test_two_processes_reply_edit_delete_see_the_marks_and_lose_a_timed_message(
    relay_url: str, tmp_path: Path
) -> None:
    url = f"{relay_url}/ws"
    alice, bob = tmp_path / "alice", tmp_path / "bob"
    alice_id = await sotto(alice, "init")
    bob_id = await sotto(bob, "init")
    await sotto(alice, "add", "bob", bob_id)
    await sotto(bob, "add", "alice", alice_id)
    await sotto(bob, "read-receipts", "off")

    bob_chat = await open_chat(bob, "alice", url)
    alice_chat = await open_chat(alice, "bob", url)
    await alice_chat.type("hello bob")
    await alice_chat.expect("#1 you: hello bob")
    await bob_chat.expect("#1 alice: hello bob")
    await alice_chat.expect("#1 sent")
    await alice_chat.expect("#1 delivered")
    await sotto(bob, "read-receipts", "on")

    await bob_chat.type("/reply 1 hi alice")
    await bob_chat.expect("#2 you, replying to #1: hi alice")
    await alice_chat.expect('#2 bob, replying to #1 "hello bob": hi alice')
    await bob_chat.expect("#2 read")
    await alice_chat.type("/edit 1 hello, bob")
    await alice_chat.expect("#1 you edited: hello, bob")
    await bob_chat.expect("#1 alice edited: hello, bob")
    await alice_chat.type("/delete 1")
    await alice_chat.expect("#1 deleted for both")
    await bob_chat.expect("#1 alice deleted the message")

    await bob_chat.type("/timer 2s")
    await bob_chat.expect("timer: 2s")
    await alice_chat.expect("bob set the timer: 2s")
    await alice_chat.type("vanishing")
    await alice_chat.expect("#3 you (2s): vanishing")
    await bob_chat.expect("#3 alice (2s): vanishing")
    await alice_chat.expect("#3 disappeared")
    await bob_chat.expect("#3 disappeared")
    await alice_chat.quit()
    await bob_chat.quit()

    assert texts_in(alice) == ["hi alice"]
    assert texts_in(bob) == ["hi alice"]


def typed(keys: str) -> TypedLine:
    line = TypedLine()
    for key in KEY.findall(keys):
        line.press(key)
    return line


def test_typed_line_is_edited_by_the_arrows_and_the_shortcuts() -> None:
    cases = {
        "wrld\x1b[D\x1b[D\x1b[Do\x01hello ": ("hello world", 6),
        "abc\x7f\x1b[D\x08": ("b", 0),
        "abc\x01\x1b[3~\x1b[F": ("bc", 2),
        "abc\x02\x02\x04\x06\x06": ("ac", 2),
        "one two  \x17": ("one ", 4),
        "one two\x1bb\x15": ("two", 0),
        "one, two\x1b[1;5D\x1b[1;3D\x1bf\x0b": ("one", 3),
        "one two\x1b[H\x1b[1;5C\x1b\x7f\x1bOF": (" two", 4),
        "a\x1b[1;7Bb\x1b[Ac\t\x1bOQ\x1b[200~d\x00\u202e": ("abcd", 4),
        "\x1bhi\x1b\x1bOA": ("hi", 2),
        "\u043f\u0440\u0438\u0432\u0435\u0442 \u4e16\u754c\x1b[D\x1b[DX": (
            "\u043f\u0440\u0438\u0432\u0435\u0442 X\u4e16\u754c",
            8,
        ),
    }

    for keys, (text, cursor) in cases.items():
        line = typed(keys)
        assert (line.text, line.cursor) == (text, cursor), repr(keys)
    line = typed("sent\x1b[D")
    assert (line.press("\r"), line.text, line.cursor) == ("sent", "", 0)
    assert line.press("x") is None


def test_typed_line_scrolls_sideways_instead_of_wrapping() -> None:
    short = typed("hi")
    long = typed("0123456789" * 3)
    wide = typed("\u4e16" * 12)

    assert short.drawn(80) == "\r> hi\x1b[K\r\x1b[4C"
    assert long.drawn(20) == "\r> 34567890123456789\x1b[K\r\x1b[19C"
    long.press("\x01")
    assert long.drawn(20) == "\r> 01234567890123456\x1b[K\r\x1b[2C"
    assert wide.drawn(20) == "\r> " + "\u4e16" * 8 + "\x1b[K\r\x1b[18C"


@dataclass
class PseudoTerminal:
    """A `sotto chat` process whose standard input and output are a pseudo-terminal."""

    process: asyncio.subprocess.Process
    master: int
    terminal: int
    output: bytearray = field(default_factory=bytearray)
    changed: asyncio.Event = field(default_factory=asyncio.Event)
    seen: int = 0

    def read(self) -> None:
        try:
            data = os.read(self.master, 4096)
        except OSError:
            data = b""
        if not data:
            asyncio.get_running_loop().remove_reader(self.master)
        self.output += data
        self.changed.set()

    async def expect(self, text: str) -> None:
        """Waits until the output after what an earlier call found holds `text`."""
        async with asyncio.timeout(PATIENCE_SECONDS):
            while (found := self.output.find(text.encode(), self.seen)) < 0:
                self.changed.clear()
                await self.changed.wait()
        self.seen = found + len(text)

    def press(self, keys: str) -> None:
        os.write(self.master, keys.encode())

    def close(self) -> None:
        asyncio.get_running_loop().remove_reader(self.master)
        os.close(self.master)
        os.close(self.terminal)


async def open_chat_at_a_terminal(data_directory: Path, name: str, url: str) -> PseudoTerminal:
    master, terminal = pty.openpty()
    process = await asyncio.create_subprocess_exec(
        SOTTO,
        "--data-dir",
        data_directory,
        "chat",
        name,
        "--relay",
        url,
        stdin=terminal,
        stdout=terminal,
    )
    chat = PseudoTerminal(process, master, terminal)
    asyncio.get_running_loop().add_reader(master, chat.read)
    return chat


@pytest.mark.stand
async def test_chat_at_a_terminal_prompts_and_keeps_the_typed_line_under_a_message(
    relay_url: str, tmp_path: Path
) -> None:
    url = f"{relay_url}/ws"
    alice, bob = tmp_path / "alice", tmp_path / "bob"
    alice_id = await sotto(alice, "init")
    bob_id = await sotto(bob, "init")
    await sotto(alice, "add", "bob", bob_id)
    await sotto(bob, "add", "alice", alice_id)

    bob_chat = await open_chat(bob, "alice", url)
    alice_chat = await open_chat_at_a_terminal(alice, "bob", url)
    try:
        await alice_chat.expect("connected\r\n")
        await alice_chat.expect(f"{CHAT_HINT}\r\n\r{PROMPT}")
        alice_chat.press("wrld\x1b[D\x1b[D\x1b[Do\x01hello \x1b[1;7B\x1b[A\r")
        await bob_chat.expect("#1 alice: hello world")
        await alice_chat.expect("#1 you: hello world")

        alice_chat.press("half \u0442\u0430\u0439\u043f")
        await alice_chat.expect(f"{PROMPT}half \u0442\u0430\u0439\u043f")
        await bob_chat.type("a message in between")
        await alice_chat.expect(
            f"#2 bob: a message in between\r\n\r{PROMPT}half \u0442\u0430\u0439\u043f"
        )
        alice_chat.press("\u0435\u0434 line\r")
        await bob_chat.expect("#3 alice: half \u0442\u0430\u0439\u043f\u0435\u0434 line")

        alice_chat.press("/quit\r")
        async with asyncio.timeout(PATIENCE_SECONDS):
            assert await alice_chat.process.wait() == 0
        modes = termios.tcgetattr(alice_chat.terminal)[3]
    finally:
        alice_chat.close()
    await bob_chat.quit()

    assert b"^[" not in alice_chat.output
    assert modes & termios.ICANON and modes & termios.ECHO


async def test_a_key_split_over_reads_is_one_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sotto.client.cli._columns", lambda: 80)
    lines: asyncio.Queue[str | None] = asyncio.Queue()
    reading, writing = os.pipe()
    loop = asyncio.get_running_loop()
    _read_keys_in_the_loop(reading, TypedLine(), lines, asyncio.Event())
    try:
        for chunk in (b"ab\x1b", b"[", b"D", b"X\n"):
            os.write(writing, chunk)
            await asyncio.sleep(0.01)
        async with asyncio.timeout(PATIENCE_SECONDS):
            assert await lines.get() == "aXb"
    finally:
        loop.remove_reader(reading)
        loop.remove_signal_handler(signal.SIGTERM)
        os.close(reading)
        os.close(writing)


@pytest.mark.stand
async def test_chat_at_a_terminal_gives_the_terminal_back_when_terminated(
    relay_url: str, tmp_path: Path
) -> None:
    alice, bob = tmp_path / "alice", tmp_path / "bob"
    await sotto(alice, "init")
    await sotto(alice, "add", "bob", await sotto(bob, "init"))

    chat = await open_chat_at_a_terminal(alice, "bob", f"{relay_url}/ws")
    try:
        await chat.expect(f"{CHAT_HINT}\r\n\r{PROMPT}")
        chat.press("half typed")
        await chat.expect(f"{PROMPT}half typed")
        chat.process.terminate()
        async with asyncio.timeout(PATIENCE_SECONDS):
            assert await chat.process.wait() == 0
        modes = termios.tcgetattr(chat.terminal)[3]
    finally:
        chat.close()

    assert modes & termios.ICANON and modes & termios.ECHO
