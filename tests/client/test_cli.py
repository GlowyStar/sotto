import asyncio
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from sotto.client.cli import DEFAULT_RELAY, RECEIVED_FILES, _print_event, main, printable
from sotto.client.envelope import MAX_AVATAR_BYTES
from sotto.client.session import FileState, Received
from sotto.client.store import Store
from sotto.client.transport import FileUpdate, Incoming, is_loopback, server_name_of
from sotto.crypto.identity import decode_user_id
from sotto.proto.sotto_pb2 import Attachment, Profile

PATIENCE_SECONDS = 10
SOTTO = Path(sys.executable).with_name("sotto")
JPEG = b"\xff\xd8\xff\xe0" + bytes(range(256)) * 40


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
    for command in ("init", "id", "add", "contacts", "chat", "reset", "send-file", "profile"):
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
    await bob_chat.expect("alice: hello bob")
    await bob_chat.type("hi alice")
    await alice_chat.expect("bob: hi alice")

    await alice_chat.quit()
    await bob_chat.type("are you there?")
    alice_chat = await open_chat(alice, "bob", url)
    await alice_chat.expect("bob: are you there?")

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
    await bob_chat.expect("alice: file photo.jpg, 150000 bytes: hi")
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
    await bob_chat.expect("alice: hello bob")
    await bob_chat.expect('alice: profile "Alice A.", with an avatar')
    await alice_chat.quit()
    await sotto(alice, "profile", "set", "--name", "Alice B.")
    alice_chat = await open_chat(alice, "bob", url)
    await bob_chat.expect('alice: profile "Alice B.", with an avatar')
    await bob_chat.type("nice")
    await alice_chat.expect("bob: nice")
    await alice_chat.quit()
    await bob_chat.quit()
    listed = await sotto(bob, "contacts")
    await sotto(bob, "profile", "show", "alice", "--avatar-to", str(written))

    assert listed == f'alice {alice_id} profile "Alice B.", avatar received'
    assert written.read_bytes() == JPEG
