import asyncio
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from sotto.client.cli import DEFAULT_RELAY, RECEIVED_FILES, _print_event, main, printable
from sotto.client.session import FileState, Received
from sotto.client.store import Store
from sotto.client.transport import FileUpdate, Incoming, is_loopback, server_name_of
from sotto.proto.sotto_pb2 import Attachment

PATIENCE_SECONDS = 10
SOTTO = Path(sys.executable).with_name("sotto")


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
    for command in ("init", "id", "add", "contacts", "chat", "reset", "send-file"):
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
