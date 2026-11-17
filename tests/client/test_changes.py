"""Part 5 of docs/protocol.md between two clients: replies, edits, delete for both, receipts
and the disappearing timer, their order and the store that keeps them."""

import asyncio
from collections.abc import Iterator
from pathlib import Path

import pytest
from client_harness import Clients, Relay, befriend, edit_envelope, files_holding, send
from transport_harness import MakeClient, is_registered, next_event, running, until

from sotto.client import session
from sotto.client.envelope import (
    MAX_CAPTION_BYTES,
    TextTooLongError,
    encode_deletion,
    encode_edit,
    encode_receipt,
)
from sotto.client.session import (
    EDIT_SECONDS,
    MAX_EDITS,
    SEEN_ID_SECONDS,
    Client,
    Delivered,
    EditTooLateError,
    FileState,
    NoSuchMessageError,
    NotOwnMessageError,
    Outgoing,
    Quoted,
    Received,
    TooManyEditsError,
)
from sotto.client.store import Store
from sotto.client.transport import Expired, Incoming, Sent, Transport, Written
from sotto.crypto.blob import MAX_FILE_BYTES
from sotto.proto.sotto_pb2 import PeerMessage

HOUR = 3600
MARKER = "part five marker 7d21"


@pytest.fixture
def clients(tmp_path: Path) -> Iterator[Clients]:
    clients = Clients(tmp_path)
    yield clients
    clients.close()


@pytest.fixture
def relay() -> Relay:
    return Relay()


@pytest.fixture
def alice(clients: Clients, relay: Relay) -> Client:
    alice = clients.open("alice")
    relay.publish(alice)
    return alice


@pytest.fixture
def bob(clients: Clients, relay: Relay, alice: Client) -> Client:
    bob = clients.open("bob")
    relay.publish(bob)
    befriend(alice, bob)
    return bob


def number_of(item: Received | Outgoing) -> int:
    assert item.number is not None
    return item.number


def one(relay: Relay, client: Client) -> Received:
    (received,) = relay.deliver(client)
    return received


def say(relay: Relay, sender: Client, recipient: Client, text: str) -> tuple[int, int]:
    """Sends a text and delivers it; returns its number at the sender and the recipient."""
    bundle = None
    if not sender.has_session(recipient.identity_key):
        bundle = relay.fetch(recipient.identity_key)
    outgoing = sender.send_text(recipient.identity_key, text, bundle=bundle)
    relay.send(sender, outgoing)
    return number_of(outgoing), number_of(one(relay, recipient))


def forge(
    monkeypatch: pytest.MonkeyPatch,
    relay: Relay,
    sender: Client,
    recipient: Client,
    plaintext: bytes,
) -> Delivered:
    """Seals a plaintext of the sender's choice, as a client that breaks part 5 can, and
    hands it to the caller instead of the queue of the relay."""
    with monkeypatch.context() as patch:
        patch.setattr(session, "encode_text", lambda text, **_: plaintext)
        delivered = send(relay, sender, recipient, "forged")
    relay.queues[recipient.identity_key].remove(delivered)
    return delivered


def send_receipts(relay: Relay, sender: Client) -> int:
    sent = sender.send_owed_receipts()
    for outgoing in sent:
        relay.send(sender, outgoing)
    return len(sent)


def send_file(relay: Relay, sender: Client, recipient: Client, caption: str) -> int:
    """Sends an attachment as if its blob were complete; returns its number."""
    upload = sender.start_upload(
        recipient.identity_key,
        b"the bytes of a file",
        blob_max_bytes=MAX_FILE_BYTES,
        file_name="notes.txt",
        caption=caption,
    )
    outgoing = sender.send_attachment(upload)
    relay.send(sender, outgoing)
    return number_of(outgoing)


def texts(client: Client) -> list[tuple[str, str]]:
    rows = client.store.connection.execute(
        "SELECT direction, text FROM messages ORDER BY position"
    ).fetchall()
    return [(direction, text) for direction, text in rows]


def text_of(client: Client, number: int) -> str | None:
    message = client.store.message(number)
    return None if message is None else message.text


def test_reply_carries_a_quote_that_shows_without_the_original(
    relay: Relay, alice: Client, bob: Client
) -> None:
    question, at_bob = say(relay, alice, bob, "are you coming?")
    reply = bob.send_text(alice.identity_key, "yes", reply_to=at_bob)
    relay.send(bob, reply)
    answered = one(relay, alice)
    lost = bob.send_text(alice.identity_key, "the lost one")
    relay.send(bob, lost)
    relay.queues.clear()
    relay.send(bob, bob.send_text(alice.identity_key, "about it", reply_to=number_of(lost)))
    unseen = one(relay, alice)

    assert answered.text == "yes"
    assert answered.quote == Quoted(number=question, text="are you coming?")
    assert unseen.quote == Quoted(number=None, text="the lost one")
    kept = alice.store.connection.execute(
        "SELECT quote_direction, quote_text FROM message_states WHERE quote_id IS NOT NULL "
        "ORDER BY written_at, quote_text"
    ).fetchall()
    assert kept == [("out", "are you coming?"), ("in", "the lost one")]


def test_reply_to_a_message_of_another_chat_or_to_none_is_refused(
    clients: Clients, relay: Relay, alice: Client, bob: Client
) -> None:
    carol = clients.open("carol")
    relay.publish(carol)
    befriend(alice, carol)
    _, at_alice = say(relay, carol, alice, "from carol")
    say(relay, alice, bob, "hi")
    outbox = alice.outbox()

    for number in (at_alice, 999):
        with pytest.raises(NoSuchMessageError):
            alice.send_text(bob.identity_key, "answer", reply_to=number)
    assert alice.outbox() == outbox


def test_edit_replaces_the_text_at_both_sides_and_only_the_author_edits(
    relay: Relay, alice: Client, bob: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    at_alice, at_bob = say(relay, alice, bob, "see you at 7")
    _, bobs_own = say(relay, bob, alice, "ok")
    relay.send(alice, alice.edit(bob.identity_key, at_alice, "see you at 8"))
    edited = one(relay, bob)
    for number in (at_bob, bobs_own + 100):
        with pytest.raises((NotOwnMessageError, NoSuchMessageError)):
            bob.edit(alice.identity_key, number, "forged")
    alices_id = alice.store.message(at_alice)
    assert alices_id is not None
    forged = forge(monkeypatch, relay, bob, alice, encode_edit(alices_id.message_id, "x"))
    alice.receive(forged)

    assert (edited.number, edited.text, edited.edited) == (at_bob, "see you at 8", True)
    assert not edited.is_a_new_message
    assert text_of(alice, at_alice) == text_of(bob, at_bob) == "see you at 8"


def test_edits_stop_after_max_edits_and_edit_seconds(
    clients: Clients, relay: Relay, alice: Client, bob: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    at_alice, at_bob = say(relay, alice, bob, "draft")
    for count in range(MAX_EDITS):
        relay.send(alice, alice.edit(bob.identity_key, at_alice, f"draft {count}"))
    relay.deliver(bob)
    with pytest.raises(TooManyEditsError):
        alice.edit(bob.identity_key, at_alice, "one more")
    message = alice.store.message(at_alice)
    assert message is not None
    beyond = forge(monkeypatch, relay, alice, bob, encode_edit(message.message_id, "beyond"))
    ignored = bob.receive(beyond)
    later, _ = say(relay, alice, bob, "later")
    clients.clock.advance(EDIT_SECONDS + 1)

    with pytest.raises(EditTooLateError):
        alice.edit(bob.identity_key, later, "too late")
    assert ignored.number is None
    assert text_of(bob, at_bob) == f"draft {MAX_EDITS - 1}"


def test_edit_of_an_attachment_replaces_its_caption(
    relay: Relay, alice: Client, bob: Client
) -> None:
    say(relay, alice, bob, "a file follows")
    at_alice = send_file(relay, alice, bob, "the plan")
    offered = one(relay, bob)
    relay.send(alice, alice.edit(bob.identity_key, at_alice, "the new plan"))
    edited = one(relay, bob)
    with pytest.raises(TextTooLongError):
        alice.edit(bob.identity_key, at_alice, "x" * (MAX_CAPTION_BYTES + 1))

    assert offered.attachment is not None
    assert offered.attachment.caption == "the plan"
    assert (edited.number, edited.text) == (offered.number, "the new plan")
    (file,) = [row for row in bob.store.files() if row.incoming]
    assert file.attachment.caption == "the new plan"
    assert text_of(bob, number_of(offered)) == "the new plan"


def test_delete_for_both_removes_the_message_and_its_file_at_both_sides(
    tmp_path: Path, relay: Relay, alice: Client, bob: Client
) -> None:
    at_alice, at_bob = say(relay, alice, bob, MARKER)
    file_at_alice = send_file(relay, alice, bob, "a caption")
    offered = one(relay, bob)
    saved = tmp_path / "saved.txt"
    saved.write_bytes(b"the bytes of a file")
    (file,) = [row for row in bob.store.files() if row.incoming]
    with bob.store.transaction():
        bob.store.set_file_state(file.position, FileState.RECEIVED, saved_as=str(saved))
    second_file_at_alice = send_file(relay, alice, bob, "not downloaded")
    not_downloaded = one(relay, bob)

    for number in (at_alice, file_at_alice, second_file_at_alice):
        relay.send(alice, alice.delete(bob.identity_key, number))
    deleted = relay.deliver(bob)

    assert [(one.number, one.deleted) for one in deleted] == [
        (at_bob, True),
        (offered.number, True),
        (not_downloaded.number, True),
    ]
    assert texts(alice) == texts(bob) == []
    assert alice.store.files() == bob.store.files() == []
    assert not saved.exists()
    assert len(alice.blob_deletions()) == 2
    assert len(bob.blob_deletions()) == 1
    for name in ("alice", "bob"):
        assert files_holding(tmp_path / name, MARKER.encode()) == []


def test_number_of_a_message_that_is_gone_is_never_given_again(
    clients: Clients, relay: Relay, alice: Client, bob: Client
) -> None:
    say(relay, alice, bob, "a session")
    last_at_alice, last_at_bob = say(relay, alice, bob, "the last one")
    relay.send(alice, alice.delete(bob.identity_key, last_at_alice))
    relay.deliver(bob)
    next_at_alice, next_at_bob = say(relay, alice, bob, "after it")
    relay.send(alice, alice.delete(bob.identity_key, next_at_alice))
    relay.deliver(bob)

    bob_again = clients.open("bob")
    relay.send(alice, alice.send_text(bob.identity_key, "after a restart"))
    (after_restart,) = relay.deliver(bob_again)

    assert next_at_alice > last_at_alice
    assert next_at_bob > last_at_bob
    assert number_of(after_restart) > next_at_bob


def test_only_the_author_deletes(
    relay: Relay, alice: Client, bob: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    at_alice, at_bob = say(relay, alice, bob, "mine")
    message = alice.store.message(at_alice)
    assert message is not None

    with pytest.raises(NotOwnMessageError):
        bob.delete(alice.identity_key, at_bob)
    alice.receive(forge(monkeypatch, relay, bob, alice, encode_deletion(message.message_id)))

    assert text_of(alice, at_alice) == text_of(bob, at_bob) == "mine"


def test_quote_of_a_message_that_is_gone_keeps_no_text(
    relay: Relay, alice: Client, bob: Client
) -> None:
    at_alice, at_bob = say(relay, alice, bob, "regret")
    relay.send(bob, bob.send_text(alice.identity_key, "noted", reply_to=at_bob))
    relay.send(alice, alice.delete(bob.identity_key, at_alice))
    crossing = alice.send_text(bob.identity_key, "the second")
    relay.send(alice, crossing)
    second_at_bob = number_of(relay.deliver(bob)[-1])
    relay.send(bob, bob.send_text(alice.identity_key, "too late", reply_to=second_at_bob))
    relay.send(alice, alice.delete(bob.identity_key, number_of(crossing)))
    (reply, late) = relay.deliver(alice)
    relay.deliver(bob)

    assert reply.quote == Quoted(number=None, text=None)
    assert late.quote == Quoted(number=None, text=None)
    for client in (alice, bob):
        quotes = client.store.connection.execute(
            "SELECT quote_text FROM message_states WHERE quote_id IS NOT NULL"
        ).fetchall()
        assert quotes == [(None,), (None,)]


def test_delivery_receipt_marks_delivered_then_read_and_never_goes_back(
    relay: Relay, alice: Client, bob: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, first_at_bob = say(relay, alice, bob, "first")
    second, second_at_bob = say(relay, alice, bob, "second")
    first_id = alice.store.message(first)
    assert first_id is not None
    before_any_receipt = alice.sent_number(first_id.message_id)

    assert send_receipts(relay, bob) == 1
    delivered = one(relay, alice)
    bob.mark_read(alice.identity_key, [first_at_bob, second_at_bob])
    assert send_receipts(relay, bob) == 1
    read = one(relay, alice)
    late = forge(
        monkeypatch, relay, bob, alice, encode_receipt([first_id.message_id], read=False)
    )
    stale = alice.receive(late)

    assert before_any_receipt == first
    assert alice.sent_number(first_id.message_id) is None
    assert (delivered.marked, delivered.read) == ((first, second), False)
    assert (read.marked, read.read) == ((first, second), True)
    assert stale.marked == ()
    receipts = [alice.store.message(number) for number in (first, second)]
    assert [message.receipt if message else None for message in receipts] == ["read", "read"]
    assert send_receipts(relay, bob) == 0


def test_read_receipt_alone_counts_as_delivered(
    relay: Relay, alice: Client, bob: Client
) -> None:
    sent, at_bob = say(relay, alice, bob, "hi")
    bob.mark_read(alice.identity_key, [at_bob])
    send_receipts(relay, bob)
    read = one(relay, alice)

    assert (read.marked, read.read) == ((sent,), True)


def test_read_receipts_off_send_none_and_the_peer_sees_delivered(
    relay: Relay, alice: Client, bob: Client
) -> None:
    first, first_at_bob = say(relay, alice, bob, "first")
    bob.mark_read(alice.identity_key, [first_at_bob])
    bob.set_read_receipts(on=False)
    second, second_at_bob = say(relay, alice, bob, "second")
    bob.mark_read(alice.identity_key, [second_at_bob])
    send_receipts(relay, bob)
    received = relay.deliver(alice)

    assert not bob.read_receipts()
    assert [(one.marked, one.read) for one in received] == [((first, second), False)]


def test_receipts_go_one_message_per_contact_and_kind_and_are_bounded(
    relay: Relay, alice: Client, bob: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session, "MAX_RECEIPT_IDS", 2)
    numbers = [say(relay, alice, bob, f"text {count}")[0] for count in range(3)]

    assert send_receipts(relay, bob) == 2
    received = relay.deliver(alice)
    assert [one.marked for one in received] == [tuple(numbers[:2]), (numbers[2],)]


def test_changes_are_no_message_and_get_no_receipt(
    relay: Relay, alice: Client, bob: Client
) -> None:
    at_alice, _ = say(relay, alice, bob, "hello")
    send_receipts(relay, bob)
    relay.send(alice, alice.edit(bob.identity_key, at_alice, "hello!"))
    relay.send(alice, alice.set_timer(bob.identity_key, HOUR))
    relay.send(alice, alice.delete(bob.identity_key, at_alice))
    changes = relay.deliver(bob)
    receipt = one(relay, alice)

    assert [change.is_a_new_message for change in [*changes, receipt]] == [False] * 4
    assert texts(alice) == texts(bob) == []
    assert send_receipts(relay, bob) == send_receipts(relay, alice) == 0


def test_receipt_that_does_not_decrypt_marks_nothing(
    relay: Relay, alice: Client, bob: Client
) -> None:
    sent, _ = say(relay, alice, bob, "hi")
    (outgoing,) = bob.send_owed_receipts()
    receipt = relay.send(bob, outgoing)
    relay.queues.clear()

    def flip(envelope: PeerMessage) -> None:
        envelope.ciphertext = envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 1])

    forged = alice.receive(edit_envelope(receipt, flip))
    genuine = alice.receive(receipt)

    assert (forged.result, forged.marked) == ("DECRYPT_FAILED", ())
    assert genuine.marked == (sent,)


def test_timer_applies_to_messages_sent_after_the_change(
    relay: Relay, alice: Client, bob: Client
) -> None:
    before, _ = say(relay, alice, bob, "before")
    relay.send(alice, alice.set_timer(bob.identity_key, HOUR))
    crossing = bob.send_text(alice.identity_key, "crossing")
    set_at_bob = one(relay, bob)
    after = alice.send_text(bob.identity_key, "after")
    relay.send(alice, after)
    after_at_bob = one(relay, bob)
    relay.send(bob, crossing)
    relay.send(bob, bob.send_text(alice.identity_key, "answer"))
    crossing_at_alice, answer_at_alice = relay.deliver(alice)

    assert set_at_bob.timer == HOUR
    assert alice.timer(bob.identity_key) == bob.timer(alice.identity_key) == HOUR
    assert after_at_bob.expires_after == HOUR
    assert (crossing_at_alice.expires_after, answer_at_alice.expires_after) == (0, HOUR)
    expiry = alice.store.message(before)
    assert expiry is not None
    assert expiry.expires_at is None


def test_timer_counts_from_reading_at_the_receiver_and_from_sending_at_the_sender(
    clients: Clients, relay: Relay, alice: Client, bob: Client
) -> None:
    say(relay, alice, bob, "a session")
    relay.send(alice, alice.set_timer(bob.identity_key, 60))
    relay.deliver(bob)
    at_alice, at_bob = say(relay, alice, bob, "soon gone")
    unread_at_alice, unread_at_bob = say(relay, alice, bob, "never read")
    clients.clock.advance(30)
    bob.mark_read(alice.identity_key, [at_bob])
    clients.clock.advance(31)

    assert alice.expire_messages() == [at_alice, unread_at_alice]
    assert bob.expire_messages() == []
    clients.clock.advance(30)
    assert bob.expire_messages() == [at_bob]
    clients.clock.advance(10 * HOUR)
    assert bob.expire_messages() == []
    assert text_of(bob, unread_at_bob) == "never read"


def test_expired_message_goes_after_a_restart_and_is_in_no_file_of_the_store(
    tmp_path: Path, clients: Clients, relay: Relay, alice: Client, bob: Client
) -> None:
    say(relay, alice, bob, "a session")
    relay.send(alice, alice.set_timer(bob.identity_key, HOUR))
    relay.deliver(bob)
    at_alice, at_bob = say(relay, alice, bob, MARKER)
    relay.send(bob, bob.send_text(alice.identity_key, "quoting", reply_to=at_bob))
    relay.deliver(alice)
    bob.mark_read(alice.identity_key, [at_bob])
    clients.clock.advance(HOUR)

    alice_again, bob_again = clients.open("alice"), clients.open("bob")

    assert alice_again.store.message(at_alice) is None
    assert bob_again.store.message(at_bob) is None
    for name in ("alice", "bob"):
        assert files_holding(tmp_path / name, MARKER.encode()) == []


def test_expired_attachment_takes_its_file_and_its_blob(
    tmp_path: Path, clients: Clients, relay: Relay, alice: Client, bob: Client
) -> None:
    say(relay, alice, bob, "files follow")
    relay.send(alice, alice.set_timer(bob.identity_key, 60))
    relay.deliver(bob)
    send_file(relay, alice, bob, "kept on disk")
    on_disk = one(relay, bob)
    send_file(relay, alice, bob, "never fetched")
    offered = one(relay, bob)
    saved = tmp_path / "kept.txt"
    saved.write_bytes(b"the bytes of a file")
    first, second = [row for row in bob.store.files() if row.incoming]
    with bob.store.transaction():
        bob.store.set_file_state(first.position, FileState.RECEIVED, saved_as=str(saved))
    bob.mark_read(alice.identity_key, [number_of(on_disk), number_of(offered)])
    clients.clock.advance(60)

    assert bob.expire_messages() == [number_of(on_disk), number_of(offered)]
    assert alice.expire_messages() != []
    assert bob.store.files() == alice.store.files() == []
    assert not saved.exists()
    assert bob.blob_deletions() == [(alice.identity_key, second.attachment.blob_id)]
    assert alice.blob_deletions() == []


def test_edit_and_deletion_before_their_message_are_applied_when_it_arrives(
    relay: Relay, alice: Client, bob: Client
) -> None:
    say(relay, alice, bob, "a session")
    first = alice.send_text(bob.identity_key, "first")
    edit = alice.edit(bob.identity_key, number_of(first), "first, edited")
    second = alice.send_text(bob.identity_key, MARKER)
    deletion = alice.delete(bob.identity_key, number_of(second))
    for outgoing in (edit, deletion, first, second):
        relay.send(alice, outgoing)
    early_edit, early_deletion, arrived, never_shown = relay.deliver(bob)

    assert (early_edit.number, early_deletion.number) == (None, None)
    assert (arrived.text, arrived.is_a_new_message) == ("first, edited", True)
    assert (never_shown.text, never_shown.number) == (None, None)
    assert texts(bob) == [("in", "a session"), ("in", "first, edited")]


def test_changes_name_messages_across_a_session_reset(
    relay: Relay, alice: Client, bob: Client
) -> None:
    at_alice, at_bob = say(relay, alice, bob, "on the first session")
    bob.start_session(alice.identity_key, relay.fetch(alice.identity_key))
    say(relay, bob, alice, "on a new session")
    relay.send(alice, alice.edit(bob.identity_key, at_alice, "edited on the new one"))
    edited = one(relay, bob)

    assert len(bob.store.sessions(alice.identity_key)) == 2
    assert (edited.number, edited.text) == (at_bob, "edited on the new one")


def test_change_for_a_message_that_is_gone_is_dropped(
    relay: Relay, alice: Client, bob: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    at_alice, at_bob = say(relay, alice, bob, "short-lived")
    message = alice.store.message(at_alice)
    assert message is not None
    relay.send(alice, alice.delete(bob.identity_key, at_alice))
    send_receipts(relay, bob)
    receipt = one(relay, alice)
    relay.deliver(bob)
    late_edit = forge(monkeypatch, relay, alice, bob, encode_edit(message.message_id, "x"))

    edited = bob.receive(late_edit)

    assert receipt.marked == ()
    assert edited.number is None
    assert bob.store.message(at_bob) is None


def test_traces_are_forgotten_with_the_seen_ids(
    clients: Clients, relay: Relay, alice: Client, bob: Client
) -> None:
    say(relay, alice, bob, "a session")
    never = alice.send_text(bob.identity_key, "never arrives")
    relay.send(alice, alice.delete(bob.identity_key, number_of(never)))
    relay.deliver(bob)
    traces = "SELECT count(*) FROM message_states WHERE gone = 1"
    assert bob.store.connection.execute(traces).fetchone() == (1,)

    clients.clock.advance(SEEN_ID_SECONDS)
    bob.forget_seen_ids()

    assert bob.store.connection.execute(traces).fetchone() == (0,)


def test_store_of_the_previous_version_opens_and_takes_part_5(
    clients: Clients, relay: Relay, alice: Client, bob: Client
) -> None:
    at_alice, at_bob = say(relay, alice, bob, "from before")
    say(relay, bob, alice, "also from before")
    path = bob.store.connection.execute("PRAGMA database_list").fetchone()[2]
    with bob.store.transaction():
        for table in ("message_states", "timers", "settings"):
            bob.store.connection.execute(f"DROP TABLE {table}")
        bob.store.connection.execute("DROP INDEX messages_by_id")
    bob.store.close()

    reopened = Client(Store(Path(path)), clock=clients.clock)
    clients.stores.append(reopened.store)
    relay.send(alice, alice.delete(bob.identity_key, at_alice))
    send_receipts(relay, alice)
    deleted, receipt = [reopened.receive(one) for one in relay.queues.pop(bob.identity_key)]

    assert receipt.marked == ()
    assert reopened.read_receipts()
    assert reopened.timer(alice.identity_key) == 0
    assert (deleted.number, deleted.deleted) == (at_bob, True)
    assert texts(reopened) == [("out", "also from before")]


async def next_incoming(link: Transport, wanted: str) -> Received:
    """The next Incoming whose Received has the attribute `wanted` set."""
    while True:
        received = (await next_event(link, Incoming)).received
        if getattr(received, wanted):
            return received


async def test_two_network_clients_see_sent_delivered_read_and_a_message_disappear(
    relay_url: str, make_client: MakeClient
) -> None:
    alice, bob = make_client("alice"), make_client("bob")
    befriend(alice, bob)
    url = f"{relay_url}/ws"

    async with running(bob, url) as bob_link, running(alice, url) as alice_link:
        await until(is_registered(bob))
        bob.set_read_receipts(on=False)
        await alice_link.send_text(bob.identity_key, "hello")
        written = await next_event(alice_link, Written)
        sent = await next_event(alice_link, Sent)
        shown = await next_incoming(bob_link, "is_a_new_message")
        bob_link.mark_read(alice.identity_key, number_of(shown))
        delivered = await next_incoming(alice_link, "marked")
        bob.set_read_receipts(on=True)
        await alice_link.send_text(bob.identity_key, "again")
        again = await next_incoming(bob_link, "is_a_new_message")
        bob_link.mark_read(alice.identity_key, number_of(again))
        read = await next_incoming(alice_link, "read")

        await bob_link.set_timer(alice.identity_key, 1)
        timer = await next_incoming(alice_link, "timer")
        await alice_link.send_text(bob.identity_key, "vanishing")
        own_copy = await next_event(alice_link, Written)
        vanishing = await next_incoming(bob_link, "is_a_new_message")
        bob_link.mark_read(alice.identity_key, number_of(vanishing))
        gone_at_alice = await next_event(alice_link, Expired)
        gone_at_bob = await next_event(bob_link, Expired)

    assert (written.text, sent.number) == ("hello", written.number)
    assert (delivered.marked, delivered.read) == ((written.number,), False)
    assert read.read and len(read.marked) == 1
    assert (timer.timer, vanishing.expires_after) == (1, 1)
    assert (own_copy.expires_after, gone_at_alice.numbers) == (1, (own_copy.number,))
    assert gone_at_bob.numbers == (number_of(vanishing),)
    assert alice.store.message(own_copy.number) is None


async def test_failed_expiry_ends_the_run_of_the_transport(
    relay_url: str, make_client: MakeClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    alice = make_client("alice")

    def fail() -> list[int]:
        raise RuntimeError("database is locked")

    monkeypatch.setattr(alice, "expire_messages", fail)
    transport = Transport(alice, f"{relay_url}/ws")

    with pytest.raises(ExceptionGroup) as failure:
        async with asyncio.timeout(10):
            await transport.run()

    assert failure.group_contains(RuntimeError)
