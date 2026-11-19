"""The caps of a queue and the token buckets of docs/protocol.md, section 12."""

import os
import sqlite3
from contextlib import closing
from dataclasses import replace

import pytest
from relay_harness import (
    Clock,
    OpenClient,
    RawClient,
    build_pq_upload,
    build_upload,
    make_public_key,
    messages_in,
    running_relay,
)

from sotto.crypto.identity import derive_identity_key
from sotto.proto.sotto_pb2 import (
    Ack,
    Bundle,
    ClientFrame,
    Deliver,
    Error,
    ErrorCode,
    FetchBundle,
    MessageRef,
    Send,
    ServerFrame,
    Stored,
    UploadBundle,
)
from sotto.relay.limits import TokenBuckets
from sotto.relay.settings import Settings

PAYLOAD_BYTES = 100
REFILL_SECONDS = 300


def one_time_prekey_ids_in(settings: Settings) -> list[int]:
    with closing(sqlite3.connect(settings.database)) as database:
        rows = database.execute(
            "SELECT prekey_id FROM one_time_prekeys ORDER BY position"
        ).fetchall()
    return [prekey_id for (prekey_id,) in rows]


def send_to(recipient: bytes) -> Send:
    return Send(
        message_id=os.urandom(16), recipient=recipient, payload=os.urandom(PAYLOAD_BYTES)
    )


def ack_of(deliver: Deliver) -> ClientFrame:
    pair = MessageRef(message_id=deliver.message_id, sender=deliver.sender)
    return ClientFrame(ack=Ack(messages=[pair]))


def refused(code: ErrorCode, frame: Send | UploadBundle | FetchBundle) -> ServerFrame:
    match frame:
        case Send():
            return ServerFrame(error=Error(code=code, message_id=frame.message_id))
        case FetchBundle():
            return ServerFrame(error=Error(code=code, identity=frame.identity))
        case UploadBundle():
            return ServerFrame(error=Error(code=code))


async def log_in(open_client: OpenClient, url: str, seed: bytes) -> RawClient:
    client = await open_client(url)
    answer = await client.log_in(seed)
    assert answer.WhichOneof("frame") == "logged_in"
    return client


async def register(
    open_client: OpenClient, url: str, seed: bytes, upload: UploadBundle | None = None
) -> RawClient:
    client = await log_in(open_client, url, seed)
    answer = await client.ask(build_upload(seed) if upload is None else upload)
    assert answer.WhichOneof("frame") == "bundle_stored"
    return client


async def fetch(client: RawClient, identity: bytes) -> Bundle:
    answer = await client.ask(FetchBundle(identity=identity))
    assert answer.WhichOneof("frame") == "bundle"
    return answer.bundle


@pytest.mark.parametrize("cap", ["messages", "bytes"])
async def test_send_over_a_queue_cap_answers_queue_full_until_an_ack_makes_room(
    settings: Settings, open_client: OpenClient, cap: str
) -> None:
    # Two messages of the test fill the queue under either cap.
    if cap == "messages":
        capped = replace(settings, queue_max_messages=2)
    else:
        capped = replace(settings, queue_max_bytes=PAYLOAD_BYTES * 5 // 2)
    recipient_seed = os.urandom(32)
    recipient_key = derive_identity_key(recipient_seed)
    first, second, third = (send_to(recipient_key) for _ in range(3))

    async with running_relay(capped) as url:
        recipient = await register(open_client, url, recipient_seed)
        sender = await log_in(open_client, url, os.urandom(32))
        answers = [await sender.ask(send) for send in (first, second, third)]
        ids_when_full = [row[2] for row in messages_in(capped)]
        first_delivery = (await recipient.receive()).deliver
        await recipient.receive()
        await recipient.send(ack_of(first_delivery))
        await fetch(recipient, recipient_key)
        answer_after_the_ack = await sender.ask(third)
        ids_after_the_ack = [row[2] for row in messages_in(capped)]

    assert answers == [
        ServerFrame(stored=Stored(message_id=first.message_id)),
        ServerFrame(stored=Stored(message_id=second.message_id)),
        refused(ErrorCode.QUEUE_FULL, third),
    ]
    assert ids_when_full == [first.message_id, second.message_id]
    assert answer_after_the_ack == ServerFrame(stored=Stored(message_id=third.message_id))
    assert ids_after_the_ack == [second.message_id, third.message_id]


async def test_frames_over_the_bucket_are_rate_limited_and_change_nothing(
    settings: Settings, open_client: OpenClient
) -> None:
    clock = Clock()
    limited = replace(settings, frame_bucket_size=1)
    owner_seed, sender_seed = os.urandom(32), os.urandom(32)
    owner_key = derive_identity_key(owner_seed)
    send = send_to(owner_key)
    upload = build_upload(sender_seed, [1])
    lookup = FetchBundle(identity=owner_key)

    async with running_relay(limited, monotonic=clock) as url:
        await register(open_client, url, owner_seed, build_upload(owner_seed, [1, 2]))
        sender = await log_in(open_client, url, sender_seed)
        first_fetch = await fetch(sender, owner_key)
        answers = [await sender.ask(frame) for frame in (send, upload, lookup)]
        rows = messages_in(limited)
        one_time_prekeys = one_time_prekey_ids_in(limited)
        clock.now += 1
        sender_key = derive_identity_key(sender_seed)
        sender_lookup = await sender.ask(FetchBundle(identity=sender_key))

    assert first_fetch.one_time_prekey.id == 1
    assert answers == [
        refused(ErrorCode.RATE_LIMITED, send),
        refused(ErrorCode.RATE_LIMITED, upload),
        refused(ErrorCode.RATE_LIMITED, lookup),
    ]
    assert rows == []
    assert one_time_prekeys == [2]
    assert sender_lookup.error.code == ErrorCode.NOT_FOUND


async def test_rate_limited_frame_passes_after_the_refill(
    settings: Settings, open_client: OpenClient
) -> None:
    clock = Clock()
    limited = replace(settings, frame_bucket_size=2, frame_refill_seconds=1)
    lookup = FetchBundle(identity=make_public_key())

    async with running_relay(limited, monotonic=clock) as url:
        client = await log_in(open_client, url, os.urandom(32))
        burst = [await client.ask(lookup) for _ in range(3)]
        clock.now += 1
        after_the_refill = [await client.ask(lookup) for _ in range(2)]

    not_found = refused(ErrorCode.NOT_FOUND, lookup)
    rate_limited = refused(ErrorCode.RATE_LIMITED, lookup)
    assert burst == [not_found, not_found, rate_limited]
    assert after_the_refill == [not_found, rate_limited]


async def test_login_and_ack_take_no_token_and_a_new_login_keeps_the_bucket(
    settings: Settings, open_client: OpenClient
) -> None:
    clock = Clock()
    limited = replace(settings, frame_bucket_size=1)
    recipient_seed = os.urandom(32)
    recipient_key = derive_identity_key(recipient_seed)
    send = send_to(recipient_key)
    lookup = FetchBundle(identity=recipient_key)

    async with running_relay(limited, monotonic=clock) as url:
        recipient = await register(open_client, url, recipient_seed)
        sender = await log_in(open_client, url, os.urandom(32))
        await sender.ask(send)
        await recipient.send(ack_of((await recipient.receive()).deliver))
        answer_after_the_ack = await recipient.ask(lookup)
        rows_after_the_ack = messages_in(limited)
        recipient_again = await log_in(open_client, url, recipient_seed)
        answer_after_the_new_login = await recipient_again.ask(lookup)
        clock.now += 1
        answer_after_the_refill = await recipient_again.ask(lookup)

    assert answer_after_the_ack == refused(ErrorCode.RATE_LIMITED, lookup)
    assert rows_after_the_ack == []
    assert answer_after_the_new_login == refused(ErrorCode.RATE_LIMITED, lookup)
    assert answer_after_the_refill.WhichOneof("frame") == "bundle"


def test_full_bucket_is_forgotten_and_is_the_same_as_a_new_one() -> None:
    clock = Clock()
    buckets = TokenBuckets(2, REFILL_SECONDS, clock)
    key = make_public_key()

    taken = [buckets.take(key) for _ in range(3)]
    clock.now += REFILL_SECONDS
    buckets.forget_full()
    is_kept_while_not_full = key in buckets.buckets
    clock.now += REFILL_SECONDS
    buckets.forget_full()
    is_forgotten_when_full = key not in buckets.buckets
    taken_again = [buckets.take(key) for _ in range(3)]

    assert taken == [True, True, False]
    assert is_kept_while_not_full
    assert is_forgotten_when_full
    assert taken_again == [True, True, False]


async def test_fetches_past_the_handout_bucket_leave_the_stored_one_time_prekeys(
    settings: Settings, open_client: OpenClient
) -> None:
    clock = Clock()
    limited = replace(settings, handout_bucket_size=2, handout_refill_seconds=REFILL_SECONDS)
    owner_seed = os.urandom(32)
    owner_key = derive_identity_key(owner_seed)

    async with running_relay(limited, monotonic=clock) as url:
        await register(open_client, url, owner_seed, build_upload(owner_seed, [1, 2, 3, 4]))
        fetchers = [await log_in(open_client, url, os.urandom(32)) for _ in range(3)]
        burst = [await fetch(fetcher, owner_key) for fetcher in fetchers]
        stored_after_the_burst = one_time_prekey_ids_in(limited)
        clock.now += REFILL_SECONDS
        after_the_refill = await fetch(fetchers[0], owner_key)

    assert [bundle.one_time_prekey.id for bundle in burst[:2]] == [1, 2]
    assert not burst[2].HasField("one_time_prekey")
    assert burst[2].signed_prekey == burst[0].signed_prekey
    assert stored_after_the_burst == [3, 4]
    assert after_the_refill.one_time_prekey.id == 3


async def test_fetch_of_a_target_without_one_time_prekeys_takes_no_handout_token(
    settings: Settings, open_client: OpenClient
) -> None:
    limited = replace(settings, handout_bucket_size=1)
    owner_seed = os.urandom(32)
    owner_key = derive_identity_key(owner_seed)
    first_upload = build_upload(owner_seed)
    later_upload = UploadBundle()
    later_upload.CopyFrom(first_upload)
    later_upload.one_time_prekeys.add(id=7, key=make_public_key())

    async with running_relay(limited) as url:
        owner = await register(open_client, url, owner_seed, first_upload)
        fetcher = await log_in(open_client, url, os.urandom(32))
        without_keys = [await fetch(fetcher, owner_key) for _ in range(2)]
        await owner.ask(later_upload)
        after_the_upload = await fetch(fetcher, owner_key)

    assert not any(bundle.HasField("one_time_prekey") for bundle in without_keys)
    assert after_the_upload.one_time_prekey.id == 7


async def test_one_handout_bucket_covers_both_kinds_of_one_time_prekey(
    settings: Settings, open_client: OpenClient
) -> None:
    limited = replace(settings, handout_bucket_size=1)
    owner_seed = os.urandom(32)
    owner_key = derive_identity_key(owner_seed)
    upload = build_pq_upload(owner_seed, 1, [2, 3])
    upload.one_time_prekeys.add(id=7, key=make_public_key())

    async with running_relay(limited) as url:
        await register(open_client, url, owner_seed, upload)
        fetcher = await log_in(open_client, url, os.urandom(32))
        with_a_token, without_a_token = [await fetch(fetcher, owner_key) for _ in range(2)]

    assert (with_a_token.one_time_prekey.id, with_a_token.pq_prekey.id) == (7, 2)
    assert not without_a_token.HasField("one_time_prekey")
    assert without_a_token.pq_prekey == upload.pq_prekey
