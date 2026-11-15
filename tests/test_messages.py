import asyncio
import os
import secrets
import socket
from collections.abc import Callable
from urllib.parse import urlsplit

import pytest
from relay_harness import OpenClient, RawClient, Wire, build_upload, make_public_key
from websockets.asyncio.client import connect

from sotto.crypto.identity import derive_identity_key
from sotto.proto.sotto_pb2 import (
    Ack,
    ClientFrame,
    Deliver,
    Error,
    ErrorCode,
    FetchBundle,
    MessageRef,
    Send,
    ServerFrame,
    Stored,
)
from sotto.relay.frames import MAX_FRAME_BYTES, MAX_PAYLOAD_BYTES
from sotto.relay.server import CloseCode

# The point of order 1, a key that section 3.3 excludes from a login.
SMALL_ORDER_KEY = bytes.fromhex("01" + "00" * 31)
SMALL_RECEIVE_BUFFER = 4096
# About 5 MiB, far above the buffers of the two sockets and the write limit of the relay.
STUCK_SENDS = 80


def random_payload() -> bytes:
    return os.urandom(1 + secrets.randbelow(1024))


def send_to(recipient: bytes, payload: bytes | None = None) -> Send:
    payload = random_payload() if payload is None else payload
    return Send(message_id=os.urandom(16), recipient=recipient, payload=payload)


def stored(send: Send) -> ServerFrame:
    return ServerFrame(stored=Stored(message_id=send.message_id))


def delivered(sender: bytes, send: Send) -> ServerFrame:
    deliver = Deliver(message_id=send.message_id, sender=sender, payload=send.payload)
    return ServerFrame(deliver=deliver)


def ack(*frames: ServerFrame) -> ClientFrame:
    pairs = [
        MessageRef(message_id=frame.deliver.message_id, sender=frame.deliver.sender)
        for frame in frames
    ]
    return ClientFrame(ack=Ack(messages=pairs))


async def log_in(open_client: OpenClient, url: str, seed: bytes) -> RawClient:
    client = await open_client(url)
    answer = await client.log_in(seed)
    assert answer.WhichOneof("frame") == "logged_in"
    return client


async def register(open_client: OpenClient, url: str, seed: bytes) -> RawClient:
    """Logs an identity in and uploads its bundle, so that messages can be sent to it."""
    client = await log_in(open_client, url, seed)
    answer = await client.ask(build_upload(seed))
    assert answer.WhichOneof("frame") == "bundle_stored"
    return client


async def round_trip(client: RawClient) -> ServerFrame:
    """Returns the answer to a FetchBundle: every frame sent before it is handled by then."""
    return await client.ask(FetchBundle(identity=make_public_key()))


def not_found(answer: ServerFrame) -> bool:
    return answer.error.code == ErrorCode.NOT_FOUND


@pytest.mark.stand
async def test_message_to_an_online_recipient_is_delivered_byte_for_byte(
    relay_url: str, open_client: OpenClient
) -> None:
    sender_seed, recipient_seed = os.urandom(32), os.urandom(32)
    recipient = await register(open_client, relay_url, recipient_seed)
    sender = await log_in(open_client, relay_url, sender_seed)
    bystander = await log_in(open_client, relay_url, os.urandom(32))
    send = send_to(derive_identity_key(recipient_seed))

    answer = await sender.ask(send)
    delivery = await recipient.receive()
    # A Deliver to the bystander would have gone out before this answer.
    bystander_next = await round_trip(bystander)

    assert answer == stored(send)
    assert delivery == delivered(derive_identity_key(sender_seed), send)
    assert not_found(bystander_next)


@pytest.mark.stand
async def test_message_to_an_offline_recipient_is_delivered_after_its_login(
    relay_url: str, open_client: OpenClient
) -> None:
    sender_seed, recipient_seed = os.urandom(32), os.urandom(32)
    await (await register(open_client, relay_url, recipient_seed)).websocket.close()
    sender = await log_in(open_client, relay_url, sender_seed)
    send = send_to(derive_identity_key(recipient_seed))

    answer = await sender.ask(send)
    recipient = await open_client(relay_url)
    logged_in = await recipient.log_in(recipient_seed)
    delivery = await recipient.receive()

    assert answer == stored(send)
    assert logged_in.WhichOneof("frame") == "logged_in"
    assert delivery == delivered(derive_identity_key(sender_seed), send)


@pytest.mark.stand
async def test_unacked_message_is_delivered_again_after_the_next_login(
    relay_url: str, open_client: OpenClient
) -> None:
    sender_seed, recipient_seed = os.urandom(32), os.urandom(32)
    recipient_key = derive_identity_key(recipient_seed)
    first_connection = await register(open_client, relay_url, recipient_seed)
    sender = await log_in(open_client, relay_url, sender_seed)
    send, later_send = send_to(recipient_key), send_to(recipient_key)

    await sender.ask(send)
    first_delivery = await first_connection.receive()
    await first_connection.websocket.close()
    second_connection = await log_in(open_client, relay_url, recipient_seed)
    second_delivery = await second_connection.receive()
    # The pair is the whole key: the Deliver of the first connection is acked here.
    await second_connection.send(ack(first_delivery))
    await round_trip(second_connection)
    await second_connection.websocket.close()
    third_connection = await log_in(open_client, relay_url, recipient_seed)
    await sender.ask(later_send)
    third_delivery = await third_connection.receive()

    sender_key = derive_identity_key(sender_seed)
    assert first_delivery == second_delivery == delivered(sender_key, send)
    assert third_delivery == delivered(sender_key, later_send)


@pytest.mark.stand
async def test_ack_deletes_the_message_and_is_safe_to_repeat(
    relay_url: str, open_client: OpenClient
) -> None:
    sender_seed, recipient_seed = os.urandom(32), os.urandom(32)
    recipient_key = derive_identity_key(recipient_seed)
    recipient = await register(open_client, relay_url, recipient_seed)
    sender = await log_in(open_client, relay_url, sender_seed)
    send, later_send = send_to(recipient_key), send_to(recipient_key)

    await sender.ask(send)
    delivery = await recipient.receive()
    await recipient.send(ack(delivery))
    await recipient.send(ack(delivery))
    # The Acks get no answer: the next frame answers the request after them.
    next_frame = await round_trip(recipient)
    await recipient.websocket.close()
    recipient_again = await log_in(open_client, relay_url, recipient_seed)
    await sender.ask(later_send)
    next_delivery = await recipient_again.receive()

    assert not_found(next_frame)
    assert next_delivery == delivered(derive_identity_key(sender_seed), later_send)


@pytest.mark.stand
async def test_repeated_send_is_stored_once_and_delivered_once(
    relay_url: str, open_client: OpenClient
) -> None:
    sender_seed, recipient_seed, other_seed = os.urandom(32), os.urandom(32), os.urandom(32)
    recipient_key = derive_identity_key(recipient_seed)
    other_key = derive_identity_key(other_seed)
    recipient = await register(open_client, relay_url, recipient_seed)
    other = await register(open_client, relay_url, other_seed)
    sender = await log_in(open_client, relay_url, sender_seed)
    send = send_to(recipient_key)
    repeat_elsewhere = Send(message_id=send.message_id, recipient=other_key, payload=b"other")
    later_send, send_to_other = send_to(recipient_key), send_to(other_key)

    answers = [await sender.ask(send), await sender.ask(send)]
    answers.append(await sender.ask(repeat_elsewhere))
    await sender.ask(later_send)
    await sender.ask(send_to_other)
    deliveries = [await recipient.receive(), await recipient.receive()]
    delivery_to_other = await other.receive()

    sender_key = derive_identity_key(sender_seed)
    assert answers == [stored(send)] * 3
    assert deliveries == [delivered(sender_key, send), delivered(sender_key, later_send)]
    assert delivery_to_other == delivered(sender_key, send_to_other)


@pytest.mark.stand
async def test_send_repeated_after_the_ack_is_a_new_message(
    relay_url: str, open_client: OpenClient
) -> None:
    sender_seed, recipient_seed, other_seed = os.urandom(32), os.urandom(32), os.urandom(32)
    recipient = await register(open_client, relay_url, recipient_seed)
    other = await register(open_client, relay_url, other_seed)
    sender = await log_in(open_client, relay_url, sender_seed)
    send = send_to(derive_identity_key(recipient_seed))
    to_nobody = Send(message_id=send.message_id, recipient=make_public_key(), payload=b"x")
    to_other = Send(
        message_id=send.message_id, recipient=derive_identity_key(other_seed), payload=b"y"
    )

    await sender.ask(send)
    await recipient.send(ack(await recipient.receive()))
    await round_trip(recipient)
    repeat = await sender.ask(send)
    redelivery = await recipient.receive()
    await recipient.send(ack(redelivery))
    await round_trip(recipient)
    refused = await sender.ask(to_nobody)
    accepted = await sender.ask(to_other)
    delivery_to_other = await other.receive()

    sender_key = derive_identity_key(sender_seed)
    assert repeat == stored(send)
    assert redelivery == delivered(sender_key, send)
    assert refused == ServerFrame(
        error=Error(code=ErrorCode.UNKNOWN_RECIPIENT, message_id=send.message_id)
    )
    assert accepted == stored(to_other)
    assert delivery_to_other == delivered(sender_key, to_other)


@pytest.mark.stand
async def test_ack_of_a_message_queued_for_another_identity_deletes_nothing(
    relay_url: str, open_client: OpenClient
) -> None:
    sender_seed, owner_seed = os.urandom(32), os.urandom(32)
    await (await register(open_client, relay_url, owner_seed)).websocket.close()
    sender = await log_in(open_client, relay_url, sender_seed)
    someone = await log_in(open_client, relay_url, os.urandom(32))
    send = send_to(derive_identity_key(owner_seed))
    foreign = delivered(derive_identity_key(sender_seed), send)

    await sender.ask(send)
    await someone.send(ack(foreign))
    # No answer and no Error: the next frame answers the request after the Ack.
    next_frame = await round_trip(someone)
    owner = await log_in(open_client, relay_url, owner_seed)
    delivery = await owner.receive()

    assert not_found(next_frame)
    assert delivery == foreign


@pytest.mark.stand
@pytest.mark.parametrize("recipient", [make_public_key(), SMALL_ORDER_KEY])
async def test_send_to_an_identity_that_is_not_registered_answers_unknown_recipient(
    relay_url: str, open_client: OpenClient, recipient: bytes
) -> None:
    sender = await log_in(open_client, relay_url, os.urandom(32))
    send = send_to(recipient)

    answer = await sender.ask(send)
    next_frame = await round_trip(sender)

    # `message_id` set and `identity` empty name a refused Send (section 7.16).
    assert answer == ServerFrame(
        error=Error(code=ErrorCode.UNKNOWN_RECIPIENT, message_id=send.message_id)
    )
    assert not_found(next_frame)


@pytest.mark.stand
async def test_queue_is_delivered_in_the_order_the_messages_were_stored(
    relay_url: str, open_client: OpenClient
) -> None:
    first_seed, second_seed, recipient_seed = os.urandom(32), os.urandom(32), os.urandom(32)
    recipient_key = derive_identity_key(recipient_seed)
    await (await register(open_client, relay_url, recipient_seed)).websocket.close()
    first_sender = await log_in(open_client, relay_url, first_seed)
    second_sender = await log_in(open_client, relay_url, second_seed)
    sends = [send_to(recipient_key) for _ in range(4)]

    await first_sender.ask(sends[0])
    await second_sender.ask(sends[1])
    await first_sender.ask(sends[2])
    recipient = await open_client(relay_url)
    logged_in = await recipient.log_in(recipient_seed)
    queued = [await recipient.receive() for _ in range(3)]
    await second_sender.ask(sends[3])
    while_logged_in = await recipient.receive()

    first_key, second_key = derive_identity_key(first_seed), derive_identity_key(second_seed)
    assert logged_in.WhichOneof("frame") == "logged_in"
    assert [*queued, while_logged_in] == [
        delivered(first_key, sends[0]),
        delivered(second_key, sends[1]),
        delivered(first_key, sends[2]),
        delivered(second_key, sends[3]),
    ]


@pytest.mark.stand
async def test_message_is_sent_once_per_connection(
    relay_url: str, open_client: OpenClient
) -> None:
    sender_seed, recipient_seed = os.urandom(32), os.urandom(32)
    recipient_key = derive_identity_key(recipient_seed)
    recipient = await register(open_client, relay_url, recipient_seed)
    sender = await log_in(open_client, relay_url, sender_seed)
    first, second = send_to(recipient_key), send_to(recipient_key)

    await sender.ask(first)
    first_delivery = await recipient.receive()
    # The first message is not acked, and the second one goes out all the same.
    await sender.ask(second)
    frames = [await recipient.receive(), await round_trip(recipient)]

    sender_key = derive_identity_key(sender_seed)
    assert first_delivery == delivered(sender_key, first)
    assert frames[0] == delivered(sender_key, second)
    assert not_found(frames[1])


@pytest.mark.stand
async def test_every_send_gets_one_answer_in_the_order_of_the_requests(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    identity = derive_identity_key(seed)
    # The client sends to itself, so that Deliver frames come between its answers.
    client = await register(open_client, relay_url, seed)
    first, refused, last = send_to(identity), send_to(make_public_key()), send_to(identity)

    for send in (first, refused, first, last):
        await client.send(ClientFrame(send=send))
    frames = [await client.receive() for _ in range(6)]
    # An answer too many would arrive before the answer to this request.
    next_frame = await round_trip(client)

    answers = [frame for frame in frames if frame.WhichOneof("frame") != "deliver"]
    deliveries = [frame for frame in frames if frame.WhichOneof("frame") == "deliver"]
    unknown = Error(code=ErrorCode.UNKNOWN_RECIPIENT, message_id=refused.message_id)
    assert answers == [
        stored(first),
        ServerFrame(error=unknown),
        stored(first),
        stored(last),
    ]
    assert deliveries == [delivered(identity, first), delivered(identity, last)]
    assert not_found(next_frame)


@pytest.mark.stand
async def test_largest_payload_is_delivered_in_a_frame_within_the_limit(
    relay_url: str, open_client: OpenClient, wire: Wire
) -> None:
    sender_seed, recipient_seed = os.urandom(32), os.urandom(32)
    recipient = await register(open_client, relay_url, recipient_seed)
    sender = await log_in(open_client, relay_url, sender_seed)
    send = send_to(derive_identity_key(recipient_seed), os.urandom(MAX_PAYLOAD_BYTES))

    answer = await sender.ask(send)
    delivery = await recipient.receive()

    assert answer == stored(send)
    assert delivery == delivered(derive_identity_key(sender_seed), send)
    assert len(wire.messages[-1]) <= MAX_FRAME_BYTES


def shorten_the_message_id(send: Send) -> None:
    send.message_id = send.message_id[:15]


def lengthen_the_message_id(send: Send) -> None:
    send.message_id += b"\x00"


def shorten_the_recipient(send: Send) -> None:
    send.recipient = send.recipient[:31]


def lengthen_the_recipient(send: Send) -> None:
    send.recipient += b"\x00"


def leave_out_the_payload(send: Send) -> None:
    send.payload = b""


def pass_the_largest_payload(send: Send) -> None:
    send.payload = bytes(MAX_PAYLOAD_BYTES + 1)


@pytest.mark.stand
@pytest.mark.parametrize(
    "spoil",
    [
        shorten_the_message_id,
        lengthen_the_message_id,
        shorten_the_recipient,
        lengthen_the_recipient,
        leave_out_the_payload,
        pass_the_largest_payload,
    ],
)
async def test_malformed_send_closes_with_1008(
    relay_url: str, open_client: OpenClient, spoil: Callable[[Send], None]
) -> None:
    client = await log_in(open_client, relay_url, os.urandom(32))
    send = send_to(make_public_key())
    spoil(send)

    await client.send(ClientFrame(send=send))

    assert await client.frames_until_close() == ([], CloseCode.PROTOCOL_VIOLATION)


@pytest.mark.stand
@pytest.mark.parametrize(
    "pairs",
    [
        [],
        [MessageRef(message_id=os.urandom(15), sender=make_public_key())],
        [MessageRef(message_id=os.urandom(16), sender=os.urandom(33))],
        [MessageRef(message_id=os.urandom(16), sender=make_public_key()), MessageRef()],
    ],
    ids=["no pair", "short message id", "long sender", "empty pair"],
)
async def test_malformed_ack_closes_with_1008(
    relay_url: str, open_client: OpenClient, pairs: list[MessageRef]
) -> None:
    client = await log_in(open_client, relay_url, os.urandom(32))

    await client.send(ClientFrame(ack=Ack(messages=pairs)))

    assert await client.frames_until_close() == ([], CloseCode.PROTOCOL_VIOLATION)


def test_no_client_frame_names_its_sender() -> None:
    frames = {
        field.name: field.message_type
        for field in ClientFrame.DESCRIPTOR.fields
        if field.message_type is not None
    }
    frames_with_a_sender = [
        name
        for name, frame in frames.items()
        if any(field.name == "sender" for field in frame.fields)
    ]

    assert [field.name for field in frames["send"].fields] == [
        "message_id",
        "recipient",
        "payload",
    ]
    assert frames_with_a_sender == []


async def test_recipient_that_stops_reading_does_not_delay_stored(
    relay_url: str, open_client: OpenClient, wire: Wire
) -> None:
    sender_seed, recipient_seed = os.urandom(32), os.urandom(32)
    await (await register(open_client, relay_url, recipient_seed)).websocket.close()
    sender = await log_in(open_client, relay_url, sender_seed)
    address = urlsplit(relay_url)
    assert address.hostname is not None
    assert address.port is not None
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SMALL_RECEIVE_BUFFER)
    sock.setblocking(False)
    await asyncio.get_running_loop().sock_connect(sock, (address.hostname, address.port))
    payload = os.urandom(MAX_PAYLOAD_BYTES)
    sends = [send_to(derive_identity_key(recipient_seed), payload) for _ in range(STUCK_SENDS)]

    # A queue of one frame pauses the reading of the socket once a Deliver arrives.
    async with connect(f"{relay_url}/ws", sock=sock, max_queue=1, proxy=None) as websocket:
        host, port = websocket.local_address[:2]
        wire.client_addresses.extend([f"{host}:{port}", f"{host!r}, {port}"])
        hello = ServerFrame.FromString(await websocket.recv(decode=False)).hello
        recipient = RawClient(websocket, hello, address.hostname, wire)
        await recipient.log_in(recipient_seed)

        answers = [await sender.ask(sends[0])]
        for send in sends[1:]:
            # Past the wire record, which holds the payload once already.
            await sender.websocket.send(ClientFrame(send=send).SerializeToString())
            answers.append(await sender.receive())
        websocket.transport.abort()

    assert answers == [stored(send) for send in sends]
