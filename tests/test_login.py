import asyncio
import os
from collections.abc import Awaitable, Callable

import pytest
from relay_harness import PATIENCE_SECONDS, OpenClient, RawClient, build_upload
from websockets.exceptions import ConnectionClosed

from sotto.crypto.identity import sign_login
from sotto.proto.sotto_pb2 import ClientFrame, FetchBundle, Login
from sotto.relay.frames import MAX_FRAME_BYTES
from sotto.relay.server import CloseCode

pytestmark = pytest.mark.stand

# Field 15 is in no message of docs/protocol.md, section 7.1.
UNKNOWN_FIELD = b"\x7a\x03new"
# Sent by the WebSocket library itself (RFC 6455, section 8.1).
INVALID_TEXT = 1007

# The point of order 1 and its encoding with a y that is not reduced, section 3.3.
SMALL_ORDER_KEY = bytes.fromhex("01" + "00" * 31)
NON_CANONICAL_KEY = bytes.fromhex("ee" + "ff" * 30 + "7f")
KEY_THAT_IS_NO_POINT = bytes.fromhex("02" + "00" * 31)
# R is the point of order 1 and S is zero: the library verifies it under either key above.
FORGED_SIGNATURE = SMALL_ORDER_KEY + bytes(32)


async def before_login(open_client: OpenClient, url: str) -> RawClient:
    return await open_client(url)


async def after_login(open_client: OpenClient, url: str) -> RawClient:
    client = await open_client(url)
    answer = await client.log_in(os.urandom(32))
    assert answer.WhichOneof("frame") == "logged_in"
    return client


type EnterState = Callable[[OpenClient, str], Awaitable[RawClient]]
IN_EVERY_STATE = pytest.mark.parametrize("enter_state", [before_login, after_login])


def flip_a_signature_bit(login: Login) -> None:
    login.signature = bytes([login.signature[0] ^ 1]) + login.signature[1:]


def sign_as_another_identity(client: RawClient, login: Login) -> None:
    login.signature = sign_login(
        os.urandom(32),
        server_name=client.server_name,
        server_nonce=client.hello.nonce,
        client_nonce=login.client_nonce,
    )


def spoil_the_signature(client: RawClient, login: Login) -> None:
    flip_a_signature_bit(login)


def name_a_key_that_is_no_point(client: RawClient, login: Login) -> None:
    login.identity_key = KEY_THAT_IS_NO_POINT


async def answers_a_ping(client: RawClient) -> bool:
    try:
        async with asyncio.timeout(PATIENCE_SECONDS):
            await (await client.websocket.ping())
    except ConnectionClosed:
        return False
    return True


async def test_relay_speaks_first_with_a_nonce_of_its_own(
    relay_url: str, open_client: OpenClient
) -> None:
    first = await open_client(relay_url)
    second = await open_client(relay_url)

    assert first.hello.version == second.hello.version == 1
    assert len(first.hello.nonce) == len(second.hello.nonce) == 32
    assert first.hello.nonce != second.hello.nonce


async def test_login_is_accepted(relay_url: str, open_client: OpenClient) -> None:
    client = await open_client(relay_url)

    answer = await client.log_in(os.urandom(32))

    assert answer.WhichOneof("frame") == "logged_in"
    assert answer.logged_in.one_time_prekey_count == 0
    assert await answers_a_ping(client)


async def test_login_with_unknown_fields_is_accepted(
    relay_url: str, open_client: OpenClient
) -> None:
    client = await open_client(relay_url)
    frame = client.login(os.urandom(32))
    known_size = frame.ByteSize()
    frame.login.MergeFromString(UNKNOWN_FIELD)
    frame.MergeFromString(UNKNOWN_FIELD)
    assert frame.ByteSize() == known_size + 2 * len(UNKNOWN_FIELD)

    await client.send(frame)
    answer = await client.receive()

    assert answer.WhichOneof("frame") == "logged_in"


@pytest.mark.parametrize(
    "spoil", [spoil_the_signature, sign_as_another_identity, name_a_key_that_is_no_point]
)
async def test_login_whose_signature_does_not_verify_closes_with_3000(
    relay_url: str, open_client: OpenClient, spoil: Callable[[RawClient, Login], None]
) -> None:
    client = await open_client(relay_url)
    frame = client.login(os.urandom(32))
    spoil(client, frame.login)

    await client.send(frame)

    assert await client.frames_until_close() == ([], CloseCode.LOGIN_REFUSED)


@pytest.mark.parametrize(
    "excluded_key", [SMALL_ORDER_KEY, NON_CANONICAL_KEY], ids=["small-order", "non-canonical"]
)
async def test_login_with_an_excluded_key_closes_with_3000(
    relay_url: str, open_client: OpenClient, excluded_key: bytes
) -> None:
    client = await open_client(relay_url)
    frame = client.login(os.urandom(32))
    frame.login.identity_key = excluded_key
    frame.login.signature = FORGED_SIGNATURE

    await client.send(frame)

    assert await client.frames_until_close() == ([], CloseCode.LOGIN_REFUSED)


async def test_login_signed_for_another_server_name_closes_with_3000(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    client = await open_client(relay_url)
    frame = client.login(seed)
    frame.login.signature = sign_login(
        seed,
        server_name="relay.example.org",
        server_nonce=client.hello.nonce,
        client_nonce=frame.login.client_nonce,
    )

    await client.send(frame)

    assert await client.frames_until_close() == ([], CloseCode.LOGIN_REFUSED)


async def test_login_signed_over_another_client_nonce_closes_with_3000(
    relay_url: str, open_client: OpenClient
) -> None:
    client = await open_client(relay_url)
    frame = client.login(os.urandom(32))
    frame.login.client_nonce = os.urandom(32)

    await client.send(frame)

    assert await client.frames_until_close() == ([], CloseCode.LOGIN_REFUSED)


async def test_login_replayed_on_another_connection_closes_with_3000(
    relay_url: str, open_client: OpenClient
) -> None:
    first = await open_client(relay_url)
    recorded = first.login(os.urandom(32))
    await first.send(recorded)
    assert (await first.receive()).WhichOneof("frame") == "logged_in"
    second = await open_client(relay_url)

    await second.send(recorded)

    assert await second.frames_until_close() == ([], CloseCode.LOGIN_REFUSED)


async def test_login_checks_stop_at_the_first_that_fails(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    live = await open_client(relay_url)
    assert (await live.log_in(seed)).WhichOneof("frame") == "logged_in"

    # Step 3 before step 4 of section 8.3: a malformed Login is no login, whatever its key.
    malformed = await open_client(relay_url)
    frame = malformed.login(seed)
    frame.login.identity_key = SMALL_ORDER_KEY
    frame.login.signature = FORGED_SIGNATURE[:-1]
    await malformed.send(frame)
    assert await malformed.frames_until_close() == ([], CloseCode.PROTOCOL_VIOLATION)

    # Step 5 before step 6: a refused Login replaces nobody, so the live connection of the
    # identity gets the code of its own violation and not 4001.
    refused = await open_client(relay_url)
    frame = refused.login(seed)
    flip_a_signature_bit(frame.login)
    await refused.send(frame)
    assert await refused.frames_until_close() == ([], CloseCode.LOGIN_REFUSED)
    await live.send(os.urandom(16).hex())
    assert await live.frames_until_close() == ([], CloseCode.TEXT_FRAME)


@IN_EVERY_STATE
async def test_text_message_closes_with_1003(
    relay_url: str, open_client: OpenClient, enter_state: EnterState
) -> None:
    client = await enter_state(open_client, relay_url)

    await client.send(os.urandom(16).hex())

    assert await client.frames_until_close() == ([], CloseCode.TEXT_FRAME)


async def test_text_message_that_is_not_utf_8_closes_with_1007(
    relay_url: str, open_client: OpenClient
) -> None:
    client = await open_client(relay_url)

    client.websocket.protocol.send_text(b"\xff")
    client.websocket.send_data()

    assert await client.frames_until_close() == ([], INVALID_TEXT)


@pytest.mark.parametrize(
    "lengths", [[MAX_FRAME_BYTES + 1], [40000, 25537]], ids=["one-frame", "two-fragments"]
)
async def test_message_above_the_largest_frame_closes_with_1009(
    relay_url: str, open_client: OpenClient, lengths: list[int]
) -> None:
    client = await open_client(relay_url)

    await client.send([os.urandom(length) for length in lengths])

    assert await client.frames_until_close() == ([], CloseCode.FRAME_TOO_BIG)


async def test_message_of_the_largest_size_reaches_the_parse_step(
    relay_url: str, open_client: OpenClient
) -> None:
    client = await open_client(relay_url)

    await client.send(os.urandom(MAX_FRAME_BYTES))

    assert await client.frames_until_close() == ([], CloseCode.PROTOCOL_VIOLATION)


def empty_message(client: RawClient) -> bytes:
    return b""


def random_bytes(client: RawClient) -> bytes:
    return os.urandom(64)


def login_with_a_short_signature(client: RawClient) -> bytes:
    frame = client.login(os.urandom(32))
    frame.login.signature = frame.login.signature[:-1]
    return frame.SerializeToString()


def login_without_a_client_nonce(client: RawClient) -> bytes:
    frame = client.login(os.urandom(32))
    frame.login.ClearField("client_nonce")
    return frame.SerializeToString()


@IN_EVERY_STATE
@pytest.mark.parametrize(
    "malformed",
    [empty_message, random_bytes, login_with_a_short_signature, login_without_a_client_nonce],
)
async def test_malformed_frame_closes_with_1008(
    relay_url: str,
    open_client: OpenClient,
    enter_state: EnterState,
    malformed: Callable[[RawClient], bytes],
) -> None:
    client = await enter_state(open_client, relay_url)

    await client.send(malformed(client))

    assert await client.frames_until_close() == ([], CloseCode.PROTOCOL_VIOLATION)


def complete_upload() -> ClientFrame:
    return ClientFrame(upload_bundle=build_upload(os.urandom(32), [1]))


def complete_fetch() -> ClientFrame:
    return ClientFrame(fetch_bundle=FetchBundle(identity=os.urandom(32)))


@pytest.mark.parametrize("make_frame", [complete_upload, complete_fetch])
async def test_frame_before_login_closes_with_1008(
    relay_url: str, open_client: OpenClient, make_frame: Callable[[], ClientFrame]
) -> None:
    client = await open_client(relay_url)

    await client.send(make_frame())

    assert await client.frames_until_close() == ([], CloseCode.PROTOCOL_VIOLATION)


async def test_second_login_on_a_connection_closes_with_1008(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    client = await open_client(relay_url)
    assert (await client.log_in(seed)).WhichOneof("frame") == "logged_in"

    await client.send(client.login(seed))

    assert await client.frames_until_close() == ([], CloseCode.PROTOCOL_VIOLATION)


async def test_frames_sent_with_the_login_are_handled_after_it(
    relay_url: str, open_client: OpenClient
) -> None:
    client = await open_client(relay_url)

    await client.send(client.login(os.urandom(32)))
    await client.send(os.urandom(16).hex())

    frames, close_code = await client.frames_until_close()
    assert [frame.WhichOneof("frame") for frame in frames] == ["logged_in"]
    assert close_code == CloseCode.TEXT_FRAME


async def test_frames_sent_with_a_refused_login_are_not_handled(
    relay_url: str, open_client: OpenClient
) -> None:
    client = await open_client(relay_url)
    frame = client.login(os.urandom(32))
    flip_a_signature_bit(frame.login)

    await client.send(frame)
    await client.send(os.urandom(16).hex())

    assert await client.frames_until_close() == ([], CloseCode.LOGIN_REFUSED)


async def test_every_login_of_an_identity_replaces_the_one_before(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    first = await open_client(relay_url)
    await first.log_in(seed)

    second = await open_client(relay_url)
    await second.log_in(seed)
    first_closing = await first.frames_until_close()
    third = await open_client(relay_url)
    await third.log_in(seed)
    second_closing = await second.frames_until_close()

    assert first_closing == ([], CloseCode.REPLACED)
    assert second_closing == ([], CloseCode.REPLACED)
    assert await answers_a_ping(third)


async def test_logins_of_one_identity_at_once_leave_one_connection(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    clients = [await open_client(relay_url) for _ in range(4)]

    answers = await asyncio.gather(*(client.log_in(seed) for client in clients))
    alive = await asyncio.gather(*(answers_a_ping(client) for client in clients))
    close_codes = [client.websocket.close_code for client in clients]

    assert [answer.WhichOneof("frame") for answer in answers] == ["logged_in"] * 4
    assert sorted(alive) == [False, False, False, True]
    assert sorted(close_codes, key=str) == [CloseCode.REPLACED] * 3 + [None]
