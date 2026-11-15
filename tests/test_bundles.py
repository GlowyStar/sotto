import os
from collections.abc import Callable

import pytest
from relay_harness import OpenClient, RawClient, build_upload, make_public_key

from sotto.crypto.identity import (
    derive_identity_key,
    sign_identity_dh_key,
    sign_signed_prekey,
)
from sotto.proto.sotto_pb2 import (
    Bundle,
    BundleStored,
    ClientFrame,
    Error,
    ErrorCode,
    FetchBundle,
    OneTimePrekey,
    ServerFrame,
    UploadBundle,
)
from sotto.relay.server import CloseCode

pytestmark = pytest.mark.stand

# ONE_TIME_PREKEY_CAP of docs/protocol.md, section 12.1: no frame carries it.
ONE_TIME_PREKEY_CAP = 100

# The point of order 1 and its encoding with a y that is not reduced, section 3.3.
SMALL_ORDER_KEY = bytes.fromhex("01" + "00" * 31)
NON_CANONICAL_KEY = bytes.fromhex("ee" + "ff" * 30 + "7f")


async def log_in(open_client: OpenClient, url: str, seed: bytes) -> RawClient:
    client = await open_client(url)
    answer = await client.log_in(seed)
    assert answer.WhichOneof("frame") == "logged_in"
    return client


async def fetch(client: RawClient, identity: bytes) -> Bundle:
    answer = await client.ask(FetchBundle(identity=identity))
    assert answer.WhichOneof("frame") == "bundle"
    return answer.bundle


def stored(count: int) -> ServerFrame:
    return ServerFrame(bundle_stored=BundleStored(one_time_prekey_count=count))


def refused(code: ErrorCode, identity: bytes = b"") -> ServerFrame:
    return ServerFrame(error=Error(code=code, identity=identity))


def later_upload(seed: bytes, first: UploadBundle, ids: list[int]) -> UploadBundle:
    """Builds a second bundle of the identity: the same X25519 identity key, new prekeys."""
    upload = build_upload(seed, ids)
    upload.identity_dh_key = first.identity_dh_key
    upload.identity_dh_signature = first.identity_dh_signature
    return upload


def flip_the_first_bit(value: bytes) -> bytes:
    return bytes([value[0] ^ 1]) + value[1:]


async def test_uploaded_bundle_is_fetched_byte_for_byte(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    upload = build_upload(seed, [7, 8])
    owner = await log_in(open_client, relay_url, seed)
    someone = await log_in(open_client, relay_url, os.urandom(32))

    answer = await owner.ask(upload)
    for_someone = await fetch(someone, derive_identity_key(seed))
    for_the_owner = await fetch(owner, derive_identity_key(seed))

    assert answer == stored(2)
    assert for_someone == Bundle(
        identity=derive_identity_key(seed),
        identity_dh_key=upload.identity_dh_key,
        identity_dh_signature=upload.identity_dh_signature,
        signed_prekey=upload.signed_prekey,
        one_time_prekey=upload.one_time_prekeys[0],
    )
    assert for_the_owner.one_time_prekey == upload.one_time_prekeys[1]
    for_the_owner.one_time_prekey.CopyFrom(upload.one_time_prekeys[0])
    assert for_the_owner == for_someone


async def test_each_fetch_hands_out_the_one_time_prekey_that_was_stored_first(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    first = build_upload(seed, [9, 2, 7])
    second = later_upload(seed, first, [4])
    owner = await log_in(open_client, relay_url, seed)
    someone = await log_in(open_client, relay_url, os.urandom(32))
    await owner.ask(first)
    await owner.ask(second)

    bundles = [await fetch(someone, derive_identity_key(seed)) for _ in range(5)]

    handed_out = [bundle.one_time_prekey for bundle in bundles[:4]]
    assert handed_out == [*first.one_time_prekeys, *second.one_time_prekeys]
    assert not bundles[4].HasField("one_time_prekey")
    assert bundles[4].signed_prekey == second.signed_prekey


async def test_bundle_without_one_time_prekeys_is_stored_and_fetched(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    upload = build_upload(seed)
    owner = await log_in(open_client, relay_url, seed)

    answer = await owner.ask(upload)
    bundle = await fetch(owner, derive_identity_key(seed))

    assert answer == stored(0)
    assert bundle.signed_prekey == upload.signed_prekey
    assert not bundle.HasField("one_time_prekey")


async def test_later_upload_replaces_the_signed_prekey_and_keeps_the_first_identity_dh_key(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    first = build_upload(seed, [1])
    second = later_upload(seed, first, [1, 2])
    owner = await log_in(open_client, relay_url, seed)
    await owner.ask(first)

    answer = await owner.ask(second)
    bundles = [await fetch(owner, derive_identity_key(seed)) for _ in range(3)]

    assert answer == stored(2)
    assert bundles[0].identity_dh_key == first.identity_dh_key
    assert bundles[0].identity_dh_signature == first.identity_dh_signature
    assert bundles[0].signed_prekey == second.signed_prekey
    # The id 1 of the second frame was stored already, so its key was skipped.
    assert bundles[0].one_time_prekey == first.one_time_prekeys[0]
    assert bundles[1].one_time_prekey == second.one_time_prekeys[1]
    assert not bundles[2].HasField("one_time_prekey")


async def test_one_time_prekeys_are_stored_in_the_order_of_the_frame_up_to_the_cap(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    first = build_upload(seed, list(range(60)))
    second = later_upload(seed, first, list(range(60, 120)))
    owner = await log_in(open_client, relay_url, seed)

    answers = [await owner.ask(first), await owner.ask(second), await owner.ask(second)]
    bundles = [
        await fetch(owner, derive_identity_key(seed)) for _ in range(ONE_TIME_PREKEY_CAP + 1)
    ]

    assert answers == [stored(60), stored(ONE_TIME_PREKEY_CAP), stored(ONE_TIME_PREKEY_CAP)]
    handed_out = [bundle.one_time_prekey for bundle in bundles[:ONE_TIME_PREKEY_CAP]]
    assert handed_out == [*first.one_time_prekeys, *second.one_time_prekeys[:40]]
    assert not bundles[ONE_TIME_PREKEY_CAP].HasField("one_time_prekey")


async def test_one_time_prekey_uploaded_again_after_its_handout_is_handed_out_again(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    upload = build_upload(seed, [5])
    owner = await log_in(open_client, relay_url, seed)
    await owner.ask(upload)
    first_handout = await fetch(owner, derive_identity_key(seed))

    answer = await owner.ask(upload)
    second_handout = await fetch(owner, derive_identity_key(seed))

    assert answer == stored(1)
    assert first_handout.one_time_prekey == upload.one_time_prekeys[0]
    assert second_handout.one_time_prekey == upload.one_time_prekeys[0]


async def test_counts_of_logged_in_and_bundle_stored_follow_the_stored_one_time_prekeys(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    first = build_upload(seed, [1, 2, 3])
    owner = await log_in(open_client, relay_url, seed)
    someone = await log_in(open_client, relay_url, os.urandom(32))

    after_the_upload = await owner.ask(first)
    await fetch(someone, derive_identity_key(seed))
    owner_again = await open_client(relay_url)
    at_the_next_login = await owner_again.log_in(seed)
    after_two_more = await owner_again.ask(later_upload(seed, first, [4, 5]))

    assert after_the_upload == stored(3)
    assert at_the_next_login.logged_in.one_time_prekey_count == 2
    assert after_two_more == stored(4)


async def test_owner_gets_no_notice_when_a_one_time_prekey_is_handed_out(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    nobody = make_public_key()
    owner = await log_in(open_client, relay_url, seed)
    someone = await log_in(open_client, relay_url, os.urandom(32))
    await owner.ask(build_upload(seed, [1, 2]))

    handout = await fetch(someone, derive_identity_key(seed))
    next_frame_of_the_owner = await owner.ask(FetchBundle(identity=nobody))

    assert handout.HasField("one_time_prekey")
    assert next_frame_of_the_owner == refused(ErrorCode.NOT_FOUND, nobody)


async def test_upload_changes_only_the_bundle_of_its_own_identity(
    relay_url: str, open_client: OpenClient
) -> None:
    seed, other_seed = os.urandom(32), os.urandom(32)
    upload, other_upload = build_upload(seed, [1]), build_upload(other_seed, [1])
    owner = await log_in(open_client, relay_url, seed)
    other = await log_in(open_client, relay_url, other_seed)
    await owner.ask(upload)

    await other.ask(other_upload)
    # The bundle of the owner as it is: the other identity cannot have signed it.
    copy_of_the_owners = await other.ask(build_upload(seed))
    other_bundle = await fetch(owner, derive_identity_key(other_seed))
    bundle = await fetch(other, derive_identity_key(seed))

    assert copy_of_the_owners == refused(ErrorCode.BAD_BUNDLE)
    assert other_bundle == Bundle(
        identity=derive_identity_key(other_seed),
        identity_dh_key=other_upload.identity_dh_key,
        identity_dh_signature=other_upload.identity_dh_signature,
        signed_prekey=other_upload.signed_prekey,
        one_time_prekey=other_upload.one_time_prekeys[0],
    )
    assert bundle == Bundle(
        identity=derive_identity_key(seed),
        identity_dh_key=upload.identity_dh_key,
        identity_dh_signature=upload.identity_dh_signature,
        signed_prekey=upload.signed_prekey,
        one_time_prekey=upload.one_time_prekeys[0],
    )


def spoil_the_identity_dh_signature(seed: bytes, upload: UploadBundle) -> None:
    upload.identity_dh_signature = flip_the_first_bit(upload.identity_dh_signature)


def spoil_the_signed_prekey_signature(seed: bytes, upload: UploadBundle) -> None:
    upload.signed_prekey.signature = flip_the_first_bit(upload.signed_prekey.signature)


def sign_the_identity_dh_key_as_another_identity(seed: bytes, upload: UploadBundle) -> None:
    upload.identity_dh_signature = sign_identity_dh_key(
        os.urandom(32), identity_dh_key=upload.identity_dh_key
    )


def sign_the_signed_prekey_as_another_identity(seed: bytes, upload: UploadBundle) -> None:
    upload.signed_prekey.signature = sign_signed_prekey(
        os.urandom(32), signed_prekey=upload.signed_prekey.key
    )


def sign_each_key_for_the_purpose_of_the_other(seed: bytes, upload: UploadBundle) -> None:
    upload.identity_dh_signature = sign_signed_prekey(
        seed, signed_prekey=upload.identity_dh_key
    )
    upload.signed_prekey.signature = sign_identity_dh_key(
        seed, identity_dh_key=upload.signed_prekey.key
    )


def carry_another_identity_dh_key(seed: bytes, upload: UploadBundle) -> None:
    upload.identity_dh_key = make_public_key()
    upload.identity_dh_signature = sign_identity_dh_key(
        seed, identity_dh_key=upload.identity_dh_key
    )


REFUSALS = [
    (spoil_the_identity_dh_signature, ErrorCode.BAD_BUNDLE),
    (spoil_the_signed_prekey_signature, ErrorCode.BAD_BUNDLE),
    (sign_the_identity_dh_key_as_another_identity, ErrorCode.BAD_BUNDLE),
    (sign_the_signed_prekey_as_another_identity, ErrorCode.BAD_BUNDLE),
    (sign_each_key_for_the_purpose_of_the_other, ErrorCode.BAD_BUNDLE),
    (carry_another_identity_dh_key, ErrorCode.IDENTITY_KEY_MISMATCH),
]
type Spoil = Callable[[bytes, UploadBundle], None]


@pytest.mark.parametrize(("spoil", "code"), REFUSALS)
async def test_refused_upload_gets_the_code_of_its_reason_and_stores_nothing(
    relay_url: str, open_client: OpenClient, spoil: Spoil, code: ErrorCode
) -> None:
    seed = os.urandom(32)
    first = build_upload(seed, [1])
    second = later_upload(seed, first, [2, 3])
    spoil(seed, second)
    owner = await log_in(open_client, relay_url, seed)
    await owner.ask(first)

    answer = await owner.ask(second)
    bundles = [await fetch(owner, derive_identity_key(seed)) for _ in range(2)]

    assert answer == refused(code)
    assert bundles[0].identity_dh_key == first.identity_dh_key
    assert bundles[0].signed_prekey == first.signed_prekey
    assert bundles[0].one_time_prekey == first.one_time_prekeys[0]
    assert not bundles[1].HasField("one_time_prekey")


async def test_refused_first_upload_does_not_register_the_identity(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    upload = build_upload(seed, [1])
    spoil_the_signed_prekey_signature(seed, upload)
    owner = await log_in(open_client, relay_url, seed)

    answer = await owner.ask(upload)
    lookup = await owner.ask(FetchBundle(identity=derive_identity_key(seed)))

    assert answer == refused(ErrorCode.BAD_BUNDLE)
    assert lookup == refused(ErrorCode.NOT_FOUND, derive_identity_key(seed))


async def test_upload_checks_stop_at_the_first_that_fails(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    first = build_upload(seed)
    another_key_and_a_bad_signature = build_upload(seed)
    spoil_the_signed_prekey_signature(seed, another_key_and_a_bad_signature)
    another_key_and_a_short_one = build_upload(seed, [1])
    another_key_and_a_short_one.one_time_prekeys[0].key = os.urandom(31)
    owner = await log_in(open_client, relay_url, seed)
    await owner.ask(first)

    # The signatures of steps 2 and 3 come before the stored key of step 4.
    answer = await owner.ask(another_key_and_a_bad_signature)
    # The lengths of the parse step come before every step of section 9.1.
    await owner.send(ClientFrame(upload_bundle=another_key_and_a_short_one))
    closing = await owner.frames_until_close()

    assert answer == refused(ErrorCode.BAD_BUNDLE)
    assert closing == ([], CloseCode.PROTOCOL_VIOLATION)


@pytest.mark.parametrize(
    "make_identity",
    [make_public_key, lambda: SMALL_ORDER_KEY, lambda: NON_CANONICAL_KEY],
    ids=["a-key-nobody-uploaded-for", "a-key-of-small-order", "a-non-canonical-key"],
)
async def test_fetch_for_an_identity_that_is_not_registered_answers_not_found(
    relay_url: str, open_client: OpenClient, make_identity: Callable[[], bytes]
) -> None:
    identity = make_identity()
    client = await log_in(open_client, relay_url, os.urandom(32))

    answer = await client.ask(FetchBundle(identity=identity))

    assert answer == refused(ErrorCode.NOT_FOUND, identity)


async def test_fetch_for_an_identity_that_only_logged_in_answers_not_found(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    client = await log_in(open_client, relay_url, seed)

    answer = await client.ask(FetchBundle(identity=derive_identity_key(seed)))

    assert answer == refused(ErrorCode.NOT_FOUND, derive_identity_key(seed))


async def test_refused_frames_get_an_error_with_their_key_and_the_connection_goes_on(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    nobody = make_public_key()
    bad_upload = build_upload(seed)
    spoil_the_identity_dh_signature(seed, bad_upload)
    client = await log_in(open_client, relay_url, seed)

    refused_upload = await client.ask(bad_upload)
    refused_fetch = await client.ask(FetchBundle(identity=nobody))
    accepted_upload = await client.ask(build_upload(seed))

    # Neither key field set names an UploadBundle, `identity` set names a FetchBundle.
    assert refused_upload == ServerFrame(error=Error(code=ErrorCode.BAD_BUNDLE))
    assert refused_fetch == ServerFrame(error=Error(code=ErrorCode.NOT_FOUND, identity=nobody))
    assert accepted_upload == stored(0)


async def test_every_upload_and_fetch_gets_one_answer_in_the_order_of_the_requests(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    identity, nobody, nobody_else = (
        derive_identity_key(seed),
        make_public_key(),
        make_public_key(),
    )
    upload = build_upload(seed, [1])
    bad_upload = later_upload(seed, upload, [2])
    spoil_the_identity_dh_signature(seed, bad_upload)
    client = await log_in(open_client, relay_url, seed)

    # Sent in one go, before any answer is read.
    await client.send(ClientFrame(upload_bundle=upload))
    await client.send(ClientFrame(fetch_bundle=FetchBundle(identity=nobody)))
    await client.send(ClientFrame(upload_bundle=bad_upload))
    await client.send(ClientFrame(fetch_bundle=FetchBundle(identity=identity)))
    await client.send(ClientFrame(fetch_bundle=FetchBundle(identity=identity)))
    answers = [await client.receive() for _ in range(5)]
    # An answer too many would arrive before the answer to this request.
    next_frame = await client.ask(FetchBundle(identity=nobody_else))

    kinds = [answer.WhichOneof("frame") for answer in answers]
    assert kinds == ["bundle_stored", "error", "error", "bundle", "bundle"]
    assert answers[1] == refused(ErrorCode.NOT_FOUND, nobody)
    assert answers[2] == refused(ErrorCode.BAD_BUNDLE)
    assert answers[3].bundle.one_time_prekey == upload.one_time_prekeys[0]
    assert not answers[4].bundle.HasField("one_time_prekey")
    assert next_frame == refused(ErrorCode.NOT_FOUND, nobody_else)


def shorten_the_identity_dh_key(upload: UploadBundle) -> None:
    upload.identity_dh_key = upload.identity_dh_key[:31]


def lengthen_the_identity_dh_key(upload: UploadBundle) -> None:
    upload.identity_dh_key += b"\x00"


def shorten_the_identity_dh_signature(upload: UploadBundle) -> None:
    upload.identity_dh_signature = upload.identity_dh_signature[:63]


def leave_out_the_signed_prekey(upload: UploadBundle) -> None:
    upload.ClearField("signed_prekey")


def shorten_the_signed_prekey(upload: UploadBundle) -> None:
    upload.signed_prekey.key = upload.signed_prekey.key[:31]


def lengthen_the_signed_prekey_signature(upload: UploadBundle) -> None:
    upload.signed_prekey.signature += b"\x00"


def shorten_the_last_one_time_prekey(upload: UploadBundle) -> None:
    upload.one_time_prekeys[-1].key = upload.one_time_prekeys[-1].key[:31]


def add_a_one_time_prekey_without_a_key(upload: UploadBundle) -> None:
    upload.one_time_prekeys.append(OneTimePrekey(id=4))


@pytest.mark.parametrize(
    "spoil",
    [
        shorten_the_identity_dh_key,
        lengthen_the_identity_dh_key,
        shorten_the_identity_dh_signature,
        leave_out_the_signed_prekey,
        shorten_the_signed_prekey,
        lengthen_the_signed_prekey_signature,
        shorten_the_last_one_time_prekey,
        add_a_one_time_prekey_without_a_key,
    ],
)
async def test_malformed_upload_closes_with_1008_and_stores_nothing(
    relay_url: str, open_client: OpenClient, spoil: Callable[[UploadBundle], None]
) -> None:
    seed = os.urandom(32)
    upload = build_upload(seed, [1, 2, 3])
    spoil(upload)
    owner = await log_in(open_client, relay_url, seed)
    someone = await log_in(open_client, relay_url, os.urandom(32))

    await owner.send(ClientFrame(upload_bundle=upload))
    closing = await owner.frames_until_close()
    lookup = await someone.ask(FetchBundle(identity=derive_identity_key(seed)))

    assert closing == ([], CloseCode.PROTOCOL_VIOLATION)
    assert lookup == refused(ErrorCode.NOT_FOUND, derive_identity_key(seed))


@pytest.mark.parametrize("length", [0, 31, 33])
async def test_malformed_fetch_closes_with_1008(
    relay_url: str, open_client: OpenClient, length: int
) -> None:
    client = await log_in(open_client, relay_url, os.urandom(32))

    await client.send(ClientFrame(fetch_bundle=FetchBundle(identity=os.urandom(length))))

    assert await client.frames_until_close() == ([], CloseCode.PROTOCOL_VIOLATION)
