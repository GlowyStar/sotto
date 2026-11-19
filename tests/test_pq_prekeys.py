"""The post-quantum prekeys on the relay, docs/protocol.md, section 42.1."""

import os
from collections.abc import Callable

import pytest
from relay_harness import OpenClient, RawClient, build_pq_upload, build_upload, make_pq_prekey

from sotto.crypto.identity import derive_identity_key
from sotto.proto.sotto_pb2 import (
    Bundle,
    BundleStored,
    ClientFrame,
    Error,
    ErrorCode,
    FetchBundle,
    ServerFrame,
    UploadBundle,
)
from sotto.relay.server import CloseCode

pytestmark = pytest.mark.stand

# PQ_ONE_TIME_PREKEY_CAP of docs/protocol.md, section 12.1: no frame carries it.
PQ_ONE_TIME_PREKEY_CAP = 40


async def log_in(open_client: OpenClient, url: str, seed: bytes) -> RawClient:
    client = await open_client(url)
    answer = await client.log_in(seed)
    assert answer.WhichOneof("frame") == "logged_in"
    return client


async def fetch(client: RawClient, identity: bytes) -> Bundle:
    answer = await client.ask(FetchBundle(identity=identity))
    assert answer.WhichOneof("frame") == "bundle"
    return answer.bundle


async def test_one_time_pq_prekeys_go_out_once_in_their_order_then_the_last_resort_one(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    upload = build_pq_upload(seed, 1, [2, 3])
    owner = await log_in(open_client, relay_url, seed)
    someone = await log_in(open_client, relay_url, os.urandom(32))

    answer = await owner.ask(upload)
    bundles = [await fetch(someone, derive_identity_key(seed)) for _ in range(4)]
    again = await open_client(relay_url)
    logged_in = await again.log_in(seed)

    assert answer == ServerFrame(bundle_stored=BundleStored(pq_one_time_prekey_count=2))
    assert [bundle.pq_prekey for bundle in bundles] == [
        upload.pq_one_time_prekeys[0],
        upload.pq_one_time_prekeys[1],
        upload.pq_prekey,
        upload.pq_prekey,
    ]
    assert logged_in.logged_in.pq_one_time_prekey_count == 0


async def test_later_last_resort_prekey_replaces_the_stored_one_and_an_upload_without_keeps_it(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    first = build_pq_upload(seed, 1)
    second = UploadBundle()
    second.CopyFrom(first)
    second.pq_prekey.CopyFrom(make_pq_prekey(seed, 5))
    of_a_first_version_client = UploadBundle()
    of_a_first_version_client.CopyFrom(first)
    of_a_first_version_client.ClearField("pq_prekey")
    owner = await log_in(open_client, relay_url, seed)

    await owner.ask(first)
    await owner.ask(second)
    after_the_second = await fetch(owner, derive_identity_key(seed))
    await owner.ask(of_a_first_version_client)
    after_the_third = await fetch(owner, derive_identity_key(seed))

    assert after_the_second.pq_prekey == second.pq_prekey
    assert after_the_third.pq_prekey == second.pq_prekey


async def test_bundle_of_an_identity_without_pq_prekeys_has_none(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    owner = await log_in(open_client, relay_url, seed)

    await owner.ask(build_upload(seed, [1]))
    bundle = await fetch(owner, derive_identity_key(seed))

    assert bundle.HasField("one_time_prekey")
    assert not bundle.HasField("pq_prekey")


async def test_one_time_pq_prekeys_are_stored_up_to_the_cap(
    relay_url: str, open_client: OpenClient
) -> None:
    seed = os.urandom(32)
    upload = build_pq_upload(seed, 1, range(100, 100 + PQ_ONE_TIME_PREKEY_CAP + 5))
    owner = await log_in(open_client, relay_url, seed)

    answer = await owner.ask(upload)
    first = await fetch(owner, derive_identity_key(seed))

    assert answer.bundle_stored.pq_one_time_prekey_count == PQ_ONE_TIME_PREKEY_CAP
    assert first.pq_prekey.id == 100


def flip_the_last_resort_signature(upload: UploadBundle) -> None:
    signature = upload.pq_prekey.signature
    upload.pq_prekey.signature = bytes([signature[0] ^ 1]) + signature[1:]


def sign_a_one_time_key_by_another_identity(upload: UploadBundle) -> None:
    upload.pq_one_time_prekeys[-1].CopyFrom(make_pq_prekey(os.urandom(32), 3))


def sign_the_key_as_a_signed_prekey(upload: UploadBundle) -> None:
    upload.pq_prekey.signature = upload.signed_prekey.signature


@pytest.mark.parametrize(
    "spoil",
    [
        flip_the_last_resort_signature,
        sign_a_one_time_key_by_another_identity,
        sign_the_key_as_a_signed_prekey,
    ],
)
async def test_upload_with_a_pq_signature_that_fails_is_bad_bundle_and_stores_nothing(
    relay_url: str, open_client: OpenClient, spoil: Callable[[UploadBundle], None]
) -> None:
    seed = os.urandom(32)
    upload = build_pq_upload(seed, 1, [2, 3])
    spoil(upload)
    owner = await log_in(open_client, relay_url, seed)

    answer = await owner.ask(upload)
    lookup = await owner.ask(FetchBundle(identity=derive_identity_key(seed)))

    assert answer == ServerFrame(error=Error(code=ErrorCode.BAD_BUNDLE))
    assert lookup.error.code == ErrorCode.NOT_FOUND


def shorten_the_last_resort_key(upload: UploadBundle) -> None:
    upload.pq_prekey.key = upload.pq_prekey.key[:-1]


def lengthen_a_one_time_signature(upload: UploadBundle) -> None:
    upload.pq_one_time_prekeys[0].signature += b"\x00"


def leave_out_a_one_time_key(upload: UploadBundle) -> None:
    upload.pq_one_time_prekeys[0].key = b""


@pytest.mark.parametrize(
    "spoil",
    [shorten_the_last_resort_key, lengthen_a_one_time_signature, leave_out_a_one_time_key],
)
async def test_malformed_pq_prekey_closes_with_1008_and_stores_nothing(
    relay_url: str, open_client: OpenClient, spoil: Callable[[UploadBundle], None]
) -> None:
    seed = os.urandom(32)
    upload = build_pq_upload(seed, 1, [2])
    spoil(upload)
    owner = await log_in(open_client, relay_url, seed)
    someone = await log_in(open_client, relay_url, os.urandom(32))

    await owner.send(ClientFrame(upload_bundle=upload))
    closing = await owner.frames_until_close()
    lookup = await someone.ask(FetchBundle(identity=derive_identity_key(seed)))

    assert closing == ([], CloseCode.PROTOCOL_VIOLATION)
    assert lookup.error.code == ErrorCode.NOT_FOUND
