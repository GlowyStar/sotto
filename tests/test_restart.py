"""A bundle that outlives a restart of the stand: scripts/stand.sh runs the two in turn."""

import hashlib
import os

import pytest
from relay_harness import OpenClient

from sotto.crypto.identity import (
    derive_identity_key,
    derive_x25519_public_key,
    sign_identity_dh_key,
    sign_signed_prekey,
)
from sotto.proto.sotto_pb2 import (
    Bundle,
    BundleStored,
    FetchBundle,
    OneTimePrekey,
    ServerFrame,
    SignedPrekey,
    UploadBundle,
)


def fixed_key(label: str) -> bytes:
    """Returns 32 bytes that every run derives again; they are no secret of anyone."""
    return hashlib.sha256(f"sotto stand restart {label}".encode()).digest()


SEED = fixed_key("identity")
IDENTITY = derive_identity_key(SEED)
IDENTITY_DH_KEY = derive_x25519_public_key(fixed_key("identity-dh"))
SIGNED_PREKEY = derive_x25519_public_key(fixed_key("signed-prekey"))
UPLOAD = UploadBundle(
    identity_dh_key=IDENTITY_DH_KEY,
    identity_dh_signature=sign_identity_dh_key(SEED, identity_dh_key=IDENTITY_DH_KEY),
    signed_prekey=SignedPrekey(
        id=1,
        key=SIGNED_PREKEY,
        signature=sign_signed_prekey(SEED, signed_prekey=SIGNED_PREKEY),
    ),
    one_time_prekeys=[
        OneTimePrekey(id=1, key=derive_x25519_public_key(fixed_key("one-time-prekey 1"))),
        OneTimePrekey(id=2, key=derive_x25519_public_key(fixed_key("one-time-prekey 2"))),
    ],
)


@pytest.mark.stand
async def test_bundle_of_the_fixed_identity_is_uploaded(
    relay_url: str, open_client: OpenClient
) -> None:
    owner = await open_client(relay_url)
    await owner.log_in(SEED)

    answer = await owner.ask(UPLOAD)

    assert answer == ServerFrame(bundle_stored=BundleStored(one_time_prekey_count=2))


@pytest.mark.stand_after_restart
async def test_bundle_uploaded_before_the_restart_is_fetched(open_client: OpenClient) -> None:
    stand_url = os.environ.get("RELAY_URL")
    if stand_url is None:
        pytest.skip("runs against the stand, after scripts/stand.sh restarted it")
    owner = await open_client(stand_url)

    logged_in = await owner.log_in(SEED)
    answer = await owner.ask(FetchBundle(identity=IDENTITY))

    assert logged_in.logged_in.one_time_prekey_count == 2
    assert answer == ServerFrame(
        bundle=Bundle(
            identity=IDENTITY,
            identity_dh_key=UPLOAD.identity_dh_key,
            identity_dh_signature=UPLOAD.identity_dh_signature,
            signed_prekey=UPLOAD.signed_prekey,
            one_time_prekey=UPLOAD.one_time_prekeys[0],
        )
    )
