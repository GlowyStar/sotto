"""What outlives a restart of the stand: scripts/stand.sh runs the two markers in turn."""

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
    BlobStored,
    Bundle,
    BundleStored,
    ClientFrame,
    DeleteBlob,
    Deliver,
    Error,
    ErrorCode,
    FetchBlob,
    FetchBundle,
    OneTimePrekey,
    PutBlob,
    Send,
    ServerFrame,
    SignedPrekey,
    StartBlob,
    Stored,
    UploadBundle,
)
from sotto.relay.frames import BLOB_CHUNK_BYTES


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


RECIPIENT_SEED = fixed_key("recipient")
RECIPIENT_DH_KEY = derive_x25519_public_key(fixed_key("recipient identity-dh"))
RECIPIENT_PREKEY = derive_x25519_public_key(fixed_key("recipient signed-prekey"))
RECIPIENT_UPLOAD = UploadBundle(
    identity_dh_key=RECIPIENT_DH_KEY,
    identity_dh_signature=sign_identity_dh_key(
        RECIPIENT_SEED,
        identity_dh_key=RECIPIENT_DH_KEY,
    ),
    signed_prekey=SignedPrekey(
        id=1,
        key=RECIPIENT_PREKEY,
        signature=sign_signed_prekey(RECIPIENT_SEED, signed_prekey=RECIPIENT_PREKEY),
    ),
)
SENDER_SEED = fixed_key("sender")
SEND = Send(
    message_id=fixed_key("message id")[:16],
    recipient=derive_identity_key(RECIPIENT_SEED),
    payload=fixed_key("payload"),
)


@pytest.mark.stand
async def test_message_to_the_fixed_recipient_is_stored(
    relay_url: str, open_client: OpenClient
) -> None:
    recipient = await open_client(relay_url)
    await recipient.log_in(RECIPIENT_SEED)
    registered = await recipient.ask(RECIPIENT_UPLOAD)
    await recipient.websocket.close()
    sender = await open_client(relay_url)
    await sender.log_in(SENDER_SEED)

    answer = await sender.ask(SEND)

    assert registered.WhichOneof("frame") == "bundle_stored"
    assert answer == ServerFrame(stored=Stored(message_id=SEND.message_id))


@pytest.mark.stand_after_restart
async def test_message_stored_before_the_restart_is_delivered(open_client: OpenClient) -> None:
    stand_url = os.environ.get("RELAY_URL")
    if stand_url is None:
        pytest.skip("runs against the stand, after scripts/stand.sh restarted it")
    recipient = await open_client(stand_url)

    await recipient.log_in(RECIPIENT_SEED)
    delivery = await recipient.receive()

    assert delivery == ServerFrame(
        deliver=Deliver(
            message_id=SEND.message_id,
            sender=derive_identity_key(SENDER_SEED),
            payload=SEND.payload,
        )
    )


BLOB_RECIPIENT_SEED = fixed_key("blob recipient")
BLOB_RECIPIENT_DH_KEY = derive_x25519_public_key(fixed_key("blob recipient identity-dh"))
BLOB_RECIPIENT_PREKEY = derive_x25519_public_key(fixed_key("blob recipient signed-prekey"))
BLOB_RECIPIENT_UPLOAD = UploadBundle(
    identity_dh_key=BLOB_RECIPIENT_DH_KEY,
    identity_dh_signature=sign_identity_dh_key(
        BLOB_RECIPIENT_SEED, identity_dh_key=BLOB_RECIPIENT_DH_KEY
    ),
    signed_prekey=SignedPrekey(
        id=1,
        key=BLOB_RECIPIENT_PREKEY,
        signature=sign_signed_prekey(BLOB_RECIPIENT_SEED, signed_prekey=BLOB_RECIPIENT_PREKEY),
    ),
)
BLOB_UPLOADER_SEED = fixed_key("blob uploader")
BLOB = hashlib.shake_256(b"sotto stand restart blob").digest(2 * BLOB_CHUNK_BYTES + 1000)
START_BLOB = StartBlob(
    blob_id=fixed_key("blob id")[:16],
    recipient=derive_identity_key(BLOB_RECIPIENT_SEED),
    length=len(BLOB),
)
PIECES = [
    PutBlob(
        blob_id=START_BLOB.blob_id,
        offset=offset,
        data=BLOB[offset : offset + BLOB_CHUNK_BYTES],
    )
    for offset in range(0, len(BLOB), BLOB_CHUNK_BYTES)
]


def blob_stored(stored_length: int) -> ServerFrame:
    return ServerFrame(
        blob_stored=BlobStored(blob_id=START_BLOB.blob_id, stored_length=stored_length)
    )


@pytest.mark.stand
async def test_first_piece_of_the_fixed_blob_is_stored(
    relay_url: str, open_client: OpenClient
) -> None:
    recipient = await open_client(relay_url)
    await recipient.log_in(BLOB_RECIPIENT_SEED)
    registered = await recipient.ask(BLOB_RECIPIENT_UPLOAD)
    uploader = await open_client(relay_url)
    await uploader.log_in(BLOB_UPLOADER_SEED)

    started = await uploader.ask(START_BLOB)
    first = await uploader.ask(PIECES[0])

    assert registered.WhichOneof("frame") == "bundle_stored"
    assert started == blob_stored(0)
    assert first == blob_stored(BLOB_CHUNK_BYTES)


@pytest.mark.stand_after_restart
async def test_upload_of_the_fixed_blob_goes_on_after_the_restart(
    open_client: OpenClient,
) -> None:
    stand_url = os.environ.get("RELAY_URL")
    if stand_url is None:
        pytest.skip("runs against the stand, after scripts/stand.sh restarted it")
    uploader = await open_client(stand_url)
    await uploader.log_in(BLOB_UPLOADER_SEED)
    recipient = await open_client(stand_url)
    await recipient.log_in(BLOB_RECIPIENT_SEED)
    uploader_key = derive_identity_key(BLOB_UPLOADER_SEED)

    resumed = await uploader.ask(START_BLOB)
    rest = [await uploader.ask(piece) for piece in PIECES[1:]]
    fetched = b""
    for offset in range(0, len(BLOB), BLOB_CHUNK_BYTES):
        fetch = FetchBlob(
            blob_id=START_BLOB.blob_id,
            uploader=uploader_key,
            offset=offset,
            length=BLOB_CHUNK_BYTES,
        )
        fetched += (await recipient.ask(fetch)).blob_data.data
    delete = DeleteBlob(blob_id=START_BLOB.blob_id, uploader=uploader_key)
    await recipient.send(ClientFrame(delete_blob=delete))
    after_the_delete = await recipient.ask(
        FetchBlob(
            blob_id=START_BLOB.blob_id,
            uploader=uploader_key,
            offset=0,
            length=BLOB_CHUNK_BYTES,
        )
    )

    assert resumed == blob_stored(BLOB_CHUNK_BYTES)
    assert rest[-1] == blob_stored(len(BLOB))
    assert fetched == BLOB
    assert after_the_delete == ServerFrame(
        error=Error(
            code=ErrorCode.NOT_FOUND, blob_id=START_BLOB.blob_id, identity=uploader_key
        )
    )
