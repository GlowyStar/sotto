"""The database of the relay: one connection for the process, one transaction per write."""

import logging
import sqlite3
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import NamedTuple

from sotto.crypto.identity import IdentityKeyMismatchError
from sotto.proto.sotto_pb2 import (
    Bundle,
    DeleteBlob,
    Deliver,
    FetchBlob,
    MessageRef,
    PutBlob,
    Send,
    SignedPrekey,
    StartBlob,
    UploadBundle,
)
from sotto.relay.frames import BLOB_CHUNK_BYTES

logger = logging.getLogger(__name__)

SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS identities (
        identity_key BLOB PRIMARY KEY,
        identity_dh_key BLOB NOT NULL,
        identity_dh_signature BLOB NOT NULL,
        signed_prekey_id INTEGER NOT NULL,
        signed_prekey BLOB NOT NULL,
        signed_prekey_signature BLOB NOT NULL
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE TABLE IF NOT EXISTS one_time_prekeys (
        position INTEGER PRIMARY KEY,
        identity_key BLOB NOT NULL,
        prekey_id INTEGER NOT NULL,
        public_key BLOB NOT NULL,
        UNIQUE (identity_key, prekey_id)
    ) STRICT
    """,
    # AUTOINCREMENT never gives a position out twice, so the cursor of a delivery that
    # passed the newest row cannot miss a row stored after that row was deleted.
    """
    CREATE TABLE IF NOT EXISTS messages (
        position INTEGER PRIMARY KEY AUTOINCREMENT,
        sender BLOB NOT NULL,
        recipient BLOB NOT NULL,
        message_id BLOB NOT NULL,
        payload BLOB NOT NULL,
        stored_at INTEGER NOT NULL,
        UNIQUE (sender, message_id)
    ) STRICT
    """,
    "CREATE INDEX IF NOT EXISTS messages_of_recipient ON messages (recipient, position)",
    # A blob of part 3 and its pieces, one row for the data of each PutBlob (section 31.8).
    """
    CREATE TABLE IF NOT EXISTS blobs (
        position INTEGER PRIMARY KEY,
        uploader BLOB NOT NULL,
        blob_id BLOB NOT NULL,
        recipient BLOB NOT NULL,
        length INTEGER NOT NULL,
        stored_length INTEGER NOT NULL,
        written_at INTEGER NOT NULL,
        UNIQUE (uploader, blob_id)
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS blob_chunks (
        blob INTEGER NOT NULL,
        offset INTEGER NOT NULL,
        data BLOB NOT NULL,
        PRIMARY KEY (blob, offset)
    ) STRICT
    """,
)

# The condition of the update is step 4.1 of docs/protocol.md, section 9.1: with another
# X25519 identity key stored the statement changes no row.
STORE_IDENTITY = """
    INSERT INTO identities VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT (identity_key) DO UPDATE SET
        signed_prekey_id = excluded.signed_prekey_id,
        signed_prekey = excluded.signed_prekey,
        signed_prekey_signature = excluded.signed_prekey_signature
    WHERE identity_dh_key = excluded.identity_dh_key
"""
STORE_ONE_TIME_PREKEY = """
    INSERT INTO one_time_prekeys (identity_key, prekey_id, public_key) VALUES (?, ?, ?)
    ON CONFLICT (identity_key, prekey_id) DO NOTHING
"""
COUNT_ONE_TIME_PREKEYS = "SELECT count(*) FROM one_time_prekeys WHERE identity_key = ?"
READ_IDENTITY = """
    SELECT identity_dh_key, identity_dh_signature,
           signed_prekey_id, signed_prekey, signed_prekey_signature
    FROM identities WHERE identity_key = ?
"""
TAKE_OLDEST_ONE_TIME_PREKEY = """
    DELETE FROM one_time_prekeys
    WHERE position = (SELECT min(position) FROM one_time_prekeys WHERE identity_key = ?)
    RETURNING prekey_id, public_key
"""
IS_REGISTERED = "SELECT 1 FROM identities WHERE identity_key = ?"
IS_MESSAGE_HELD = "SELECT 1 FROM messages WHERE sender = ? AND message_id = ?"
MEASURE_QUEUE = """
    SELECT count(*), coalesce(sum(length(payload)), 0) FROM messages WHERE recipient = ?
"""
STORE_MESSAGE = """
    INSERT INTO messages (sender, recipient, message_id, payload, stored_at)
    VALUES (?, ?, ?, ?, ?)
"""
READ_NEXT_MESSAGE = """
    SELECT position, sender, message_id, payload FROM messages
    WHERE recipient = ? AND position > ? ORDER BY position LIMIT 1
"""
DELETE_MESSAGE = "DELETE FROM messages WHERE recipient = ? AND sender = ? AND message_id = ?"
DELETE_EXPIRED_MESSAGES = "DELETE FROM messages WHERE stored_at <= ?"
READ_BLOB = """
    SELECT position, length, stored_length FROM blobs WHERE uploader = ? AND blob_id = ?
"""
MEASURE_BLOBS_OF_UPLOADER = "SELECT coalesce(sum(length), 0) FROM blobs WHERE uploader = ?"
STORE_BLOB = """
    INSERT INTO blobs (uploader, blob_id, recipient, length, stored_length, written_at)
    VALUES (?, ?, ?, ?, 0, ?)
"""
STORE_BLOB_CHUNK = "INSERT INTO blob_chunks (blob, offset, data) VALUES (?, ?, ?)"
STORE_BLOB_PROGRESS = "UPDATE blobs SET stored_length = ?, written_at = ? WHERE position = ?"
READ_COMPLETE_BLOB = """
    SELECT position FROM blobs
    WHERE uploader = ? AND blob_id = ? AND recipient = ? AND stored_length = length
"""
# A chunk is at most BLOB_CHUNK_BYTES long, so the first one that reaches into the range
# starts less than that before it: the read stays on the range in the primary key.
READ_BLOB_RANGE = """
    SELECT offset, data FROM blob_chunks
    WHERE blob = ? AND offset > ? AND offset < ? AND offset + length(data) > ?
    ORDER BY offset
"""
# The rule of docs/protocol.md, section 31.4: the uploader deletes its blob in any state,
# the recipient only a complete one.
DELETE_BLOB = """
    DELETE FROM blobs
    WHERE uploader = ? AND blob_id = ?
      AND (uploader = ? OR (recipient = ? AND stored_length = length))
    RETURNING position
"""
DELETE_EXPIRED_BLOBS = "DELETE FROM blobs WHERE written_at <= ? RETURNING position"
DELETE_BLOB_CHUNKS = "DELETE FROM blob_chunks WHERE blob = ?"
MEASURE_BLOBS = "SELECT coalesce(sum(stored_length), 0) FROM blobs"
READ_PAGE_COUNT = "PRAGMA page_count"
READ_PAGE_SIZE = "PRAGMA page_size"
# Copies the write-ahead log into the database file and truncates the log to zero length,
# which removes the old pages of deleted rows (docs/protocol.md, section 13.2).
CHECKPOINT = "PRAGMA wal_checkpoint(TRUNCATE)"


class StorageFullError(Exception):
    """A write needed a page above the ceiling of the database, or the disk is full."""


class UnknownRecipientError(Exception):
    """The recipient of a message is not registered."""


class QueueFullError(Exception):
    """The queue of the recipient is at one of its caps."""


class BlobTooLargeError(Exception):
    """A blob would be longer than the relay accepts, or a piece would end past its length."""


class QuotaFullError(Exception):
    """A new blob would take the blobs of its uploader over their quota."""


class BlobNotFoundError(Exception):
    """The relay holds no blob of the uploader with this blob id."""


class BlobStart(NamedTuple):
    stored_length: int
    is_new: bool


class BlobPut(NamedTuple):
    stored_length: int
    appended: int
    completes: bool


class Swept(NamedTuple):
    messages: int
    blobs: int


class Storage:
    """The one connection of the process to the database file, which is the whole state."""

    def __init__(
        self, path: Path, *, max_pages: int, clock: Callable[[], float] = time.time
    ) -> None:
        self.clock = clock
        self.connection = sqlite3.connect(path, autocommit=True)
        # The journal mode cannot change inside a transaction, so the pragmas run first.
        journal_mode = self.connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute("PRAGMA secure_delete=ON")
        ceiling = self.connection.execute(f"PRAGMA max_page_count={max_pages:d}").fetchone()[0]

        with self._write():
            for statement in SCHEMA:
                self.connection.execute(statement)

        logger.info(
            "database open: SQLite %s, journal mode %s, ceiling %d pages",
            sqlite3.sqlite_version,
            journal_mode,
            ceiling,
        )

    def close(self) -> None:
        """Closes the connection; as the last one of the file it removes the -wal file."""
        self.connection.close()

    def count_one_time_prekeys(self, identity_key: bytes) -> int:
        row = self.connection.execute(COUNT_ONE_TIME_PREKEYS, (identity_key,)).fetchone()
        count: int = row[0]
        return count

    def store_bundle(self, identity_key: bytes, upload: UploadBundle, *, cap: int) -> int:
        """Runs step 4 of docs/protocol.md, section 9.1, and returns the count of step 5.

        Raises:
            IdentityKeyMismatchError: Another X25519 identity key is stored for the identity.
            StorageFullError: The database is at its page ceiling.
        """
        signed_prekey = upload.signed_prekey
        identity_row = (
            identity_key,
            upload.identity_dh_key,
            upload.identity_dh_signature,
            signed_prekey.id,
            signed_prekey.key,
            signed_prekey.signature,
        )

        with self._write():
            if self.connection.execute(STORE_IDENTITY, identity_row).rowcount == 0:
                raise IdentityKeyMismatchError(
                    "the identity has another X25519 identity key stored"
                )

            count = self.count_one_time_prekeys(identity_key)
            for prekey in upload.one_time_prekeys:
                if count >= cap:
                    break
                stored = self.connection.execute(
                    STORE_ONE_TIME_PREKEY, (identity_key, prekey.id, prekey.key)
                )
                count += stored.rowcount
        return count

    def fetch_bundle(self, identity: bytes) -> Bundle | None:
        """Returns the bundle of an identity with the one-time prekey that was stored first.

        The prekey is deleted in the transaction that reads the bundle. When that
        transaction cannot be written, the bundle comes without a one-time prekey and the
        stored ones stay. The result is None for an identity that is not registered.
        """
        try:
            with self._write():
                bundle = self.read_bundle(identity)
                taken = self.connection.execute(TAKE_OLDEST_ONE_TIME_PREKEY, (identity,))
                one_time_prekey = taken.fetchone()
        except StorageFullError:
            return self.read_bundle(identity)

        if bundle is not None and one_time_prekey is not None:
            bundle.one_time_prekey.id, bundle.one_time_prekey.key = one_time_prekey
        return bundle

    def store_message(
        self, sender: bytes, send: Send, *, max_messages: int, max_bytes: int
    ) -> bool:
        """Runs steps 2 to 5 of docs/protocol.md, section 10.2, in one transaction.

        A message that the relay holds under the sender and the message id stays as it is.
        Returns whether the message was stored now.

        Raises:
            UnknownRecipientError: The recipient is not registered.
            QueueFullError: The queue of the recipient is at one of its caps.
            StorageFullError: The database is at its page ceiling.
        """
        with self._write():
            if self.connection.execute(IS_MESSAGE_HELD, (sender, send.message_id)).fetchone():
                return False
            if self.connection.execute(IS_REGISTERED, (send.recipient,)).fetchone() is None:
                raise UnknownRecipientError("the recipient is not registered")

            count, size = self.connection.execute(MEASURE_QUEUE, (send.recipient,)).fetchone()
            is_at_count_cap = count >= max_messages
            would_pass_bytes_cap = size + len(send.payload) > max_bytes
            if is_at_count_cap or would_pass_bytes_cap:
                raise QueueFullError("the queue of the recipient is full")

            row = (sender, send.recipient, send.message_id, send.payload, int(self.clock()))
            self.connection.execute(STORE_MESSAGE, row)
        return True

    def next_message(self, recipient: bytes, *, after: int) -> tuple[int, Deliver] | None:
        """Returns the message of the queue that was stored first after the position `after`.

        The result is the position of the message and its Deliver, or None for a queue that
        holds nothing after `after`.
        """
        row = self.connection.execute(READ_NEXT_MESSAGE, (recipient, after)).fetchone()
        if row is None:
            return None

        position, sender, message_id, payload = row
        return position, Deliver(message_id=message_id, sender=sender, payload=payload)

    def delete_messages(self, recipient: bytes, messages: Iterable[MessageRef]) -> int:
        """Deletes the messages of the queue of `recipient` that the pairs name.

        A pair that names no message of this queue changes nothing. Returns the count of
        the deleted messages.
        """
        rows = [(recipient, message.sender, message.message_id) for message in messages]
        with self._write():
            deleted = self.connection.executemany(DELETE_MESSAGE, rows)
        return deleted.rowcount

    def start_blob(
        self, uploader: bytes, start: StartBlob, *, max_bytes: int, quota_bytes: int
    ) -> BlobStart:
        """Runs steps 2 to 6 of docs/protocol.md, section 31.1, in one transaction.

        A blob that the relay holds under the uploader and the blob id stays as it is, and
        the result carries its stored length.

        Raises:
            BlobTooLargeError: The length is more than `max_bytes`.
            UnknownRecipientError: The recipient is not registered.
            QuotaFullError: The blobs of the uploader would take more than `quota_bytes`.
            StorageFullError: The database is at its page ceiling.
        """
        with self._write():
            held = self.connection.execute(READ_BLOB, (uploader, start.blob_id)).fetchone()
            if held is not None:
                return BlobStart(stored_length=held[2], is_new=False)
            if start.length > max_bytes:
                raise BlobTooLargeError("the blob is longer than the relay accepts")
            if self.connection.execute(IS_REGISTERED, (start.recipient,)).fetchone() is None:
                raise UnknownRecipientError("the recipient is not registered")

            quota_used = self.connection.execute(MEASURE_BLOBS_OF_UPLOADER, (uploader,))
            if quota_used.fetchone()[0] + start.length > quota_bytes:
                raise QuotaFullError("the blobs of the uploader would pass the quota")

            row = (uploader, start.blob_id, start.recipient, start.length, int(self.clock()))
            self.connection.execute(STORE_BLOB, row)
        return BlobStart(stored_length=0, is_new=True)

    def put_blob(self, uploader: bytes, put: PutBlob) -> BlobPut:
        """Runs steps 1 to 4 of docs/protocol.md, section 31.2, in one transaction.

        A piece whose offset is not the stored length stores nothing, and the result
        carries the stored length.

        Raises:
            BlobNotFoundError: The relay holds no blob of the uploader with this blob id.
            BlobTooLargeError: The piece would end past the length of the blob.
            StorageFullError: The database is at its page ceiling.
        """
        with self._write():
            held = self.connection.execute(READ_BLOB, (uploader, put.blob_id)).fetchone()
            if held is None:
                raise BlobNotFoundError("the uploader holds no blob with this id")
            position, length, stored_length = held
            if put.offset != stored_length:
                return BlobPut(stored_length=stored_length, appended=0, completes=False)

            new_length = put.offset + len(put.data)
            if new_length > length:
                raise BlobTooLargeError("the piece ends past the length of the blob")
            self.connection.execute(STORE_BLOB_CHUNK, (position, put.offset, put.data))
            progress = (new_length, int(self.clock()), position)
            self.connection.execute(STORE_BLOB_PROGRESS, progress)
        return BlobPut(
            stored_length=new_length, appended=len(put.data), completes=new_length == length
        )

    def fetch_blob(self, recipient: bytes, fetch: FetchBlob) -> bytes | None:
        """Returns the range of a complete blob of `recipient` (docs/protocol.md, 31.3).

        The result is empty from the end of the blob on, and None when the relay holds no
        complete blob with this uploader and blob id for this recipient.
        """
        key = (fetch.uploader, fetch.blob_id, recipient)
        row = self.connection.execute(READ_COMPLETE_BLOB, key).fetchone()
        if row is None:
            return None

        end = fetch.offset + fetch.length
        bounds = (row[0], fetch.offset - BLOB_CHUNK_BYTES, end, fetch.offset)
        chunks = self.connection.execute(READ_BLOB_RANGE, bounds).fetchall()
        if not chunks:
            return b""
        first_offset = chunks[0][0]
        joined = b"".join(data for _, data in chunks)
        return joined[fetch.offset - first_offset : end - first_offset]

    def delete_blob(self, identity: bytes, delete: DeleteBlob) -> bool:
        """Deletes the blob that `identity` may delete by docs/protocol.md, section 31.4.

        Returns whether a blob was deleted; a pair that names none changes nothing.
        """
        names = (delete.uploader, delete.blob_id, identity, identity)
        with self._write():
            deleted = self.connection.execute(DELETE_BLOB, names).fetchall()
            self.connection.executemany(DELETE_BLOB_CHUNKS, deleted)
        return bool(deleted)

    def blob_bytes(self) -> int:
        """Returns the stored lengths of all blobs, added up."""
        total: int = self.connection.execute(MEASURE_BLOBS).fetchone()[0]
        return total

    def sweep(self, *, ttl_seconds: int, blob_ttl_seconds: int) -> Swept:
        """Deletes what expired, then truncates the log (docs/protocol.md, 13.2 and 31.5).

        A message expires `ttl_seconds` after it was stored, a blob `blob_ttl_seconds`
        after its last write. Returns the counts of what was deleted.
        """
        now = int(self.clock())
        with self._write():
            expired = self.connection.execute(DELETE_EXPIRED_MESSAGES, (now - ttl_seconds,))
            expired_blobs = self.connection.execute(
                DELETE_EXPIRED_BLOBS, (now - blob_ttl_seconds,)
            ).fetchall()
            self.connection.executemany(DELETE_BLOB_CHUNKS, expired_blobs)
        is_busy, _, _ = self.connection.execute(CHECKPOINT).fetchone()
        if is_busy:
            logger.warning("the checkpoint of the sweep did not finish")
        return Swept(messages=expired.rowcount, blobs=len(expired_blobs))

    def size_bytes(self) -> int:
        page_count: int = self.connection.execute(READ_PAGE_COUNT).fetchone()[0]
        page_size: int = self.connection.execute(READ_PAGE_SIZE).fetchone()[0]
        return page_count * page_size

    def read_bundle(self, identity: bytes) -> Bundle | None:
        """Returns the bundle of an identity without a one-time prekey, None when unknown."""
        row = self.connection.execute(READ_IDENTITY, (identity,)).fetchone()
        if row is None:
            return None

        identity_dh_key, identity_dh_signature, prekey_id, prekey, prekey_signature = row
        return Bundle(
            identity=identity,
            identity_dh_key=identity_dh_key,
            identity_dh_signature=identity_dh_signature,
            signed_prekey=SignedPrekey(id=prekey_id, key=prekey, signature=prekey_signature),
        )

    @contextmanager
    def _write(self) -> Iterator[None]:
        """Runs the block as one write transaction and rolls it back when it fails.

        Raises:
            StorageFullError: The database is at its page ceiling.
        """
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.connection.execute("COMMIT")
        except sqlite3.OperationalError as error:
            if error.sqlite_errorcode != sqlite3.SQLITE_FULL:
                raise
            # The exception reaches no log line with its text, so the cause gets one here.
            logger.warning("the database is full")
            raise StorageFullError from error
        finally:
            # SQLite rolls a transaction back by itself on some failures, a full database
            # among them, and a ROLLBACK without a transaction is an error.
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
