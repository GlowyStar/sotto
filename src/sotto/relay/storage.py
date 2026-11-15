"""The database of the relay: one connection for the process, one transaction per write."""

import logging
import sqlite3
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

from sotto.crypto.identity import IdentityKeyMismatchError
from sotto.proto.sotto_pb2 import Bundle, Deliver, MessageRef, Send, SignedPrekey, UploadBundle

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
STORE_MESSAGE = """
    INSERT INTO messages (sender, recipient, message_id, payload, stored_at)
    VALUES (?, ?, ?, ?, ?)
"""
READ_NEXT_MESSAGE = """
    SELECT position, sender, message_id, payload FROM messages
    WHERE recipient = ? AND position > ? ORDER BY position LIMIT 1
"""
DELETE_MESSAGE = "DELETE FROM messages WHERE recipient = ? AND sender = ? AND message_id = ?"


class StorageFullError(Exception):
    """A write needed a page above the ceiling of the database, or the disk is full."""


class UnknownRecipientError(Exception):
    """The recipient of a message is not registered."""


class Storage:
    """The one connection of the process to the database file, which is the whole state."""

    def __init__(self, path: Path, *, max_pages: int) -> None:
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
                bundle = self._read_bundle(identity)
                taken = self.connection.execute(TAKE_OLDEST_ONE_TIME_PREKEY, (identity,))
                one_time_prekey = taken.fetchone()
        except StorageFullError:
            return self._read_bundle(identity)

        if bundle is not None and one_time_prekey is not None:
            bundle.one_time_prekey.id, bundle.one_time_prekey.key = one_time_prekey
        return bundle

    def store_message(self, sender: bytes, send: Send) -> None:
        """Runs steps 2, 3 and 5 of docs/protocol.md, section 10.2, in one transaction.

        A message that the relay holds under the sender and the message id stays as it is.

        Raises:
            UnknownRecipientError: The recipient is not registered.
            StorageFullError: The database is at its page ceiling.
        """
        with self._write():
            if self.connection.execute(IS_MESSAGE_HELD, (sender, send.message_id)).fetchone():
                return
            if self.connection.execute(IS_REGISTERED, (send.recipient,)).fetchone() is None:
                raise UnknownRecipientError("the recipient is not registered")

            row = (sender, send.recipient, send.message_id, send.payload, int(time.time()))
            self.connection.execute(STORE_MESSAGE, row)

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

    def delete_messages(self, recipient: bytes, messages: Iterable[MessageRef]) -> None:
        """Deletes the messages of the queue of `recipient` that the pairs name.

        A pair that names no message of this queue changes nothing.
        """
        rows = [(recipient, message.sender, message.message_id) for message in messages]
        with self._write():
            self.connection.executemany(DELETE_MESSAGE, rows)

    def _read_bundle(self, identity: bytes) -> Bundle | None:
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
