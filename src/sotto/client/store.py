"""The client store of docs/protocol.md, section 22: one SQLite file per identity."""

import json
import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sotto.crypto.ratchet import RatchetState, SkippedKey
from sotto.proto.sotto_pb2 import Attachment

DIRECTORY_MODE = 0o700
FILE_MODE = 0o600
WIDER_THAN_OWNER = 0o077
MAX_SESSIONS = 3
LAST_PREKEY_ID = 2**32 - 1

TABLES = (
    """
    CREATE TABLE IF NOT EXISTS identity (
        only_row INTEGER PRIMARY KEY CHECK (only_row = 1),
        seed BLOB NOT NULL,
        identity_dh_private_key BLOB NOT NULL,
        last_signed_prekey_id INTEGER NOT NULL,
        last_one_time_prekey_id INTEGER NOT NULL
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS signed_prekeys (
        prekey_id INTEGER PRIMARY KEY,
        private_key BLOB NOT NULL,
        made_at INTEGER NOT NULL,
        replaced_at INTEGER,
        confirmed INTEGER NOT NULL
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS one_time_prekeys (
        prekey_id INTEGER PRIMARY KEY,
        private_key BLOB NOT NULL
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS contacts (
        identity_key BLOB PRIMARY KEY,
        pinned_identity_dh_key BLOB,
        name TEXT UNIQUE
    ) STRICT, WITHOUT ROWID
    """,
    # AUTOINCREMENT because a record keeps the id of a session that is gone, and no later
    # session may take that id.
    """
    CREATE TABLE IF NOT EXISTS sessions (
        session_id INTEGER PRIMARY KEY AUTOINCREMENT,
        contact BLOB NOT NULL,
        position INTEGER NOT NULL,
        associated_data BLOB NOT NULL,
        state TEXT NOT NULL,
        initial_header BLOB
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS records (
        sender BLOB NOT NULL,
        ephemeral_key BLOB NOT NULL,
        session_id INTEGER NOT NULL,
        signed_prekey_id INTEGER NOT NULL,
        PRIMARY KEY (sender, ephemeral_key)
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE TABLE IF NOT EXISTS seen_ids (
        sender BLOB NOT NULL,
        message_id BLOB NOT NULL,
        seen_at INTEGER NOT NULL,
        PRIMARY KEY (sender, message_id)
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE TABLE IF NOT EXISTS outbox (
        position INTEGER PRIMARY KEY,
        message_id BLOB NOT NULL UNIQUE,
        recipient BLOB NOT NULL,
        payload BLOB NOT NULL
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS messages (
        position INTEGER PRIMARY KEY,
        contact BLOB NOT NULL,
        direction TEXT NOT NULL CHECK (direction IN ('in', 'out')),
        message_id BLOB NOT NULL,
        text TEXT NOT NULL
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS uploads (
        position INTEGER PRIMARY KEY,
        blob_id BLOB NOT NULL UNIQUE,
        contact BLOB NOT NULL,
        attachment BLOB NOT NULL,
        blob BLOB NOT NULL
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS files (
        position INTEGER PRIMARY KEY,
        contact BLOB NOT NULL,
        direction TEXT NOT NULL CHECK (direction IN ('in', 'out')),
        message_id BLOB NOT NULL,
        attachment BLOB NOT NULL,
        state TEXT NOT NULL,
        held INTEGER NOT NULL DEFAULT 0,
        saved_as TEXT
    ) STRICT
    """,
    # Apart from `files`, so that counting a piece in `held` does not rewrite the blob.
    """
    CREATE TABLE IF NOT EXISTS downloads (
        position INTEGER PRIMARY KEY,
        bytes BLOB NOT NULL
    ) STRICT
    """,
    """
    CREATE TABLE IF NOT EXISTS blob_deletions (
        uploader BLOB NOT NULL,
        blob_id BLOB NOT NULL,
        PRIMARY KEY (uploader, blob_id)
    ) STRICT, WITHOUT ROWID
    """,
    """
    CREATE TABLE IF NOT EXISTS own_profile (
        only_row INTEGER PRIMARY KEY CHECK (only_row = 1),
        name TEXT NOT NULL,
        avatar BLOB,
        media_type TEXT NOT NULL
    ) STRICT
    """,
    # The latest profile of each contact; `avatar_file` is the row of `files` that
    # carries its avatar, which is no attachment of the message log.
    """
    CREATE TABLE IF NOT EXISTS profiles (
        contact BLOB PRIMARY KEY,
        name TEXT NOT NULL,
        avatar_file INTEGER UNIQUE,
        avatar BLOB
    ) STRICT, WITHOUT ROWID
    """,
    # The contacts owed the own profile; `blob_id` names the upload of its avatar.
    """
    CREATE TABLE IF NOT EXISTS profile_sends (
        contact BLOB PRIMARY KEY,
        blob_id BLOB UNIQUE
    ) STRICT, WITHOUT ROWID
    """,
)

ADD_SESSION = """
    INSERT INTO sessions (contact, position, associated_data, state, initial_header)
    VALUES (?, (SELECT coalesce(max(position), 0) + 1 FROM sessions), ?, ?, ?)
    RETURNING session_id
"""
COUNT_SKIPPED_KEYS_BEHIND = """
    SELECT coalesce(sum(json_array_length(state, '$.mkskipped')), 0) FROM sessions
    WHERE contact = ? AND session_id NOT IN (
        SELECT session_id FROM sessions WHERE contact = ? ORDER BY position DESC LIMIT ?
    )
"""
DROP_SESSIONS_BEHIND = """
    DELETE FROM sessions WHERE contact = ? AND session_id NOT IN (
        SELECT session_id FROM sessions WHERE contact = ? ORDER BY position DESC LIMIT ?
    )
"""
# A record outlives its session until the private key of its signed prekey is deleted
# (section 20.4).
DELETE_ORPHAN_RECORDS = """
    DELETE FROM records
    WHERE session_id NOT IN (SELECT session_id FROM sessions)
        AND signed_prekey_id NOT IN (SELECT prekey_id FROM signed_prekeys)
"""
ACCEPT_ON_SESSION = """
    UPDATE sessions SET
        state = ?,
        initial_header = NULL,
        position = (SELECT max(position) + 1 FROM sessions)
    WHERE session_id = ?
"""
READ_SESSIONS = """
    SELECT session_id, contact, associated_data, state, initial_header FROM sessions
    WHERE contact = ? ORDER BY position DESC
"""
READ_SESSION = """
    SELECT session_id, contact, associated_data, state, initial_header FROM sessions
    WHERE session_id = ?
"""
READ_SIGNED_PREKEY = """
    SELECT private_key FROM signed_prekeys
    WHERE prekey_id = ? AND (replaced_at IS NULL OR replaced_at > ?)
"""
READ_NEWEST_SIGNED_PREKEY = """
    SELECT prekey_id, private_key, made_at, confirmed FROM signed_prekeys
    WHERE replaced_at IS NULL
"""
READ_ONE_TIME_PREKEY = "SELECT private_key FROM one_time_prekeys WHERE prekey_id = ?"
COUNT_SIGNED_PREKEY = """
    UPDATE identity SET last_signed_prekey_id = last_signed_prekey_id + 1
    WHERE last_signed_prekey_id < ? RETURNING last_signed_prekey_id
"""
COUNT_ONE_TIME_PREKEY = """
    UPDATE identity SET last_one_time_prekey_id = last_one_time_prekey_id + 1
    WHERE last_one_time_prekey_id < ? RETURNING last_one_time_prekey_id
"""
DELETE_LOWEST_ONE_TIME_PREKEYS = """
    DELETE FROM one_time_prekeys WHERE prekey_id IN (
        SELECT prekey_id FROM one_time_prekeys ORDER BY prekey_id LIMIT ?
    )
"""

READ_FILES = """
    SELECT position, contact, direction, message_id, attachment, state, held, saved_as,
        position IN (SELECT avatar_file FROM profiles WHERE avatar_file IS NOT NULL)
    FROM files ORDER BY position
"""
READ_FILE = """
    SELECT position, contact, direction, message_id, attachment, state, held, saved_as,
        position IN (SELECT avatar_file FROM profiles WHERE avatar_file IS NOT NULL)
    FROM files WHERE position = ?
"""
READ_FILE_OF_MESSAGE = """
    SELECT position, contact, direction, message_id, attachment, state, held, saved_as,
        position IN (SELECT avatar_file FROM profiles WHERE avatar_file IS NOT NULL)
    FROM files WHERE direction = 'out' AND message_id = ?
"""
READ_UPLOADS = """
    SELECT blob_id, contact, attachment, length(blob),
        blob_id IN (SELECT blob_id FROM profile_sends WHERE blob_id IS NOT NULL)
    FROM uploads ORDER BY position
"""
SET_OWN_PROFILE = """
    INSERT INTO own_profile VALUES (1, ?, ?, ?)
    ON CONFLICT DO UPDATE SET
        name = excluded.name, avatar = excluded.avatar, media_type = excluded.media_type
"""
SET_PROFILE = """
    INSERT INTO profiles VALUES (?, ?, ?, NULL)
    ON CONFLICT DO UPDATE SET
        name = excluded.name, avatar_file = excluded.avatar_file, avatar = NULL
"""


class StoreModeError(Exception):
    """The directory or the file of the store gives a right to the group or to others."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Identity:
    seed: bytes = field(repr=False)
    identity_dh_private_key: bytes = field(repr=False)


@dataclass(frozen=True, slots=True, kw_only=True)
class StoredSignedPrekey:
    prekey_id: int
    private_key: bytes = field(repr=False)
    made_at: int
    confirmed: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class StoredSession:
    session_id: int
    contact: bytes
    associated_data: bytes
    state: RatchetState
    initial_header: bytes | None


@dataclass(frozen=True, slots=True, kw_only=True)
class Record:
    session_id: int
    signed_prekey_id: int


@dataclass(frozen=True, slots=True, kw_only=True)
class OutboxRow:
    message_id: bytes
    recipient: bytes
    payload: bytes


@dataclass(frozen=True, slots=True, kw_only=True)
class UploadRow:
    blob_id: bytes
    contact: bytes
    attachment: Attachment
    length: int
    profile: bool = False


@dataclass(frozen=True, slots=True, kw_only=True)
class FileRow:
    """An attachment of the message log, sent or received."""

    position: int
    contact: bytes
    incoming: bool
    message_id: bytes
    attachment: Attachment
    state: str
    held: int
    saved_as: str | None
    avatar: bool = False


@dataclass(frozen=True, slots=True, kw_only=True)
class OwnProfile:
    name: str = ""
    avatar: bytes | None = field(default=None, repr=False)
    media_type: str = ""

    @property
    def is_empty(self) -> bool:
        return not self.name and self.avatar is None


@dataclass(frozen=True, slots=True, kw_only=True)
class ContactProfile:
    """The latest profile of a contact; `avatar` is None until the avatar is received."""

    name: str
    avatar_file: int | None
    avatar: bytes | None = field(repr=False)


class Store:
    """The one connection to the file of one identity; every write runs in `transaction`."""

    def __init__(self, path: Path) -> None:
        """Opens the store at `path`, making its directory and its file when they are missing.

        Raises:
            StoreModeError: The directory or the file has a mode with one of the bits 077.
        """
        _make_private_directory(path.parent)
        _make_private_file(path)
        self.connection = sqlite3.connect(path, autocommit=True)
        self.connection.execute("PRAGMA journal_mode=DELETE")
        self.connection.execute("PRAGMA secure_delete=ON")

        with self.transaction():
            for table in TABLES:
                self.connection.execute(table)

    def close(self) -> None:
        self.connection.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Runs the block as one write transaction and rolls it back when it fails."""
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.connection.execute("COMMIT")
        finally:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")

    def identity(self) -> Identity | None:
        row = self.connection.execute(
            "SELECT seed, identity_dh_private_key FROM identity"
        ).fetchone()
        if row is None:
            return None
        return Identity(seed=row[0], identity_dh_private_key=row[1])

    def is_contact(self, identity_key: bytes) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM contacts WHERE identity_key = ?", (identity_key,)
        ).fetchone()
        return row is not None

    def pin(self, contact: bytes) -> bytes | None:
        row = self.connection.execute(
            "SELECT pinned_identity_dh_key FROM contacts WHERE identity_key = ?", (contact,)
        ).fetchone()
        if row is None:
            return None
        pinned: bytes | None = row[0]
        return pinned

    def signed_prekey(self, prekey_id: int, *, replaced_after: int) -> bytes | None:
        """The private key of a signed prekey that is the newest or was replaced after the
        given time; any other counts as not held (section 21.2)."""
        row = self.connection.execute(
            READ_SIGNED_PREKEY, (prekey_id, replaced_after)
        ).fetchone()
        return None if row is None else bytes(row[0])

    def newest_signed_prekey(self) -> StoredSignedPrekey | None:
        row = self.connection.execute(READ_NEWEST_SIGNED_PREKEY).fetchone()
        if row is None:
            return None
        prekey_id, private_key, made_at, confirmed = row
        return StoredSignedPrekey(
            prekey_id=prekey_id,
            private_key=private_key,
            made_at=made_at,
            confirmed=confirmed == 1,
        )

    def one_time_prekey_ids_left(self) -> int:
        """The ids that the counter of one-time prekeys can still give (section 21.1)."""
        last_id: int = self.connection.execute(
            "SELECT last_one_time_prekey_id FROM identity"
        ).fetchone()[0]
        return LAST_PREKEY_ID - last_id

    def one_time_prekey_count(self) -> int:
        count: int = self.connection.execute(
            "SELECT count(*) FROM one_time_prekeys"
        ).fetchone()[0]
        return count

    def one_time_prekey(self, prekey_id: int) -> bytes | None:
        row = self.connection.execute(READ_ONE_TIME_PREKEY, (prekey_id,)).fetchone()
        return None if row is None else bytes(row[0])

    def sessions(self, contact: bytes) -> list[StoredSession]:
        """Returns the session list of a contact, its head first."""
        rows = self.connection.execute(READ_SESSIONS, (contact,)).fetchall()
        return [_session(row) for row in rows]

    def session(self, session_id: int) -> StoredSession | None:
        row = self.connection.execute(READ_SESSION, (session_id,)).fetchone()
        return None if row is None else _session(row)

    def record(self, sender: bytes, ephemeral_key: bytes) -> Record | None:
        row = self.connection.execute(
            "SELECT session_id, signed_prekey_id FROM records "
            "WHERE sender = ? AND ephemeral_key = ?",
            (sender, ephemeral_key),
        ).fetchone()
        return None if row is None else Record(session_id=row[0], signed_prekey_id=row[1])

    def is_seen(self, sender: bytes, message_id: bytes) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM seen_ids WHERE sender = ? AND message_id = ?", (sender, message_id)
        ).fetchone()
        return row is not None

    def outbox(self) -> list[OutboxRow]:
        rows = self.connection.execute(
            "SELECT message_id, recipient, payload FROM outbox ORDER BY position"
        ).fetchall()
        return [OutboxRow(message_id=row[0], recipient=row[1], payload=row[2]) for row in rows]

    def save_identity(self, identity: Identity) -> None:
        self._change(
            "INSERT INTO identity VALUES (1, ?, ?, 0, 0)",
            (identity.seed, identity.identity_dh_private_key),
        )

    def add_signed_prekey(self, private_key: bytes, *, made_at: int) -> int | None:
        """Saves the newest signed prekey under the next id of its counter (section 21.1)
        and marks the one it replaces; None, and nothing saved, once the counter is at
        LAST_PREKEY_ID."""
        counted = self._change(COUNT_SIGNED_PREKEY, (LAST_PREKEY_ID,)).fetchone()
        if counted is None:
            return None
        prekey_id: int = counted[0]
        self._change(
            "UPDATE signed_prekeys SET replaced_at = ? WHERE replaced_at IS NULL", (made_at,)
        )
        self._change(
            "INSERT INTO signed_prekeys VALUES (?, ?, ?, NULL, 0)",
            (prekey_id, private_key, made_at),
        )
        return prekey_id

    def confirm_signed_prekey(self, prekey_id: int) -> None:
        self._change(
            "UPDATE signed_prekeys SET confirmed = 1 WHERE prekey_id = ?", (prekey_id,)
        )

    def delete_signed_prekeys(self, *, replaced_at_or_before: int) -> None:
        """Deletes the signed prekeys replaced at or before the time, with the records that
        name them and whose session is gone (section 21.2, step 1)."""
        self._change(
            "DELETE FROM signed_prekeys WHERE replaced_at <= ?", (replaced_at_or_before,)
        )
        self._change(DELETE_ORPHAN_RECORDS, ())

    def add_one_time_prekey(self, private_key: bytes) -> int | None:
        """Saves a one-time prekey under the next id of its counter (section 21.1); None,
        and nothing saved, once the counter is at LAST_PREKEY_ID."""
        counted = self._change(COUNT_ONE_TIME_PREKEY, (LAST_PREKEY_ID,)).fetchone()
        if counted is None:
            return None
        prekey_id: int = counted[0]
        self._change("INSERT INTO one_time_prekeys VALUES (?, ?)", (prekey_id, private_key))
        return prekey_id

    def delete_one_time_prekey(self, prekey_id: int) -> None:
        self._change("DELETE FROM one_time_prekeys WHERE prekey_id = ?", (prekey_id,))

    def delete_lowest_one_time_prekeys(self, count: int) -> None:
        self._change(DELETE_LOWEST_ONE_TIME_PREKEYS, (count,))

    def contacts(self) -> list[tuple[bytes, str | None]]:
        """Every contact with the local name the user gave it, by name."""
        return self.connection.execute(
            "SELECT identity_key, name FROM contacts ORDER BY name, identity_key"
        ).fetchall()

    def add_contact(self, identity_key: bytes, *, name: str | None = None) -> None:
        self._change(
            "INSERT INTO contacts (identity_key, name) VALUES (?, ?) ON CONFLICT DO NOTHING",
            (identity_key, name),
        )

    def remove_contact(self, contact: bytes) -> None:
        """Deletes the contact with its sessions and its profile; its seen ids and records
        stay (20.6)."""
        profile = self.profile(contact)
        if profile is not None and profile.avatar_file is not None:
            self.delete_file(profile.avatar_file)
        self._change("DELETE FROM profiles WHERE contact = ?", (contact,))
        self._change("DELETE FROM profile_sends WHERE contact = ?", (contact,))
        self._change("DELETE FROM sessions WHERE contact = ?", (contact,))
        self._change("DELETE FROM contacts WHERE identity_key = ?", (contact,))
        self._change(DELETE_ORPHAN_RECORDS, ())

    def set_pin(self, contact: bytes, identity_dh_key: bytes) -> None:
        self._change(
            "UPDATE contacts SET pinned_identity_dh_key = ? WHERE identity_key = ?",
            (identity_dh_key, contact),
        )

    def add_session(
        self,
        contact: bytes,
        *,
        associated_data: bytes,
        state: RatchetState,
        initial_header: bytes | None,
    ) -> int:
        """Puts a new session at the head of the list."""
        added = self._change(
            ADD_SESSION, (contact, associated_data, _encode_state(state), initial_header)
        )
        session_id: int = added.fetchone()[0]
        return session_id

    def drop_sessions_behind(self, contact: bytes) -> int:
        """Deletes the sessions past MAX_SESSIONS and the records that go with them
        (sections 20.1 and 20.4); returns the skipped keys that left with them."""
        behind = (contact, contact, MAX_SESSIONS)
        skipped: int = self.connection.execute(COUNT_SKIPPED_KEYS_BEHIND, behind).fetchone()[0]
        self._change(DROP_SESSIONS_BEHIND, behind)
        self._change(DELETE_ORPHAN_RECORDS, ())
        return skipped

    def accept_on_session(self, session_id: int, state: RatchetState) -> None:
        """Saves the state after a decryption: the session drops its initial header and
        moves to the head of the list."""
        self._change(ACCEPT_ON_SESSION, (_encode_state(state), session_id))

    def advance_session(self, session_id: int, state: RatchetState) -> None:
        """Saves the state after an encryption."""
        self._change(
            "UPDATE sessions SET state = ? WHERE session_id = ?",
            (_encode_state(state), session_id),
        )

    def add_record(
        self, sender: bytes, ephemeral_key: bytes, *, session_id: int, signed_prekey_id: int
    ) -> None:
        self._change(
            "INSERT INTO records VALUES (?, ?, ?, ?)",
            (sender, ephemeral_key, session_id, signed_prekey_id),
        )

    def add_seen_id(self, sender: bytes, message_id: bytes, *, seen_at: int) -> None:
        self._change("INSERT INTO seen_ids VALUES (?, ?, ?)", (sender, message_id, seen_at))

    def delete_seen_ids(self, *, seen_at_or_before: int) -> None:
        self._change("DELETE FROM seen_ids WHERE seen_at <= ?", (seen_at_or_before,))

    def add_to_outbox(self, row: OutboxRow) -> None:
        self._change(
            "INSERT INTO outbox (message_id, recipient, payload) VALUES (?, ?, ?)",
            (row.message_id, row.recipient, row.payload),
        )

    def remove_from_outbox(self, message_id: bytes) -> None:
        self._change("DELETE FROM outbox WHERE message_id = ?", (message_id,))

    def log_message(
        self, contact: bytes, *, direction: str, message_id: bytes, text: str
    ) -> None:
        self._change(
            "INSERT INTO messages (contact, direction, message_id, text) VALUES (?, ?, ?, ?)",
            (contact, direction, message_id, text),
        )

    def uploads(self) -> list[UploadRow]:
        rows = self.connection.execute(READ_UPLOADS).fetchall()
        return [
            UploadRow(
                blob_id=blob_id,
                contact=contact,
                attachment=Attachment.FromString(attachment),
                length=length,
                profile=profile == 1,
            )
            for blob_id, contact, attachment, length, profile in rows
        ]

    def read_upload(self, blob_id: bytes, offset: int, length: int) -> bytes:
        """Bytes of the blob of an upload, read by range without loading the whole blob."""
        (position,) = self.connection.execute(
            "SELECT position FROM uploads WHERE blob_id = ?", (blob_id,)
        ).fetchone()
        with self.connection.blobopen("uploads", "blob", position, readonly=True) as blob:
            blob.seek(offset)
            return blob.read(length)

    def add_upload(
        self, blob_id: bytes, *, contact: bytes, attachment: Attachment, blob: bytes
    ) -> None:
        self._change(
            "INSERT INTO uploads (blob_id, contact, attachment, blob) VALUES (?, ?, ?, ?)",
            (blob_id, contact, attachment.SerializeToString(), blob),
        )

    def delete_upload(self, blob_id: bytes) -> None:
        """Deletes an upload, and the profile send that it carries, if it carries one."""
        self._change("DELETE FROM uploads WHERE blob_id = ?", (blob_id,))
        self._change("DELETE FROM profile_sends WHERE blob_id = ?", (blob_id,))

    def files(self) -> list[FileRow]:
        return [_file(row) for row in self.connection.execute(READ_FILES).fetchall()]

    def file(self, position: int) -> FileRow | None:
        row = self.connection.execute(READ_FILE, (position,)).fetchone()
        return None if row is None else _file(row)

    def file_of_message(self, message_id: bytes) -> FileRow | None:
        """The file that a message of the client's own carries, if it carries one."""
        row = self.connection.execute(READ_FILE_OF_MESSAGE, (message_id,)).fetchone()
        return None if row is None else _file(row)

    def add_file(
        self,
        contact: bytes,
        *,
        incoming: bool,
        message_id: bytes,
        attachment: Attachment,
        state: str,
    ) -> int:
        """Adds a file and returns its position."""
        added = self._change(
            "INSERT INTO files (contact, direction, message_id, attachment, state) "
            "VALUES (?, ?, ?, ?, ?) RETURNING position",
            (
                contact,
                "in" if incoming else "out",
                message_id,
                attachment.SerializeToString(),
                state,
            ),
        )
        position: int = added.fetchone()[0]
        return position

    def delete_file(self, position: int) -> None:
        self._change("DELETE FROM files WHERE position = ?", (position,))
        self._change("DELETE FROM downloads WHERE position = ?", (position,))

    def set_file_state(
        self, position: int, state: str, *, saved_as: str | None = None
    ) -> None:
        """Sets the state of a file and drops its downloaded bytes."""
        self._change(
            "UPDATE files SET state = ?, saved_as = ?, held = 0 WHERE position = ?",
            (state, saved_as, position),
        )
        self._change("DELETE FROM downloads WHERE position = ?", (position,))

    def begin_download(self, position: int, state: str, length: int) -> None:
        """Makes room for the `length` bytes of a download, unless it has its room."""
        self._change("UPDATE files SET state = ? WHERE position = ?", (state, position))
        self._change(
            "INSERT INTO downloads VALUES (?, zeroblob(?)) ON CONFLICT DO NOTHING",
            (position, length),
        )

    def add_download_piece(self, position: int, data: bytes) -> None:
        """Writes `data` at the held length of a download and counts it as held."""
        if not self.connection.in_transaction:
            raise RuntimeError("a write of the store runs outside a transaction")

        (held,) = self.connection.execute(
            "SELECT held FROM files WHERE position = ?", (position,)
        ).fetchone()
        with self.connection.blobopen("downloads", "bytes", position) as blob:
            blob.seek(held)
            blob.write(data)
        self._change(
            "UPDATE files SET held = held + ? WHERE position = ?", (len(data), position)
        )

    def downloaded(self, position: int) -> bytes:
        (data,) = self.connection.execute(
            "SELECT bytes FROM downloads WHERE position = ?", (position,)
        ).fetchone()
        return bytes(data)

    def blob_deletions(self) -> list[tuple[bytes, bytes]]:
        """The DeleteBlob frames to send, as (uploader, blob id)."""
        return self.connection.execute(
            "SELECT uploader, blob_id FROM blob_deletions ORDER BY uploader, blob_id"
        ).fetchall()

    def add_blob_deletion(self, uploader: bytes, blob_id: bytes) -> None:
        self._change(
            "INSERT INTO blob_deletions VALUES (?, ?) ON CONFLICT DO NOTHING",
            (uploader, blob_id),
        )

    def delete_blob_deletion(self, uploader: bytes, blob_id: bytes) -> None:
        self._change(
            "DELETE FROM blob_deletions WHERE uploader = ? AND blob_id = ?",
            (uploader, blob_id),
        )

    def own_profile(self) -> OwnProfile:
        """The own profile; the empty one when none was ever set."""
        row = self.connection.execute(
            "SELECT name, avatar, media_type FROM own_profile"
        ).fetchone()
        if row is None:
            return OwnProfile()
        return OwnProfile(name=row[0], avatar=row[1], media_type=row[2])

    def set_own_profile(self, name: str, avatar: bytes | None, media_type: str) -> None:
        self._change(SET_OWN_PROFILE, (name, avatar, media_type))

    def owe_profile(self, contact: bytes) -> None:
        """Marks the own profile as owed to a contact; a send already owed stays as it is."""
        self._change(
            "INSERT INTO profile_sends (contact) VALUES (?) ON CONFLICT DO NOTHING", (contact,)
        )

    def profile_upload(self, contact: bytes) -> bytes | None:
        """The blob id of the avatar upload of the profile owed to a contact, if any."""
        row = self.connection.execute(
            "SELECT blob_id FROM profile_sends WHERE contact = ?", (contact,)
        ).fetchone()
        return None if row is None else row[0]

    def owed_profiles(self) -> list[bytes]:
        """The contacts owed the own profile whose avatar upload has not started."""
        rows = self.connection.execute(
            "SELECT contact FROM profile_sends WHERE blob_id IS NULL ORDER BY contact"
        ).fetchall()
        return [contact for (contact,) in rows]

    def start_profile_upload(self, contact: bytes, blob_id: bytes) -> None:
        self._change(
            "UPDATE profile_sends SET blob_id = ? WHERE contact = ?", (blob_id, contact)
        )

    def delete_profile_send(self, contact: bytes) -> None:
        self._change("DELETE FROM profile_sends WHERE contact = ?", (contact,))

    def profile(self, contact: bytes) -> ContactProfile | None:
        row = self.connection.execute(
            "SELECT name, avatar_file, avatar FROM profiles WHERE contact = ?", (contact,)
        ).fetchone()
        if row is None:
            return None
        return ContactProfile(name=row[0], avatar_file=row[1], avatar=row[2])

    def set_profile(self, contact: bytes, name: str, *, avatar_file: int | None) -> None:
        """Saves the latest profile of a contact; its avatar is not received yet."""
        self._change(SET_PROFILE, (contact, name, avatar_file))

    def delete_profile(self, contact: bytes) -> None:
        self._change("DELETE FROM profiles WHERE contact = ?", (contact,))

    def set_avatar(self, avatar_file: int, avatar: bytes) -> None:
        self._change(
            "UPDATE profiles SET avatar = ? WHERE avatar_file = ?", (avatar, avatar_file)
        )

    def _change(self, statement: str, parameters: tuple[Any, ...]) -> sqlite3.Cursor:
        if not self.connection.in_transaction:
            raise RuntimeError("a write of the store runs outside a transaction")
        return self.connection.execute(statement, parameters)


def _make_private_directory(directory: Path) -> None:
    try:
        directory.mkdir(mode=DIRECTORY_MODE, parents=True)
    except FileExistsError:
        pass
    else:
        directory.chmod(DIRECTORY_MODE)
    _refuse_wide_mode(directory)


def _make_private_file(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
    except FileExistsError:
        pass
    else:
        os.fchmod(descriptor, FILE_MODE)
        os.close(descriptor)
    _refuse_wide_mode(path)


def _refuse_wide_mode(path: Path) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & WIDER_THAN_OWNER:
        raise StoreModeError(f"{path} has mode {mode:04o}: the group or others have a right")


def _session(row: tuple[Any, ...]) -> StoredSession:
    session_id, contact, associated_data, state, initial_header = row
    return StoredSession(
        session_id=session_id,
        contact=contact,
        associated_data=associated_data,
        state=_decode_state(state),
        initial_header=initial_header,
    )


def _file(row: tuple[Any, ...]) -> FileRow:
    position, contact, direction, message_id, attachment, state, held, saved_as, avatar = row
    return FileRow(
        position=position,
        contact=contact,
        incoming=direction == "in",
        message_id=message_id,
        attachment=Attachment.FromString(attachment),
        state=state,
        held=held,
        saved_as=saved_as,
        avatar=avatar == 1,
    )


def _encode_state(state: RatchetState) -> str:
    skipped = [
        {
            "ratchet_key": entry.ratchet_key.hex(),
            "number": entry.number,
            "message_key": entry.message_key.hex(),
            "step": entry.step,
        }
        for entry in state.mkskipped
    ]
    return json.dumps(
        {
            "dhs_private_key": state.dhs_private_key.hex(),
            "dhs_public_key": state.dhs_public_key.hex(),
            "dhr": _hex_or_none(state.dhr),
            "rk": state.rk.hex(),
            "cks": _hex_or_none(state.cks),
            "ckr": _hex_or_none(state.ckr),
            "ns": state.ns,
            "nr": state.nr,
            "pn": state.pn,
            "dhsteps": state.dhsteps,
            "mkskipped": skipped,
        }
    )


def _decode_state(encoded: str) -> RatchetState:
    fields = json.loads(encoded)
    skipped = tuple(
        SkippedKey(
            ratchet_key=bytes.fromhex(entry["ratchet_key"]),
            number=entry["number"],
            message_key=bytes.fromhex(entry["message_key"]),
            step=entry["step"],
        )
        for entry in fields["mkskipped"]
    )
    return RatchetState(
        dhs_private_key=bytes.fromhex(fields["dhs_private_key"]),
        dhs_public_key=bytes.fromhex(fields["dhs_public_key"]),
        dhr=_bytes_or_none(fields["dhr"]),
        rk=bytes.fromhex(fields["rk"]),
        cks=_bytes_or_none(fields["cks"]),
        ckr=_bytes_or_none(fields["ckr"]),
        ns=fields["ns"],
        nr=fields["nr"],
        pn=fields["pn"],
        dhsteps=fields["dhsteps"],
        mkskipped=skipped,
    )


def _hex_or_none(value: bytes | None) -> str | None:
    return None if value is None else value.hex()


def _bytes_or_none(value: str | None) -> bytes | None:
    return None if value is None else bytes.fromhex(value)
