import os
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest

from sotto.client.store import Store, StoreModeError


@pytest.fixture
def open_umask() -> Iterator[None]:
    """A umask that takes no bit off, so that the modes come from the store alone."""
    previous = os.umask(0)
    yield
    os.umask(previous)


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.mark.usefixtures("open_umask")
def test_directory_gets_mode_0700_and_the_file_0600(tmp_path: Path) -> None:
    path = tmp_path / "data" / "store.db"

    Store(path).close()

    assert mode_of(path.parent) == 0o700
    assert mode_of(path) == 0o600


@pytest.mark.parametrize("bits", [0o040, 0o020, 0o010, 0o004, 0o002, 0o001])
@pytest.mark.parametrize("which", ["directory", "file"])
def test_start_is_refused_when_a_mode_gives_a_right_to_the_group_or_others(
    tmp_path: Path, bits: int, which: str
) -> None:
    path = tmp_path / "data" / "store.db"
    Store(path).close()
    widened = path.parent if which == "directory" else path
    widened.chmod(mode_of(widened) | bits)

    with pytest.raises(StoreModeError):
        Store(path)


def test_store_uses_the_rollback_journal_with_secure_delete(tmp_path: Path) -> None:
    path = tmp_path / "data" / "store.db"
    store = Store(path)

    with store.transaction():
        store.add_contact(bytes(32))

    assert store.connection.execute("PRAGMA journal_mode").fetchone() == ("delete",)
    assert store.connection.execute("PRAGMA secure_delete").fetchone() == (1,)
    assert sorted(child.name for child in path.parent.iterdir()) == ["store.db"]
    store.close()


def test_write_outside_a_transaction_is_refused(tmp_path: Path) -> None:
    store = Store(tmp_path / "data" / "store.db")

    with pytest.raises(RuntimeError):
        store.add_contact(bytes(32))
    assert not store.is_contact(bytes(32))
    store.close()


def test_store_holds_what_section_22_1_lists(tmp_path: Path) -> None:
    store = Store(tmp_path / "data" / "store.db")

    tables = store.connection.execute(
        "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()

    assert sorted(name for (name,) in tables) == [
        "contacts",
        "identity",
        "messages",
        "one_time_prekeys",
        "outbox",
        "records",
        "seen_ids",
        "sessions",
        "signed_prekeys",
    ]
    store.close()
