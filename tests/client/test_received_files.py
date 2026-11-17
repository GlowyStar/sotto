import stat
from pathlib import Path

import pytest

from sotto.client.files import OWN_NAME, is_safe_name, save_file


@pytest.mark.parametrize(
    "name",
    [
        "",
        ".",
        "..",
        "a/b",
        "a\\b",
        "a\x00b",
        "a\x1fb",
        "a\x7fb",
        "a\x9bb",
        "cat\u202egpj.exe",
        "a\u2028b",
        "x" * 256,
        "\u00e9" * 128,
    ],
)
def test_name_that_breaks_section_32_2_is_replaced(name: str) -> None:
    assert not is_safe_name(name)


@pytest.mark.parametrize(
    "name", ["photo.jpg", ".hidden", "\u00e9t\u00e9 \U0001f600.png", "x" * 255]
)
def test_name_within_section_32_2_is_kept(name: str) -> None:
    assert is_safe_name(name)


def test_saved_file_takes_a_free_name_and_never_follows_a_link(tmp_path: Path) -> None:
    folder = tmp_path / "received"
    folder.mkdir()
    target = tmp_path / "outside.txt"
    target.write_bytes(b"outside")
    (folder / "note.txt").symlink_to(target)
    long_name = "y" * 251 + ".txt"
    (folder / long_name).write_bytes(b"taken")

    linked = save_file(folder, "note.txt", b"first")
    unsafe = save_file(folder, "../outside.txt", b"second")
    long = save_file(folder, long_name, b"third")

    assert linked.name == "note (1).txt"
    assert unsafe.name == OWN_NAME
    assert long.name == f"{OWN_NAME} (1)"
    assert target.read_bytes() == b"outside"
    assert (folder / long_name).read_bytes() == b"taken"
    assert [path.read_bytes() for path in (linked, unsafe, long)] == [
        b"first",
        b"second",
        b"third",
    ]
    assert stat.S_IMODE(linked.stat().st_mode) == 0o600
