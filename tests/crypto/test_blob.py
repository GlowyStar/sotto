import os
import re
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sotto.crypto.blob import (
    FILE_PADDING_MIN,
    MAX_FILE_BYTES,
    blob_length,
    chunk_count,
    digest_of,
    encrypt_blob,
    open_blob,
    padded_length,
)

ROOT = Path(__file__).parent.parent.parent
PROTOCOL = (ROOT / "docs" / "protocol.md").read_text(encoding="utf-8")
NUMBER_ROW = re.compile(r"^\| (\d+) +\| (\d+) +\|(?: (\d+) +\| (\d+) +\|)?$", re.MULTILINE)


def rows_of(number: str) -> list[tuple[int, ...]]:
    start = PROTOCOL.index(f"\n### {number} ")
    end = PROTOCOL.index("\n### ", start + 1)
    return [
        tuple(int(cell) for cell in row if cell)
        for row in NUMBER_ROW.findall(PROTOCOL[start:end])
    ]


def test_padded_lengths_are_the_table_of_section_29_2() -> None:
    table = rows_of("29.2")

    assert table
    assert [(size, padded_length(size)) for size, _ in table] == table


def test_blob_lengths_are_the_table_of_section_29_5() -> None:
    table = rows_of("29.5")

    assert table
    assert [
        (size, padded_length(size), chunk_count(size), blob_length(size)) for size, *_ in table
    ] == table


@given(st.integers(min_value=0, max_value=MAX_FILE_BYTES + 1))
def test_padding_is_at_least_the_minimum_and_below_a_sixteenth(size: int) -> None:
    padded = padded_length(size)

    assert padded >= max(size, FILE_PADDING_MIN)
    if size >= FILE_PADDING_MIN:
        assert padded - size < size / 16


def test_file_above_the_largest_is_not_encrypted() -> None:
    with pytest.raises(ValueError, match="above"):
        encrypt_blob(bytes(MAX_FILE_BYTES + 1), file_key=bytes(16), nonce=bytes(16))


@given(st.binary(max_size=3000))
def test_any_file_opens_from_its_blob(file: bytes) -> None:
    file_key, nonce = os.urandom(16), os.urandom(16)
    blob = encrypt_blob(file, file_key=file_key, nonce=nonce)

    assert len(blob) == blob_length(len(file))
    assert open_blob(blob, file_key=file_key, size=len(file), digest=digest_of(blob)) == file
