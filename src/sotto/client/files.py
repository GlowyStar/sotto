"""Received files on disk by docs/protocol.md, section 32.2: the name of the peer never
picks a folder and a file is never written over another."""

import os
from pathlib import Path

from sotto.client.envelope import MAX_FILE_NAME_BYTES, is_control

FOLDER_MODE = 0o700
FILE_MODE = 0o600
OWN_NAME = "received-file"
SEPARATORS = frozenset("/\\")


def is_safe_name(file_name: str) -> bool:
    """Whether a received name keeps the rule of section 32.2."""
    is_too_long = len(file_name.encode()) > MAX_FILE_NAME_BYTES
    is_a_folder_name = file_name in ("", ".", "..")
    has_a_bad_character = any(
        character in SEPARATORS or is_control(character) for character in file_name
    )
    return not (is_too_long or is_a_folder_name or has_a_bad_character)


def save_file(folder: Path, file_name: str, data: bytes) -> Path:
    """Writes a received file into `folder` under a free name and returns its path.

    The name is the sent one when it passes `is_safe_name`, else one of the client's own;
    a name that is taken gets a number, ` (1)` and up, in front of its suffix. A write that
    fails leaves no file.
    """
    folder.mkdir(mode=FOLDER_MODE, parents=True, exist_ok=True)
    name = file_name if is_safe_name(file_name) else OWN_NAME
    stem, suffix = Path(name).stem, Path(name).suffix

    number = 0
    while True:
        candidate = name if number == 0 else f"{stem} ({number}){suffix}"
        if len(candidate.encode()) > MAX_FILE_NAME_BYTES:
            candidate = f"{OWN_NAME} ({number})"
        path = folder / candidate
        number += 1
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
        except FileExistsError:
            continue
        try:
            with os.fdopen(descriptor, "wb") as file:
                file.write(data)
                file.flush()
                os.fsync(file.fileno())
        except OSError:
            path.unlink(missing_ok=True)
            raise
        return path
