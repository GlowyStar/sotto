import ast
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

ROOT = Path(__file__).parent.parent
DOCS = sorted((ROOT / "docs").rglob("*.md"))
CITING_DOCUMENTS = [*DOCS, ROOT / "README.md"]

OPEN_POINT = re.compile(r"(?<!`)OPEN:")
TEST_CITATION = re.compile(r"\[test: (tests/(?:\w+/)*\w+\.py)::(test_\w+)\]")
PENDING_CITATION = re.compile(r"\[pending: task (?:[4-8]|1[0-4])\]")
CITATION_PART = re.compile(r"\[\w+:|\btests/|::|\bpending\b", re.IGNORECASE)


def numbered_lines(documents: Iterable[Path]) -> Iterator[tuple[str, str]]:
    for document in documents:
        text = document.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), 1):
            yield f"{document.relative_to(ROOT)}:{number}", line


def functions_defined_in(test_file: Path) -> set[str]:
    try:
        source = test_file.read_text(encoding="utf-8")
    except FileNotFoundError:
        return set()

    definitions = (ast.FunctionDef, ast.AsyncFunctionDef)
    return {node.name for node in ast.parse(source).body if isinstance(node, definitions)}


def test_docs_are_found() -> None:
    assert DOCS


def test_docs_have_no_open_point() -> None:
    open_points = []
    for location, line in numbered_lines(DOCS):
        if OPEN_POINT.search(line):
            open_points.append(location)

    assert open_points == []


def test_citations_are_well_formed() -> None:
    malformed = []
    for location, line in numbered_lines(CITING_DOCUMENTS):
        outside_citations = PENDING_CITATION.sub("", TEST_CITATION.sub("", line))
        if CITATION_PART.search(outside_citations):
            malformed.append(f"{location}: {line.strip()}")

    assert malformed == []


def test_cited_tests_exist() -> None:
    missing = [
        f"{location}: {test_file}::{test_name}"
        for location, line in numbered_lines(CITING_DOCUMENTS)
        for test_file, test_name in TEST_CITATION.findall(line)
        if test_name not in functions_defined_in(ROOT / test_file)
    ]

    assert missing == []
