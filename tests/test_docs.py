import ast
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from google.protobuf.descriptor_pb2 import FileDescriptorProto, FileDescriptorSet
from grpc_tools import protoc  # type: ignore[import-untyped]

from sotto.relay.frames import MAX_FRAME_BYTES
from sotto.relay.server import CloseCode
from sotto.relay.settings import Settings

ROOT = Path(__file__).parent.parent
DOCS = sorted((ROOT / "docs").rglob("*.md"))
CITING_DOCUMENTS = [*DOCS, ROOT / "README.md"]

OPEN_POINT = re.compile(r"(?<!`)OPEN:")
TEST_CITATION = re.compile(r"\[test: (tests/(?:\w+/)*\w+\.py)::(test_\w+)\]")
PENDING_CITATION = re.compile(r"\[pending: task 1[2-4]\]")
CITATION_PART = re.compile(r"\[\w+:|\btests/|::|\bpending\b", re.IGNORECASE)

PROTOCOL = (ROOT / "docs" / "protocol.md").read_text(encoding="utf-8")
SCHEMA = ROOT / "proto" / "sotto.proto"
SCHEMA_LISTING = re.compile(r"^```proto\n(.*?)^```$", re.DOTALL | re.MULTILINE)
CLOSE_CODE_ROW = re.compile(r"^\| (\d{4}) \| (\w+) +\|", re.MULTILINE)
LIMITS_TABLE = re.compile(r"^### 12\.1 The table\n(.*?)^### ", re.DOTALL | re.MULTILINE)
LIMIT_ROW = re.compile(r"^\| ([A-Z_]+) +\| (\d+) +\|", re.MULTILINE)


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


def test_close_codes_of_the_relay_are_those_of_the_spec() -> None:
    table = {name: int(number) for number, name in CLOSE_CODE_ROW.findall(PROTOCOL)}

    assert table == {code.name: code.value for code in CloseCode}


def test_limits_table_is_the_settings_of_the_relay() -> None:
    section = LIMITS_TABLE.search(PROTOCOL)
    assert section is not None
    table = {name: int(default) for name, default in LIMIT_ROW.findall(section.group(1))}
    settings_names = [name for name in table if name != "MAX_FRAME_BYTES"]
    environ = {"RELAY_DATABASE": "relay.db"}
    defaults = Settings.from_env(environ)
    read = Settings.from_env(environ | {f"RELAY_{name}": "7" for name in settings_names})

    in_code = {name: getattr(defaults, name.lower()) for name in settings_names}
    assert table == {"MAX_FRAME_BYTES": MAX_FRAME_BYTES, **in_code}
    assert {name: getattr(read, name.lower()) for name in settings_names} == dict.fromkeys(
        settings_names, 7
    )


def compile_schema(source: str, folder: Path) -> FileDescriptorProto:
    folder.mkdir()
    (folder / "sotto.proto").write_text(source, encoding="utf-8")
    compiled = folder / "sotto.binpb"
    arguments = ["protoc", f"-I{folder}", f"--descriptor_set_out={compiled}", "sotto.proto"]
    assert protoc.main(arguments) == 0
    return FileDescriptorSet.FromString(compiled.read_bytes()).file[0]


def test_schema_file_is_a_part_of_the_listing_in_the_spec(tmp_path: Path) -> None:
    listing = SCHEMA_LISTING.search(PROTOCOL)
    assert listing is not None
    listed = compile_schema(listing.group(1), tmp_path / "listed")
    in_file = compile_schema(SCHEMA.read_text(encoding="utf-8"), tmp_path / "in_file")

    assert (in_file.syntax, in_file.package) == (listed.syntax, listed.package)
    listed_enums = {enum.name: enum for enum in listed.enum_type}
    for enum in in_file.enum_type:
        assert enum == listed_enums[enum.name]
    listed_messages = {message.name: message for message in listed.message_type}
    for message in in_file.message_type:
        listed_message = listed_messages[message.name]
        # Only an envelope grows: a frame enters its oneof with the handler of the frame.
        if message.oneof_decl:
            assert all(member in listed_message.field for member in message.field)
        else:
            assert message == listed_message
