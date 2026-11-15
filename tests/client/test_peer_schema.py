import re
from pathlib import Path

from google.protobuf.descriptor_pb2 import FileDescriptorProto, FileDescriptorSet
from grpc_tools import protoc  # type: ignore[import-untyped]

ROOT = Path(__file__).parent.parent.parent
PROTOCOL = (ROOT / "docs" / "protocol.md").read_text(encoding="utf-8")
SCHEMA = ROOT / "proto" / "sotto.proto"
PEER_LISTING = re.compile(
    r"^### 19\.1 The schema$.*?^```proto\n(.*?)^```$", re.DOTALL | re.MULTILINE
)
PEER_MESSAGES = ("PeerMessage", "InitialHeader", "Content")


def compile_schema(source: str, folder: Path) -> FileDescriptorProto:
    folder.mkdir()
    (folder / "sotto.proto").write_text(source, encoding="utf-8")
    compiled = folder / "sotto.binpb"
    arguments = ["protoc", f"-I{folder}", f"--descriptor_set_out={compiled}", "sotto.proto"]
    assert protoc.main(arguments) == 0
    return FileDescriptorSet.FromString(compiled.read_bytes()).file[0]


def test_peer_messages_of_the_schema_file_are_those_of_section_19_1(tmp_path: Path) -> None:
    listing = PEER_LISTING.search(PROTOCOL)
    assert listing is not None
    listed_source = 'syntax = "proto3";\n\npackage sotto;\n\n' + listing.group(1)
    listed = compile_schema(listed_source, tmp_path / "listed")
    in_file = compile_schema(SCHEMA.read_text(encoding="utf-8"), tmp_path / "in_file")

    listed_messages = {message.name: message for message in listed.message_type}
    file_messages = {message.name: message for message in in_file.message_type}
    assert sorted(listed_messages) == sorted(PEER_MESSAGES)
    for name in PEER_MESSAGES:
        assert file_messages[name] == listed_messages[name]
