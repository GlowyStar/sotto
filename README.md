# sotto

An end-to-end encrypted one-to-one messenger with a content-blind relay, in the making.
The goal is a server that passes sealed messages between clients and holds no key that
opens one.

## Status

- Not audited. Nobody has reviewed this code for security, so do not trust it with
  anything that matters.
- Nothing is encrypted so far. The relay answers a health check, logs a connection in by
  a signature over its own challenge, and stores and hands out prekey bundles. It stores
  a message for a registered recipient, answers the sender once the message is
  committed, delivers it when the recipient is logged in and deletes it when the
  recipient acks it or it expires; the payload is opaque bytes that it never parses or
  logs. Queue caps and rate limits are not there yet. The frames
  are protobuf messages, whose schema is `proto/sotto.proto`. The identity core holds the
  user ids, the three signed strings and the checks of a prekey bundle, with the shared
  test vectors in `vectors/identity.json`.
- The protocol is written down ahead of the code. [docs/protocol.md](docs/protocol.md)
  holds both parts. Part 1 is identity, the prekey bundle and the relay protocol. Part 2
  is the end-to-end protocol: the key agreement, the Double Ratchet, message encryption,
  the session rules and the client store. [docs/threat-model.md](docs/threat-model.md)
  has two halves as well. The relay half lists
  [what the relay learns](docs/threat-model.md#what-the-relay-learns),
  [what the relay can do](docs/threat-model.md#what-the-relay-can-do) and what is
  [not protected](docs/threat-model.md#not-protected). The client half covers a peer, a
  stolen device or data directory, and what the keys of a session cover and what they do
  not.

## Plan

- An identity is a key pair made on the device: no phone number, no email, no password.
- The relay routes ciphertext and keeps a message only until its recipient confirms it.
  It still sees who talks to whom, when and how much.
- Key agreement and message encryption follow Signal's public X3DH and Double Ratchet
  specifications in their classical form, with no post-quantum protection. The primitives
  come from vetted libraries only.
- The protocol is written down, and shared test vectors keep the implementations in step:
  a command-line client here and a macOS client in a repository of its own.

## Run the relay

Needs [uv](https://docs.astral.sh/uv/) and Python 3.14.

```sh
uv sync
RELAY_DATABASE=relay.db uv run sotto-relay
```

The relay listens on `127.0.0.1:8765`; `RELAY_HOST` and `RELAY_PORT` change that. It speaks
plain WebSocket, so TLS belongs to a reverse proxy in front of it.

A client signs its login for the host it dialed, so `RELAY_NAME` has to be that host, in
lowercase and without the port. The default is `127.0.0.1`: a client that dials
`localhost` is refused. `RELAY_LOGIN_DEADLINE_SECONDS`, 10 by default, is the time a
client has to log in.

| Path          | Answer            |
|---------------|-------------------|
| `/ws`         | WebSocket upgrade |
| `/healthz`    | `200`             |
| anything else | `404`             |

The match is exact: a query string or a trailing slash makes it another path.

The relay keeps its whole state in one SQLite file, the path in `RELAY_DATABASE`, which
has no default. It opens the file in write-ahead mode, so a `-wal` and a `-shm` file sit
next to it while it runs, and it removes the two on an orderly stop. Keep the three on a
directory of their own: the image keeps them in `/data`, which `compose.yaml` mounts as the
named volume `relay-data`. `RELAY_MAX_PAGES` caps the file, 262144 pages of 4096 bytes by
default; an upload or a message into a full database is refused and the relay stays up.
`RELAY_ONE_TIME_PREKEY_CAP`, 100 by default, caps the one-time prekeys kept per identity.

The relay keeps a registered identity and its bundle with no expiry. It keeps a message
until its recipient acks it, and for `RELAY_MESSAGE_TTL_SECONDS` at most, 2592000 seconds
(30 days) by default, whether it was delivered or not. Every `RELAY_SWEEP_INTERVAL_SECONDS`,
60 by default, a sweep deletes the expired messages and truncates the `-wal` file, so that
an acked or expired message is then in none of the three files. Until that sweep, and in a
relay that was killed before it, the old bytes are still in the `-wal` file. What the
filesystem, the disk or a backup keeps after that is out of scope (`docs/protocol.md`,
section 13).

Logs are JSON lines on stdout. On SIGTERM the relay closes its connections and exits
with 0.

## Checks

```sh
uv run ruff check
uv run ruff format --check
uv run mypy
uv run pytest
```

The Python module of the frames in `src/sotto/proto` is generated from
`proto/sotto.proto` and committed. After a change of the schema run
`scripts/generate_proto.sh` and commit what it wrote; CI runs the script and fails when
the committed files differ.

`scripts/stand.sh <project>` builds the image, starts the relay with Docker Compose under
that project name and runs the tests marked `stand` against it. It restarts the relay
and runs the tests marked `stand_after_restart`, which fetch a bundle uploaded and receive
a message sent before the restart. It then checks that the
container runs as a non-root user and exits with 0 on stop, and removes the stand.
`RELAY_PORT` moves the published port off 8765.

## License

Apache-2.0, see [LICENSE](LICENSE).
