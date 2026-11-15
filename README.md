# sotto

An end-to-end encrypted one-to-one messenger with a content-blind relay, in the making.
The goal is a server that passes sealed messages between clients and holds no key that
opens one.

## Status

- Not audited. Nobody has reviewed this code for security, so do not trust it with
  anything that matters.
- Nothing is encrypted so far. The repository holds the scaffold of the relay: a process
  that answers a health check and accepts WebSocket connections on one path.
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
uv run sotto-relay
```

The relay listens on `127.0.0.1:8765`; `RELAY_HOST` and `RELAY_PORT` change that. It speaks
plain WebSocket, so TLS belongs to a reverse proxy in front of it.

| Path          | Answer            |
|---------------|-------------------|
| `/ws`         | WebSocket upgrade |
| `/healthz`    | `200`             |
| anything else | `404`             |

The match is exact: a query string or a trailing slash makes it another path.

Logs are JSON lines on stdout. On SIGTERM the relay closes its connections and exits
with 0.

## Checks

```sh
uv run ruff check
uv run ruff format --check
uv run mypy
uv run pytest
```

`scripts/stand.sh <project>` builds the image, starts the relay with Docker Compose under
that project name and runs the tests marked `stand` against it. It then checks that the
container runs as a non-root user and exits with 0 on stop, and removes the stand.
`RELAY_PORT` moves the published port off 8765.

## License

Apache-2.0, see [LICENSE](LICENSE).
