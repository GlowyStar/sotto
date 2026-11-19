# sotto

An end-to-end encrypted one-to-one messenger with a content-blind relay, in the making.
The goal is a server that passes sealed messages between clients and holds no key that
opens one.

## Status

- Not audited. Nobody has reviewed this code for security, so do not trust it with
  anything that matters.
- An alpha. Two people chat from two terminals through a relay: the command-line client
  `sotto` encrypts every text end to end (the key agreement PQXDH of part 6 and the
  Double Ratchet of part 2 of the protocol), and the text is in no frame, log line or file of the relay
  [test: tests/client/test_transport.py::test_marker_text_is_in_no_frame_log_or_file_of_the_relay].
  Files of up to 100 MiB go the same way: encrypted on the sender's device, uploaded in
  pieces that resume where a broken connection or a restart left them, and saved whole
  or reported as not sent
  [test: tests/client/test_files.py::test_upload_cut_in_the_middle_goes_on_from_the_stored_length]
  [test: tests/client/test_files.py::test_download_cut_in_the_middle_goes_on_from_the_bytes_it_holds].
  A message can be answered with a quote, edited and deleted for both, shows when it
  reached the other client and when it was read, and can disappear after a timer
  [test: tests/client/test_cli.py::test_two_processes_reply_edit_delete_see_the_marks_and_lose_a_timed_message].
  Delete for both and the timer are requests that the other side's client honours, and
  nothing more: whoever received a message can keep it.
  The relay logs a connection in by a signature over its own challenge, stores and hands
  out prekey bundles, and keeps a message until its recipient acks it or it expires; it
  caps queues and rate-limits frames. The frames are protobuf messages, whose schema is
  `proto/sotto.proto`, and the shared test vectors are in `vectors/`.
- The protocol is written down ahead of the code. [docs/protocol.md](docs/protocol.md)
  holds six parts. Part 1 is identity, the prekey bundle and the relay protocol. Part 2
  is the end-to-end protocol: the key agreement, the Double Ratchet, message encryption,
  the session rules and the client store. Part 3 is files and photos: the blob cipher,
  resumable uploads and downloads through the relay and the attachment of a message.
  Part 4 is the profile: a display name and an avatar that a client sends to its
  contacts. Part 5 is replies, edits, delete for both, delivery and read receipts and
  disappearing messages. Part 6 is the post-quantum key agreement of every new session,
  X25519 with ML-KEM-768, and the transition from the classical one.
  [docs/threat-model.md](docs/threat-model.md)
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
- Key agreement and message encryption follow Signal's public PQXDH and Double Ratchet
  specifications. A new session agrees its key with X25519 and ML-KEM-768, so recorded
  traffic stays closed to a later quantum computer; the ratchet stays classical, and
  nothing protects against an attacker who has such a computer at the time of the
  session ([threat model](docs/threat-model.md#post-quantum-protection)). The primitives
  come from vetted libraries only.
- The protocol is written down, and shared test vectors keep the implementations in step:
  a command-line client here and a macOS client in a repository of its own.

## Try it

Two terminals on one machine, about five minutes. Needs [uv](https://docs.astral.sh/uv/),
Python 3.14 and Docker.

1. Start the relay from the root of the repository:

   ```sh
   docker compose up --build -d --wait
   ```

   It listens on `127.0.0.1:8765` and serves metrics on `127.0.0.1:9765`. When a port is
   taken, `RELAY_PORT` and `RELAY_METRICS_PORT` move them, and every `chat` below then
   gets `--relay ws://127.0.0.1:<port>/ws`:

   ```sh
   RELAY_PORT=8784 RELAY_METRICS_PORT=9784 docker compose up --build -d --wait
   ```

2. Make two identities, one per terminal. Each command prints the user id, 64 hex
   characters:

   ```sh
   uv run sotto --data-dir alice init    # terminal 1
   uv run sotto --data-dir bob init      # terminal 2
   ```

3. Exchange the ids and give each other a local name:

   ```sh
   uv run sotto --data-dir alice add bob <the id that bob printed>      # terminal 1
   uv run sotto --data-dir bob add alice <the id that alice printed>    # terminal 2
   ```

4. Chat, Bob first: an identity can receive once its client has connected one time,
   because that is when its prekey bundle reaches the relay.

   ```sh
   uv run sotto --data-dir bob chat alice    # terminal 2
   uv run sotto --data-dir alice chat bob    # terminal 1
   ```

   Both print `connected`, a line on how to send and leave, and the prompt `> `. A line
   typed in one terminal is printed in the other as `#1 alice: <the line>`, where `#1` is
   the number of the message in that terminal's log. `/quit`, Ctrl-D on an empty line or
   the end of input leaves the chat; what the other side sends meanwhile waits at the
   relay and is printed by the next `chat`.

   The typed line is edited in place: the arrows, Home and End, Option- or Ctrl-arrows by
   word, Backspace, Delete and Ctrl-A, E, B, F, U, K, W, D; other keys do nothing. What
   arrives meanwhile is printed above it, and a line wider than the window scrolls
   sideways. When stdin or stdout is not a terminal, the chat reads plain lines and prints
   neither the prompt nor the help line.

   Under your own message the chat prints `#1 sent` when the relay has it, then
   `#1 delivered` or `#1 read` when the other client reports it. A message counts as
   read once the other chat printed it. In the chat:

   ```text
   /reply 1 see you there    answer message 1 with a quote of it
   /edit 2 see you at 8      change your own message 2, up to 10 times within a day
   /delete 2                 ask both sides to delete your own message 2
   /timer 1h                 messages sent from now on disappear after an hour
   /timer off                messages sent from now on stay
   ```

   A message with a timer disappears from the reader's store an hour after it was read
   and from the sender's an hour after it was sent, with any file it brought. The other
   side's chat prints one line for each edit, deletion and timer change.
   `sotto --data-dir bob read-receipts off` stops Bob's read receipts: Alice then sees
   `delivered` and never `read`. A deletion and a timer are requests that the other
   client honours: it removes the text and any received file from its store, but it
   cannot clear what the terminal already printed, and nothing stops the other person
   from keeping a copy.

   Send a file from a third terminal while Bob's chat runs:

   ```sh
   uv run sotto --data-dir alice send-file bob photo.jpg --caption "the view"
   ```

   It prints the progress and `sent photo.jpg to bob`. Bob's chat shows the file, its
   size and caption, downloads it into `bob/received/` and prints where it was saved. A
   received name never picks another folder and never replaces a file there. A
   `send-file` stopped halfway goes on at the next `chat` or `send-file` of Alice.

   Give yourself a name and a picture, a JPEG or PNG of up to 1 MiB:

   ```sh
   uv run sotto --data-dir alice profile set --name "Alice A." --avatar me.jpg
   ```

   The profile goes to every contact at Alice's next `chat`, and into every new session
   after that. Bob's chat prints `alice: profile "Alice A.", with an avatar`, `sotto
   --data-dir bob contacts` shows the name next to Bob's own name for Alice, and `sotto
   --data-dir bob profile show alice --avatar-to alice.jpg` writes the picture out. The
   name Bob gave Alice stays the name his client uses. `sotto profile show` prints your
   own profile and `sotto profile clear` clears it at your contacts too.

5. Stop the relay and delete its data: `docker compose down -v`.

Without `--data-dir` the identity lives in `~/.sotto`. `sotto contacts` lists the
contacts, `sotto id` prints the own id and `sotto reset <name>` starts a new session with
a contact. Dial the relay as `127.0.0.1`, not `localhost`: the relay of `compose.yaml`
refuses a login signed for another host name (see `RELAY_NAME` below).

What the alpha does not do yet:

- No TLS on the way to the relay of `compose.yaml`. The client dials a `ws://` URL only
  to a loopback host; `--insecure` overrides that, and then the login and every frame
  cross the network readable. A relay on another machine belongs behind a TLS proxy and
  is dialed as `wss://`.
- The data directory is not encrypted: whoever can read it holds the identity, the keys
  and the message log.
- One device per identity, one-to-one chats, texts and files. No groups, no thumbnails
  from the command line and no history view: a chat prints what arrives while it runs.
- Nothing checks that an id belongs to the person you think; ids are compared out of
  band, by you.
- No security audit.

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
named volume `relay-data`. `RELAY_MAX_PAGES` caps the file, 2097152 pages of 4096 bytes (8 GiB) by
default; an upload, a message or a blob into a full database is refused and the relay
stays up.
`RELAY_ONE_TIME_PREKEY_CAP`, 100 by default, caps the one-time prekeys kept per identity.

The relay keeps a registered identity and its bundle with no expiry. It keeps a message
until its recipient acks it, and for `RELAY_MESSAGE_TTL_SECONDS` at most, 2592000 seconds
(30 days) by default, whether it was delivered or not. Every `RELAY_SWEEP_INTERVAL_SECONDS`,
60 by default, a sweep deletes the expired messages and truncates the `-wal` file, so that
an acked or expired message is then in none of the three files. Until that sweep, and in a
relay that was killed before it, the old bytes are still in the `-wal` file. What the
filesystem, the disk or a backup keeps after that is out of scope (`docs/protocol.md`,
section 13).

The limits of `docs/protocol.md`, section 12, are settings with the defaults of its table:

| Variable                       | Default  | Limit                                              |
|--------------------------------|----------|----------------------------------------------------|
| `RELAY_QUEUE_MAX_MESSAGES`     | 1000     | messages queued for one recipient                  |
| `RELAY_QUEUE_MAX_BYTES`        | 16777216 | payload bytes queued for one recipient             |
| `RELAY_FRAME_BUCKET_SIZE`      | 60       | Send, UploadBundle, FetchBundle and StartBlob frames of one identity in a burst |
| `RELAY_FRAME_REFILL_SECONDS`   | 1        | the time in which one frame token returns          |
| `RELAY_HANDOUT_BUCKET_SIZE`    | 20       | one-time prekeys of one identity handed out in a burst |
| `RELAY_HANDOUT_REFILL_SECONDS` | 300      | the time in which one handout token returns        |
| `RELAY_BLOB_MAX_BYTES`         | 104883216 | the largest blob, announced in LoggedIn           |
| `RELAY_BLOB_QUOTA_BYTES`       | 268435456 | blob bytes held for one uploader                  |
| `RELAY_BLOB_TTL_SECONDS`       | 3196800  | the time after its last write at which a blob expires |

A Send into a full queue gets `QUEUE_FULL`, a StartBlob over the quota gets `QUOTA_FULL`,
a frame over its bucket gets `RATE_LIMITED` and the connection stays open, and a fetch over the handout bucket gets the bundle without
a one-time prekey. The buckets live in the memory of the process: a restart fills them.

`RELAY_METRICS_PORT` turns on a second listener, on `RELAY_HOST`, that answers `/metrics`
with totals of the process in the Prometheus text format: open connections, logins, frames
by type and answer, messages stored, delivered, acked and expired, bundle fetches with and
without a one-time prekey, blobs started, completed, deleted and expired, blob bytes
stored, fetched and held, refusals by limit and the size of the database. No value names
an identity, but the counts of traffic are metadata: keep the port private. A reverse
proxy in front of the relay forwards the WebSocket port only, and `compose.yaml` publishes
the metrics port on `127.0.0.1` only. The WebSocket port answers `404` for `/metrics`. The
listener is off when the variable is not set.

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
a message sent before the restart, and finish an upload of a blob that the restart cut in
the middle. It then checks that the
container runs as a non-root user and exits with 0 on stop, and removes the stand.
Before the restart it reads `/metrics` on `127.0.0.1` and checks that a stored message
and a started blob were counted. `RELAY_PORT` moves the published port off 8765, and `RELAY_METRICS_PORT`
moves the published metrics port off `RELAY_PORT` plus 1000.

## License

Apache-2.0, see [LICENSE](LICENSE).
