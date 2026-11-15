# sotto threat model: the relay half

## Scope and status

This document says whom the relay protocol of [protocol.md](protocol.md) defends against
and where it does not defend. It is the relay half: the relay itself, the network between
a client and the relay, and abuse of the relay by its own users. The client half (the
device, the client store, the end-to-end protocol) comes with part 2 of the specification
[pending: task 9].

- No security audit. Nobody has reviewed this design or its code for security.
- The relay is content-blind and nothing more: it is blind to the content of a message
  and to nothing else about it. The list "What the relay learns" is the other side of
  that word.
- A guarantee in this document cites the test that holds it, in the syntax of section 2.6
  of the protocol. A guarantee whose citation names a task is held by no test in this
  repository, and the code behind it can be missing as well. What the lists admit (what
  the relay learns, what it can do, what is not protected) is no guarantee and needs no
  citation.
- "The relay" in the lists below is whoever controls the relay. The rules of the protocol
  describe the relay of this repository, run unchanged; they bind that code and not the
  person who runs it.

## The attackers

### Whoever runs or seizes the relay

The operator of the relay, the provider of its host, and anyone who takes over the
process, the host, its disk or a backup of it.

- While the relay runs under their control they see every frame and decide every answer:
  everything in "What the relay learns" and in "What the relay can do" is theirs.
- With the disk alone they read what the relay stores at that moment: the bundle of every
  registered identity, and every queued message with its sender, its recipient, its time
  and its ciphertext. The database is not encrypted.

### A network attacker

Someone on the path between a client and the relay.

- The relay process speaks WebSocket without TLS; TLS belongs to a reverse proxy in front
  of it (protocol, section 6.5). On a link without TLS a network attacker reads every
  frame of the connections that pass by and can change, drop and add frames on them: for
  those connections the attacker is in the position of the relay.
- On a link with TLS whose server authentication holds, a network attacker sees the
  addresses, the times and the sizes of what is sent, and can delay or cut a connection.
- A network attacker who breaks the server authentication of TLS, for example with a
  certificate that the client wrongly accepts, can stand between the client and the
  relay and pass the login on. The login is not bound to the TLS session (protocol,
  section 8.7), so the relay accepts it on the attacker's connection. The attacker holds
  a full session of the victim's identity:
  - it receives the victim's queue and can ack it away, so that the victim never sees
    those messages;
  - it can send payloads in the victim's name, which no recipient can decrypt;
  - it can upload one-time prekeys of its own for the victim, which are not signed, and
    so break the start of new sessions with the victim;
  - it can put back a signed prekey that the victim replaced, because the old signature
    still verifies;
  - it can fetch bundles and spend handout buckets in the victim's name.

  For that connection the attacker is also in the position of the relay: everything in
  "What the relay learns" and "What the relay can do" holds for the frames of that client,
  the recipients of its messages and a false Stored included. Of the content it reads
  only ciphertext, and it cannot replace the victim's X25519 identity key or signed prekey
  with keys of its own, because those need a signature of the identity
  [pending: task 5]. That the ciphertext stays closed rests on the end-to-end protocol of
  part 2 [pending: task 9].

### An abuser with free identities

Anyone who can reach the relay. An identity is a key pair and costs nothing: there is no
phone number, no email address and no proof of work behind it. An abuser has as many
identities as it wants, and each of them logs in like any other.

- A limit per identity is fairness between honest clients. It bounds no abuser, because a
  new identity starts with a full frame bucket (protocol, section 12.2).
- The bounds that hold are on scarce things: the queue of one recipient, the database as
  a whole and the one-time prekeys of one target. "Not protected" says what an abuser can
  still do inside those bounds.
- One identity cannot act for another through the relay of this repository: an Ack deletes
  only messages queued for the acking identity [pending: task 6], the sender of a message
  is the identity of the connection and not a field of the frame [pending: task 6], and an
  upload changes only the bundle of the identity that is logged in [pending: task 5].

## What the relay learns

Whoever controls the relay learns all of this, with or without the rules of the protocol:

- The network address of every client, the time of every connection and how long it stays
  open. Without a proxy the relay process sees the address of its peer; behind a reverse
  proxy the proxy sees it, whether it passes it on or not.
- The headers of the WebSocket handshake. Those that a client library sends by default
  name the client program and its version.
- The identity key behind every connection: a stable name for a user, and with it which
  addresses that user connects from and when it is online.
- For every message: the sender, the recipient, the time, the length of the payload and
  the message id.
- When a message was delivered and when it was acked, that is, when the recipient was
  online and its client handled the message.
- Who fetched whose bundle, and when: who is about to start a session with whom.
- The bundle of every registered identity: its public keys, when the signed prekey is
  replaced, how many one-time prekeys are stored and how fast they are used.
- The depth of every queue: how many messages wait for a recipient and how large they are.
- Whether a given id is registered.
- The parts of a payload that are not encrypted. The payload is opaque to the relay
  protocol, and the relay of this repository does not parse it [pending: task 6], but its
  bytes pass through. Part 2 specifies the envelope; the message header is not encrypted,
  so ratchet public keys and message counters are readable [pending: task 9].

The relay does not learn the content of a message: it holds no key that opens a payload.
That rests on the end-to-end protocol of part 2 [pending: task 9].

What the relay of this repository writes down, run unchanged:

- The database holds the bundle of every registered identity [pending: task 5] and every
  queued message with its sender, recipient, message id, payload and time of storing
  [pending: task 6].
- A message leaves the database when its recipient acks it or when it expires. "Deleted
  after the ack" means: after the next sweep its payload and its message id are in none of
  the files of the database, the write-ahead log included (protocol, section 13)
  [pending: task 7].
- The log is JSON lines on standard output
  [test: tests/test_process.py::test_relay_logs_json_lines_and_exits_0_on_sigterm]. No log
  line holds payload bytes, a nonce, a signature, a key, a full user id, a pair of sender
  and recipient or the network address of a client, on error paths included
  [pending: task 4].
- Metrics are counters and gauges without a label that names an identity. They are served
  on a listener of their own, which is off unless it is configured, and never on the
  WebSocket port [pending: task 8].

## What the relay can do

Whoever controls the relay can do all of this, and no rule of the protocol stops it:

- Drop a message, delay it, deliver messages in another order, withhold some and deliver
  others, and replay a message that was delivered and acked before.
- Answer Stored for a message it does not store, and keep a message that was acked or
  that expired, with its sender, recipient and time, for as long as it likes.
- Refuse service to anyone, to everyone or to chosen pairs, and give a false reason:
  claim that a registered id is not registered, or that a queue is full.
- Deliver a payload of its own under any sender. The recipient's client cannot decrypt
  it [pending: task 9].
- Hand out a bundle with a signed prekey that the identity replaced long ago: the old
  signature still verifies.
- Change what is not signed in a bundle: the prekey ids and the one-time prekey. It can
  hand out one one-time prekey to several clients or hand out a key of its own. The result
  is a session that does not start [pending: task 9].
- Report a wrong count of stored one-time prekeys, so that a client uploads none when it
  has to, or more than it has to.
- Keep a target without one-time prekeys: withhold them, or let fetches spend the handout
  bucket of the target, so that every bundle of the target goes out without one.
- Keep the Login of a connection and show it to anyone. The signature proves that the
  holder of the identity key logged in at a relay with this server name. The relay chooses
  the server nonce, so it can pick one that shows the login is not older than a given
  date. The signatures of a bundle prove in the same way that the identity published those
  keys.
- Record everything in "What the relay learns" and keep it.

What it cannot do:

- Make a client accept an X25519 identity key or a signed prekey that the identity did
  not sign
  [test: tests/crypto/test_identity.py::test_changed_signed_field_fails_the_bundle_check]
  [test: tests/crypto/test_identity_vectors.py::test_negative_vectors_raise_their_named_error],
  or accept another X25519 identity key for a contact whose key the client pinned
  [test: tests/crypto/test_identity.py::test_pinned_x25519_identity_key_refuses_another_one].
- Turn a login into a prekey statement or the reverse: the three signed strings have
  distinct prefixes
  [test: tests/crypto/test_identity.py::test_signed_strings_of_two_purposes_never_coincide].
  The relay never chooses all the bytes of a login string, because the client adds a nonce
  of its own [pending: task 4].
- Use a login it received to log in at a relay with another server name, or on another
  connection [pending: task 4]. Relays that clients dial under one host, on different
  ports, share a server name and are not told apart (protocol, section 8.2).
- Read the content of a message, or make a message of its own that the recipient's client
  accepts [pending: task 9].

## Not protected

- Metadata. Everything in "What the relay learns" is known to whoever controls the
  relay: who talks to whom, when and how much.
- Delivery. Nothing proves to a sender that a message reached its recipient: Stored says
  that the relay stored it. The relay and everyone on the path can drop and delay
  messages.
- Order and completeness. The relay can reorder messages and withhold some of them.
- The link without TLS. The relay process has no TLS, and the stand of this repository
  has none either. On such a link a network attacker has the position of the relay.
- The login under a broken TLS. There is no channel binding: a network attacker who
  breaks the server authentication of TLS and passes a login on holds a full session of
  that identity ("The attackers"). It learns the metadata of that identity and, of the
  content, reads only ciphertext.
- Whether an id is registered. Anyone who knows an id can ask: a Send that is refused
  names its reason, UNKNOWN_RECIPIENT, and a bundle fetch answers with a Bundle or with
  NOT_FOUND. An id is a 32-byte key that cannot be guessed, but a known one can be
  confirmed.
- When a client is online. Anyone who knows an id can tell when its client handles its
  queue, in three ways. A sender whose message is queued for the id repeats the message id
  with another recipient: the answer comes from the first message while the relay holds
  it, and the repeat is a new message once the recipient acked the first (protocol,
  section 10.3). Such a repeat stores nothing for the id. A full queue answers QUEUE_FULL
  until the recipient acks. A fetched bundle shows whether a one-time prekey is left and
  whether the signed prekey changed since the last fetch.
- The queue of one recipient. Free identities can fill it up to QUEUE_MAX_MESSAGES or
  QUEUE_MAX_BYTES; with the defaults about 256 messages of the largest payload do. Until
  the recipient acks, every honest sender gets QUEUE_FULL.
- The storage ceiling. Free identities can fill the database up to MAX_PAGES, with the
  defaults about 64 full queues of identities they registered themselves. Until those
  messages are acked or expire, every Send and every upload gets STORAGE_FULL. Bundles
  count toward the ceiling as well, never expire, and no frame deletes one: a database
  filled with the bundles of free identities, each with ONE_TIME_PREKEY_CAP one-time
  prekeys, stays full until the operator removes them.
- One-time prekeys. Anyone can keep a target without one-time prekeys by spending its
  handout bucket: 20 fetches empty it, and after that one fetch every 5 minutes takes each
  token as it returns. Every other client gets a bundle without a one-time prekey. The
  bucket keeps the stored keys from being taken in one burst [pending: task 8]; it does
  not keep them available. What the first messages of a session lose without a one-time
  prekey is stated in the client half [pending: task 9].
- Connections and Acks. There is no limit per address: anyone can open connections and
  hold them. A logged-in identity can send Acks without limit, and each makes the relay
  look up every pair it names (protocol, section 12.2).
- Data at rest. A queued message stays on the disk of the relay, with its sender,
  recipient and time, until it is acked, for up to MESSAGE_TTL_SECONDS. Bundles stay
  without an expiry. Whoever gets the disk reads them.
- The limits of erasure. Between a deletion and the next sweep the deleted bytes are
  still in the write-ahead log. A relay that was killed keeps them there until it runs
  again. What the filesystem, the storage device, a snapshot or a backup keeps is out of
  scope (protocol, section 13).
- Durability. A message that was answered with Stored survives a kill of the relay
  process [pending: task 6]. It can be lost with the power when the host does not honour
  fsync.
- The clock. The relay's clock decides when a message expires.
- The device. A client whose private key or store is taken is the subject of the client
  half [pending: task 9].
