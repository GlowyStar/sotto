# sotto threat model

## Scope and status

This document says whom the protocol of [protocol.md](protocol.md) defends against and
where it does not defend. It has two halves. The relay half is about the relay protocol:
the relay itself, the network between a client and the relay, and abuse of the relay by
its own users. The client half, from "The client half" on, is about the end-to-end
protocol: a peer, the device with its store, and what the keys of a session cover.

- No security audit. Nobody has reviewed this design or its code for security.
- The relay is content-blind and nothing more: it is blind to the content of a message
  and to nothing else about it. The list "What the relay learns" is the other side of
  that word.
- A guarantee in this document cites the test that holds it, in the syntax of section 2.6
  of the protocol. What this document admits (what the relay learns, what it can do,
  what is not protected, what a peer or a thief can do) is no guarantee and needs no
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
  - it can send payloads in the victim's name. No recipient can decrypt one; a recipient
    that has the victim as a contact is shown a message that could not be read;
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
  [test: tests/test_bundles.py::test_refused_upload_gets_the_code_of_its_reason_and_stores_nothing].
  That the ciphertext stays closed rests on the key agreement and the ratchet (protocol,
  sections 16 to 18)
  [test: tests/crypto/test_x3dh.py::test_both_sides_derive_the_same_secret_and_associated_data]
  [test: tests/crypto/test_ratchet_vectors.py::test_positive_vectors_replay_byte_for_byte]
  [test: tests/crypto/test_ratchet.py::test_random_conversations_keep_the_invariants].

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
  only messages queued for the acking identity [test: tests/test_messages.py::test_ack_of_a_message_queued_for_another_identity_deletes_nothing], the sender of a message
  is the identity of the connection and not a field of the frame [test: tests/test_messages.py::test_no_client_frame_names_its_sender], and an
  upload changes only the bundle of the identity that is logged in
  [test: tests/test_bundles.py::test_upload_changes_only_the_bundle_of_its_own_identity].

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
  protocol, and the relay of this repository does not parse it
  [test: tests/test_messages.py::test_message_to_an_online_recipient_is_delivered_byte_for_byte], but its
  bytes pass through. The envelope leaves readable: which messages are the first of a
  session, the ratchet public key and the two message counters of every message, and the
  length of a text in steps of 256 bytes. "What the relay sees of the end-to-end layer"
  has the full list.

The relay does not learn the content of a message: it holds no key that opens a payload
(protocol, sections 16 to 18) [test: tests/client/test_transport.py::test_marker_text_is_in_no_frame_log_or_file_of_the_relay].

What the relay of this repository writes down, run unchanged:

- The database holds the bundle of every registered identity
  [test: tests/test_storage.py::test_relay_restarted_on_the_same_file_serves_the_bundle] and every
  queued message with its sender, recipient, message id, payload and time of storing
  [test: tests/test_storage.py::test_message_is_one_row_until_its_recipient_acks_it].
- A message leaves the database when its recipient acks it or when it expires,
  MESSAGE_TTL_SECONDS after it was stored, 30 days by default (protocol, section 10.7)
  [test: tests/test_storage.py::test_expired_message_is_deleted_by_the_sweep_and_never_delivered]. "Deleted after the ack" means: after the next sweep, every
  SWEEP_INTERVAL_SECONDS, 60 seconds by default, its payload and its message id are in
  none of the files of the database, the write-ahead log included (protocol, section 13)
  [test: tests/test_storage.py::test_acked_message_is_in_no_file_of_the_database_after_the_sweep]
  [test: tests/test_storage.py::test_expired_message_is_in_no_file_of_the_database_after_the_sweep].
- The log is JSON lines on standard output
  [test: tests/test_process.py::test_relay_logs_json_lines_and_exits_0_on_sigterm]. No log
  line holds a nonce, a signature, a key, a full user id or the network address of a
  client. Every test of the relay runs under a check of the log, which fails on eight bytes
  in a row of a message of the test and on the address of one of its clients
  [test: tests/test_logs.py::test_scan_finds_bytes_of_the_wire_in_a_log_line]. On an error
  path an exception is logged as its type and its stack, without its text
  [test: tests/test_logs.py::test_text_of_an_exception_stays_out_of_the_line], the failure
  of a connection handler included
  [test: tests/test_connection.py::test_failed_handler_closes_with_1011_and_logs_no_text_of_the_exception].
  No log line holds payload bytes or a pair of sender and recipient
  [test: tests/test_messages.py::test_send_to_an_identity_that_is_not_registered_answers_unknown_recipient]
  [test: tests/test_storage.py::test_failed_send_closes_with_1011_and_the_relay_serves_on].
- Metrics are counters and gauges without a label that names an identity. They are served
  on a listener of their own, which is off unless it is configured, and never on the
  WebSocket port
  [test: tests/test_metrics.py::test_metrics_move_by_a_login_send_delivery_and_ack]
  [test: tests/test_metrics.py::test_metrics_listener_is_off_unless_its_port_is_set]
  [test: tests/test_routing.py::test_websocket_port_answers_404_for_metrics].

## What the relay can do

Whoever controls the relay can do all of this, and no rule of the protocol stops it:

- Drop a message, delay it, deliver messages in another order, withhold some and deliver
  others, and replay a message that was delivered and acked before.
- Answer Stored for a message it does not store, and keep a message that was acked or
  that expired, with its sender, recipient and time, for as long as it likes.
- Refuse service to anyone, to everyone or to chosen pairs, and give a false reason:
  claim that a registered id is not registered, or that a queue is full.
- Deliver a payload of its own under any sender, or change a real message: its sender,
  its message id, its header, its nonce or its sealed bytes, or the X25519 identity key
  or the ephemeral key of its initial header. The recipient's client does not decrypt
  the result (protocol, section 20.3)
  [test: tests/client/test_hostile_relay.py::test_lying_relay_gives_no_text_and_leaves_the_store_unchanged]. From a sender that is not a
  contact it is dropped unseen. From a contact it is shown as a message that could not
  be read: the relay can put such a notice under the name of any contact, as often as it
  likes.
- Change the rest of an envelope: how its fields are encoded, a prekey id of an initial
  header whose session exists, the signature bytes of an initial header, and whether a
  message carries the initial header of its session. The client then reads the plaintext
  that the sender sealed or nothing. No change gives another plaintext, another sender
  or another message id (protocol, sections 16.9 and 18.2)
  [test: tests/client/test_hostile_relay.py::test_changed_prekey_ids_of_a_message_with_a_record_change_nothing]
  [test: tests/client/test_hostile_relay.py::test_lying_relay_gives_no_text_and_leaves_the_store_unchanged].
- Make a real message unreadable for good: by changing it, or by the order in which it
  delivers. A message fails when it arrives after its skipped key was purged, when it
  arrives while more than 1000 earlier messages of its chain are missing, and, for an
  initial message whose session the recipient does not hold, when it arrives after the
  grace period of its signed prekey (protocol, sections 17.7, 17.8 and 21.2). Every
  Deliver is acked, and no frame asks a peer to send a message again.
- Hand out a bundle with a signed prekey that the identity replaced long ago, or refuse
  to store the next one: the old signature still verifies. A session made with that key
  starts during its grace period, 37 days from the moment the identity made the next
  key, and not after (protocol, section 21.2)
  [test: tests/client/test_lifecycle.py::test_initial_message_under_a_replaced_signed_prekey_decrypts_only_in_the_grace_period].
- Keep a client from logging in. The client then makes no new signed prekey (protocol,
  section 21.2). Its newest one stays in use for as long, which stretches the time in
  which the first messages of sessions without a one-time prekey can be opened with
  keys taken from that client.
- Change what is not signed in a bundle: the prekey ids and the one-time prekey. It can
  hand out one one-time prekey to several clients or hand out a key of its own. The result
  is a session that does not start; of two sessions made with one key, the first that
  reaches the responder starts and the other does not. When the relay takes the one-time
  prekey away, the result is a session without one (protocol, section 16.9)
  [test: tests/crypto/test_x3dh.py::test_replaced_one_time_prekey_gives_the_responder_another_secret]
  [test: tests/client/test_session.py::test_substituted_one_time_prekey_ends_in_a_decrypt_failure_and_keeps_the_prekey]
  [test: tests/client/test_session.py::test_one_time_prekey_handed_to_two_initiators_starts_one_session].
- Report a wrong count of stored one-time prekeys, so that a client uploads none when it
  has to, or more than it has to. Whatever the count says, a client holds at most 1000
  private keys of one-time prekeys (protocol, section 21.3)
  [test: tests/client/test_lifecycle.py::test_held_one_time_prekeys_are_bounded_by_deleting_the_lowest_ids].
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
  or accept another X25519 identity key for a contact whose key the client pinned, in a
  bundle
  [test: tests/crypto/test_identity.py::test_pinned_x25519_identity_key_refuses_another_one]
  or in an initial header (protocol, section 16.8)
  [test: tests/client/test_session.py::test_initial_header_that_fails_step_1_or_2_changes_nothing].
- Turn a login into a prekey statement or the reverse: the three signed strings have
  distinct prefixes
  [test: tests/crypto/test_identity.py::test_signed_strings_of_two_purposes_never_coincide].
  The relay never chooses all the bytes of a login string, because the client adds a nonce
  of its own
  [test: tests/test_login.py::test_login_signed_over_another_client_nonce_closes_with_3000].
- Use a login it received to log in at a relay with another server name
  [test: tests/test_login.py::test_login_signed_for_another_server_name_closes_with_3000], or
  on another connection
  [test: tests/test_login.py::test_login_replayed_on_another_connection_closes_with_3000]. Relays that clients dial under one host, on different
  ports, share a server name and are not told apart (protocol, section 8.2).
- Read the content of a message, or make a message of its own that the recipient's client
  accepts (protocol, sections 16 to 18)
  [test: tests/client/test_hostile_relay.py::test_arbitrary_bytes_from_any_sender_end_in_a_named_result]
  [test: tests/client/test_hostile_relay.py::test_lying_relay_gives_no_text_and_leaves_the_store_unchanged].
- Make a message decrypt at another identity than the one its sender meant, by handing
  out the X25519 keys of one identity under the signature of another: the associated
  data of every message names the Ed25519 keys of both sides (protocol, section 16.5)
  [test: tests/crypto/test_x3dh.py::test_unknown_key_share_gives_the_same_secret_under_other_associated_data]
  [test: tests/client/test_hostile_relay.py::test_lying_relay_gives_no_text_and_leaves_the_store_unchanged].
- Make a client read a message twice, or start a second session from an initial message
  that it replays, as it was sent or with other bytes in its ephemeral key that give
  the same secret (protocol, sections 16.5 and 20.4)
  [test: tests/client/test_lifecycle.py::test_replayed_initial_message_gives_no_text_after_its_session_left_and_after_a_restart]
  [test: tests/client/test_hostile_relay.py::test_lying_relay_gives_no_text_and_leaves_the_store_unchanged].
- Make a client start a key agreement or delete a one-time prekey by delivering messages
  that fail: a failure starts nothing and deletes nothing (protocol, section 20.3)
  [test: tests/client/test_hostile_relay.py::test_lying_relay_gives_no_text_and_leaves_the_store_unchanged].

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
  bucket keeps the stored keys from being taken in one burst
  [test: tests/test_limits.py::test_fetches_past_the_handout_bucket_leave_the_stored_one_time_prekeys]; it does
  not keep them available. What the first messages of a session lose without a one-time
  prekey is stated under "One-time prekeys are not authenticated".
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
  process [test: tests/test_process.py::test_message_answered_with_stored_survives_a_kill_of_the_relay]. It can be lost with the power when the host does not honour
  fsync.
- The clock. The relay's clock decides when a message expires.
- Prekey ids. A client numbers its signed prekeys and its one-time prekeys from 1 upward
  (protocol, section 21.1), and the relay hands out the one-time prekey that was stored
  first. Whoever fetches the bundle of an identity learns from the id of the signed
  prekey about how many weeks the identity has been in use, and from the one-time prekey
  ids of two fetches about how many were handed out in between, that is, how many
  sessions others started with that identity.
- Lengths. The padding hides the length of a text inside a step of 256 bytes and no
  further: the relay sees how many steps a message has.
- Notices of failure. Whoever controls the relay can make a client show that a message of
  a contact could not be read, with or without a real message behind it ("What the relay
  can do").
- The device. A client whose keys or store are taken is the subject of "A thief of the
  device or of the data directory".

## The client half

The rest of this document is about the end-to-end protocol (protocol, sections 16 to 25)
and about the device that runs a client. The attackers of the relay half remain. Two join
them: the peer, and whoever gets the device or a copy of its data directory.

## A peer

The peer is the identity at the other end of a session: a contact that the user added by
its id.

- Nothing protects a message from the peer who received it. The peer holds the
  plaintext. It can keep it, copy it and show it to anyone, and no rule of the protocol
  makes its client delete anything.
- A peer cannot be told from the person the user has in mind by anything in the
  protocol: a contact is an id, and "The id and its channel" says what that rests on.
- Two things that a peer can make a client keep are bounded: 3 sessions (protocol,
  section 20.1)
  [test: tests/client/test_sessions.py::test_fourth_session_drops_the_oldest_and_reports_its_missing_messages], and 2000 skipped message keys in each (protocol,
  section 17.8)
  [test: tests/crypto/test_ratchet.py::test_the_cap_removes_the_oldest_entry_and_counts_it].
  What it can make a client compute for one message is bounded as well: a header that
  asks for more than 1000 skipped keys is refused before a key is derived
  [test: tests/crypto/test_ratchet.py::test_too_many_skipped_keys_are_refused_before_any_key_is_derived].
- The rest grows with what a contact sends and has no cap: the message log, a seen id
  for every accepted message for 37 days, and a record for every accepted initial
  message, kept while its session or the private key of its signed prekey exists
  (protocol, section 20.4). A contact needs no one-time prekey of the client for an
  initial message. The rate at which the relay takes messages is the only brake, and
  the user's remedy is to remove the contact.
- A text is whatever the peer chose to send, control characters included. The
  command-line client escapes them before it prints [test: tests/client/test_cli.py::test_peer_text_is_printed_with_control_characters_escaped].
- A peer that stops answering, loses its store or goes back to an older copy of it
  leaves messages that fail and sessions that only a reset repairs (protocol,
  section 20.6). The user sees the failures; the protocol does not say why they happen.
- An identity that is not a contact is no peer. Its messages are dropped before a byte of
  them is parsed, shown nowhere and acked (protocol, section 20.3)
  [test: tests/client/test_session.py::test_stranger_is_acked_before_a_byte_is_parsed].
  Whoever knows an id can still fill the queue of that id at the relay ("Not
  protected").

## A thief of the device or of the data directory

Someone who takes the device, reads its disk, or gets a copy of the data directory of a
client: from a backup, a synchronised folder, another account with the rights to read it,
or a program that runs as the user.

- Nothing is encrypted at rest. The data directory holds the seed of the identity, every
  private key, the state of every session and the text of every message that was sent
  and received (protocol, section 22.1). Whoever can read it has all of that.
- The file modes are the whole protection: the directory is 0700, the file 0600, and the
  client of this repository refuses to start on wider modes
  [test: tests/client/test_client_store.py::test_start_is_refused_when_a_mode_gives_a_right_to_the_group_or_others]. That
  stops another account of the same machine. It does not stop the administrator of the
  machine, a program that runs as the user, a backup, or anyone with the disk.
- A copy of the data directory clones the identity. Whoever holds the copy is the user
  for the relay and for every contact: it logs in, receives the queue and can ack it
  away, reads the message log, decrypts what arrives on the copied sessions, sends on
  them, and starts new sessions with any contact in the user's name.
- A clone shows itself only by chance. The relay keeps one connection per identity, so
  a copy and the original that are connected at the same time close each other with
  code 4001 (protocol, section 8.5). That is the only direct sign, and it also shows
  when the user starts the client twice. A copy that connects only while the original
  is offline gives none: the user sees at most messages that could not be read or a
  notice of missing messages later, and the protocol does not say why.
- A copy also lets its holder speak to the user as any contact, when it controls the
  relay or a link without TLS. The private key of one signed prekey is enough to make
  an initial message that the user's client accepts under the id of a contact: the
  signature over that contact's X25519 identity key is public in its bundle, and the
  other values of the key agreement are the forger's own. A copied session is enough to
  make messages inside that session. This lasts for a signed prekey until the user's
  client deletes its private key (protocol, section 21.2), and for a session until it
  has healed as "Forward secrecy and post-compromise security" says.
- The clone cannot be locked out. "Compromise of the identity" says why.
- Keys cannot be zeroized in the memory of a Python process. The command-line client is
  written in Python, where a byte string cannot be overwritten, values are copied
  freely and memory is freed without being cleared. A key that the protocol calls
  deleted can remain in the memory of the process, in swap and in a core dump until the
  memory is used again. "Deleted" in the protocol is a statement about the files of the
  store (protocol, section 22.3), not about memory.
- Below the files nothing is promised. The store deletes with `secure_delete` and keeps
  no write-ahead log, so a deleted key is in none of its files after the commit
  [test: tests/client/test_lifecycle.py::test_replaced_chain_keys_are_in_no_file_of_the_store]. The blocks of a removed journal file, a snapshot of the filesystem
  and a backup can still hold it.
- A data directory that is put back from an older copy is an older state of every
  session. The client then sends under chain keys it used before, and the peer refuses
  those messages; what it receives can fail as well. The random nonce of every message
  (protocol, section 18.1) is the one hedge against a message key that is used twice.
  The protocol has no way to move or to back up an identity.
- The clock of the device decides when a signed prekey is replaced and when private
  keys, records and seen ids are deleted (protocol, section 21). A clock that is set
  back keeps keys longer than the protocol means; one that is set forward deletes them
  early, and messages on the way fail.

## Forward secrecy and post-compromise security

Both are properties of the keys of a session. They say what a thief of the session state
cannot open; they say nothing about what the client keeps in readable form.

What forward secrecy covers:

- The key of a message is deleted when the message is encrypted or decrypted, and a
  chain key cannot be turned back into the one before it (protocol, sections 17.4 to
  17.7). A copy of the state of a session that is taken after a message does not open
  that message as it was recorded on the wire
  [test: tests/crypto/test_ratchet.py::test_copy_after_a_message_opens_none_of_the_messages_before].
- After the commit that follows a message, the chain key that was replaced is in none of
  the files of the store
  [test: tests/client/test_lifecycle.py::test_replaced_chain_keys_are_in_no_file_of_the_store].

What it does not cover, because it stays on disk:

- The message log. The text of every message that was sent or received stays in the data
  directory in readable form. Forward secrecy protects recorded traffic, not the
  client's own copy.
- Skipped message keys. The key of a message that has not arrived is kept until the
  message arrives or the key is purged, after 5 DH ratchet steps or when the session
  holds 2000 of them (protocol, section 17.8). A thief of the state opens those
  messages if it also recorded them.
- The first messages of a session, on the side of the responder. They can be opened from
  the recorded traffic with the private keys of the responder's X25519 identity key and
  signed prekey and, when one was used, of the one-time prekey. The one-time prekey
  private key is deleted when the first of those messages is accepted. The private key
  of a signed prekey is deleted 37 days after the client made the next one, which it
  does after a login once the key is 7 days old: with the defaults about 44 days after
  the key was made, and not earlier (protocol, section 21.2)
  [test: tests/client/test_lifecycle.py::test_initial_message_under_a_replaced_signed_prekey_decrypts_only_in_the_grace_period]
  [test: tests/client/test_lifecycle.py::test_rotation_follows_the_age_of_the_newest_signed_prekey]. The
  client counts on its own clock and waits for no answer to an upload. It deletes when
  it starts or logs in and makes the next key only after a login: a client that does
  not run, that stays on one connection or that the relay keeps from logging in can
  keep the key longer. The messages in question are those the initiator sent before it
  received the first answer.
- Memory and what lies below the files ("A thief of the device or of the data
  directory").

What post-compromise security covers:

- A copy of the state of a session loses its use when the session moves on without it.
  Once the owner of the state has taken a DH ratchet step that the copy did not see, the
  copy opens no message that the owner sends after that step and none that the peer
  sends in answer
  [test: tests/crypto/test_ratchet.py::test_copy_stops_opening_after_a_dh_ratchet_step_it_did_not_see].

What it does not cover:

- The messages that the peer sends under the ratchet key that set off the owner's step.
  The copy holds the root key and the owner's older ratchet private key and reads the
  peer's key in the header, so it derives that whole receiving chain. It opens the
  messages of that chain, those sent after the step included, and can make messages on
  it. That ends when the peer has received a message of the owner under the owner's new
  key: from then on the peer sends under a new key of its own.
- A thief who has the identity keys. A copy of the data directory holds them next to the
  sessions, and with them the thief starts new sessions and answers initial messages in
  the user's name. No ratchet step heals that.
- A thief who uses the copy. With the state of a session it can send in the session
  before the owner does and take the session over.
- A session in which only one side sends. A DH ratchet step needs a message from the
  peer with a new ratchet key.
- The skipped message keys that the copy holds.

## Compromise of the identity

The identity is one Ed25519 seed and the private key of its X25519 identity key. Its
compromise is total and permanent.

- Total. Whoever holds the two keys is the user for the relay and for every contact. It
  logs in and receives everything that is sent to the user from then on. It publishes
  signed prekeys of its own, so that every new session with the user is a session with
  it. It starts sessions with any contact as the user. The seed alone is enough to log
  in and to sign any key.
- Permanent. The user id is the key (protocol, section 3.2). The protocol has no way to
  replace the key of an id, to revoke it or to tell a contact that it is lost, and the
  relay keeps an identity without an expiry. The X25519 identity key cannot be replaced
  either (protocol, section 5.3).
- The one remedy lies outside the protocol: a new identity, whose id has to reach every
  contact again over an authentic channel, and contacts who remove the old id by hand.
  Until a contact has done that, the holder of the old keys is the user for that
  contact.
- The messages of before the compromise are covered by what "Forward secrecy and
  post-compromise security" says, and by nothing more.

## The id and its channel

Every check of the protocol starts from the user id: the bundle of a contact has to
carry the key that its id encodes, and an initial message is accepted only from the key
of a contact (protocol, sections 5.4 and 16.8). The id is the whole public key, so two
users who hold each other's ids hold each other's keys.

- The id has to reach the peer over an authentic channel: one on which the two users
  know whom they hear and on which nobody can change what is said. The protocol does
  not provide that channel and cannot check it.
- Whoever replaces an id on its way gives the user its own id in place of the peer's.
  The user then has a valid session with the wrong identity. Done to both sides, this
  puts the attacker between them: it reads every message and passes it on in a session
  of its own.
- Nothing later repairs a substituted id. There is no safety number and no other
  comparison of keys after the fact, and no session, pin or warning shows the
  substitution: the client holds exactly the key it was given.
- The pinned X25519 identity key protects against a later bundle that carries another
  X25519 key under the same id
  [test: tests/crypto/test_identity.py::test_pinned_x25519_identity_key_refuses_another_one].
  It says nothing about the id itself.

## What the relay sees of the end-to-end layer

The relay protocol carries the envelope of a message as bytes that the relay of this
repository does not parse
[test: tests/test_messages.py::test_message_to_an_online_recipient_is_delivered_byte_for_byte]. Whoever controls the relay can parse them.
Everything in the envelope but the sealed text is readable (protocol, sections 17.5 and
19):

- Which messages are session-initial. A message with an initial header is one of the
  first of a session. The relay sees who started a session with whom, when, and when
  the initiator received the first answer, because the header stops then.
- The initial header: the X25519 identity key of the sender with its signature, the
  ephemeral key, and the ids of the prekeys that were used, which also tell whether the
  session has a one-time prekey.
- The ratchet public key in the header of every message. It changes when the direction
  of a conversation turns, so it shows the turns even to someone who sees one direction
  only.
- The two counters in the header of every message: the number of the message on its
  chain and the length of the chain before. They show how many messages each side sent
  and which of them did not arrive.
- The nonce of every message.
- The length of a text, as a bucket: the plaintext is padded to a multiple of 256 bytes
  before it is sealed (protocol, section 19.6), so the relay learns the number of
  256-byte blocks and nothing finer
  [test: tests/client/test_envelope.py::test_padding_adds_the_mark_and_zero_bytes_up_to_the_next_block]. A message with an initial header
  is longer by that header.

The header is not encrypted, and hiding it is not part of this protocol (protocol,
section 26). What the relay does not see is the sealed text: it holds no key of a session
(protocol, sections 16 to 18) [test: tests/client/test_transport.py::test_marker_text_is_in_no_frame_log_or_file_of_the_relay].

## One-time prekeys are not authenticated

A one-time prekey carries no signature, and neither does a prekey id (protocol,
section 5.2).

- This gives the relay a denial of service. It can replace a one-time prekey with a key
  of its own, hand one out twice, or change an id. Each of these ends in a session that
  does not start: the first messages fail at the responder. Of two sessions made with
  one key, the first that reaches the responder starts and the other does not. None lets
  the relay read a message, because the secret of a session also rests on the signed
  keys (protocol, section 16.9)
  [test: tests/crypto/test_x3dh.py::test_replaced_one_time_prekey_gives_the_responder_another_secret]
  [test: tests/client/test_session.py::test_substituted_one_time_prekey_ends_in_a_decrypt_failure_and_keeps_the_prekey]
  [test: tests/client/test_session.py::test_one_time_prekey_handed_to_two_initiators_starts_one_session]. A session that
  does not start can also be without the protection of its one-time prekey: the relay
  holds the private key of a key of its own, and a real key keeps its private key in the
  responder's store for as long as no initial message that names it is accepted
  (protocol, section 21.3). What the initiator sends on such a session is covered like
  the first messages of a session without a one-time prekey, below.
- The relay can also hand out a bundle without a one-time prekey, and so can anyone who
  empties the handout bucket of an identity ("Not protected"). A client cannot tell why
  a bundle has none. It starts the session all the same: a client that refused would be
  cut off from that contact by anyone with free identities.
- What a session without a one-time prekey loses:
  - Forward secrecy for its first messages lasts only as long as the signed prekey. The
    messages that the initiator sent before the first answer can be opened from recorded
    traffic by whoever later takes the responder's private keys, until the responder
    deletes the private key of that signed prekey. With the defaults that is about 44
    days after it made the key and not earlier: 7 days until it makes the next key and
    37 after. The responder counts on its own clock and waits for no answer of the
    relay, but it makes the next key only after a login and deletes only when it starts
    or logs in: a client that does not run, that stays on one connection or that the
    relay keeps from logging in can keep the key longer (protocol, section 21.2). With a
    one-time prekey that time ends when the responder accepts the first message.
  - Nothing in the key agreement is fresh on the side of the responder, so the same
    initial message could be accepted again. The responder's record of accepted initial
    messages refuses the replay while the session or the private key of the signed
    prekey exists, and without that key no key agreement runs (protocol, section 20.4)
    [test: tests/client/test_lifecycle.py::test_replayed_initial_message_gives_no_text_after_its_session_left_and_after_a_restart].

## No post-quantum protection

The key agreement and the ratchet rest on X25519 alone (protocol, section 25.4). Whoever
records the traffic of a relay and later has a quantum computer that breaks X25519 can
open the recorded messages. The Signal applications run a post-quantum key agreement,
PQXDH, and a post-quantum ratchet beside the Double Ratchet; this protocol has neither,
and reserves nothing for them but its version numbers.

## No claim of deniability

This project claims no deniability.

- One fact is stated: no signature covers the content of a message (protocol,
  section 25.5). A message is authenticated by keys that both sides of a session hold.
- That is no promise that a user can deny a conversation. The relay sees who sends to
  whom. A login signature shows that the holder of an identity key was connected at a
  time the relay can narrow down, and the signatures of a bundle show that the identity
  published its keys ("What the relay can do").
- A peer can show what it received. Whether that convinces anyone is outside this
  document.
