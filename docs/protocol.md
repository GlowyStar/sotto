# sotto protocol

Part 1, sections 1 to 15: identity, the prekey bundle and the relay protocol. Part 2,
sections 16 to 25: the end-to-end protocol between two clients. Sections 26 and 27 close
both parts. Part 3, sections 28 to 34: attachments, that is, files and photos. Part 4,
sections 35 to 37: the profile, a display name and an avatar. Appendix A follows
section 37.

## 1. Status and scope

### 1.1 What this document is

sotto is an end-to-end encrypted one-to-one messenger. Clients exchange ciphertext through
a relay that holds no key that opens a message (sections 16 to 18) [test: tests/client/test_transport.py::test_marker_text_is_in_no_frame_log_or_file_of_the_relay].
This document is the contract between the implementations: the relay and the command-line
client of this repository, and a macOS client in a repository of its own. It is written at
the level of bytes. Where an implementation and this text disagree, the implementation is
wrong.

Part 1 specifies:

- the identity of a user and its text form, the user id (section 3);
- the three byte strings an identity key signs (section 4);
- the prekey bundle (section 5);
- the protocol between a client and the relay: transport, frames, login, bundles,
  messages, errors, limits and erasure (sections 6 to 13);
- versioning and the format of the shared test vectors (sections 14 and 15).

Part 2 specifies what two clients do with each other through the relay: the key agreement,
the ratchet, the encryption of a message and the rules around them. Section 1.4 lists its
sections.

Part 3 specifies files: the blob cipher, the frames that move a blob through the relay,
the attachment of a message and the rules of a client around them (section 28).

Part 4 specifies the profile that a client sends to its contacts: a display name and an
avatar that travels as an attachment of part 3 (section 35).

### 1.2 Status

- No security audit. Nobody has reviewed this protocol or its implementations for
  security. Do not rely on it to protect anything that matters.
- Every guarantee of parts 1 to 4 carries a citation (section 2.6), which names the
  test that holds it.
- Field numbers and signed byte layouts are frozen from the moment they are merged
  (sections 4.1 and 7.2).

### 1.3 Two version numbers

| Version                     | Value | Covers                                                    |
|-----------------------------|-------|-----------------------------------------------------------|
| Relay protocol version      | 1     | Sections 6 to 13, the login string of section 4.2, and sections 30 and 31 |
| End-to-end protocol version | 1     | Sections 3 and 5, the key statements of sections 4.3 and 4.4, sections 16 to 25, sections 29, 32 and 33, and sections 35 and 36 |

The two numbers change independently. Section 14 says where each appears on the wire and
what a client does with a relay protocol version it does not know.

### 1.4 Specified in part 2

Part 1 states about the items of this table only what the relay protocol depends on, and
names the section of part 2 each time.

| Item                                                                                                  | Section |
|-------------------------------------------------------------------------------------------------------|---------|
| Key agreement between two identities from a prekey bundle, including the handling of an all-zero Diffie-Hellman output | 16 |
| The Double Ratchet: key derivation, the message header, skipped message keys                          | 17      |
| Message encryption: the cipher, the nonce, the associated data and the wire layout                    | 18      |
| The peer envelope and the plaintext with its padding, that is, the content of the `payload` field of sections 7.12 and 7.14 | 19 |
| Session rules: several sessions per peer, duplicates, messages from an id that is not a contact, decryption failures | 20 |
| The prekey lifecycle: rotation of the signed prekey, allocation of prekey ids, refill of one-time prekeys | 21  |
| The client store: what it holds and the order of its writes                                           | 22      |
| The client transport: the reconnect and Back off schedules and the refusal of an unencrypted connection to a host that is not a loopback host | 23 |
| The constants and local results of part 2, and what its test vectors record                           | 24      |
| Every deviation from the specifications this protocol follows, and what it lacks                      | 25      |

## 2. Conventions

### 2.1 Bytes and hex

A byte is 8 bits. A byte string is written in lowercase hex, two digits per byte, first
byte first, without separators: `736f74746f` is the five bytes of the ASCII text `sotto`.
One byte is also written as `0x00`. Text inside a byte layout is ASCII, one byte per
character, with no terminator unless the layout shows one.

`A || B` is the bytes of A followed by the bytes of B. `X[i]` is byte i of X, counted
from 0.

### 2.2 Integers

- `u8`, `u32` and `u64` are unsigned integers of 1, 4 and 8 bytes.
- In a byte layout an integer wider than one byte is big-endian, most significant byte
  first. Part 1 has one integer in a byte layout, the 1-byte name length of section 4.2.
  Part 2 has three: the version byte of section 16.5 and the two counters of the message
  header (section 17.5).
- In a frame and in the peer envelope of section 19 an integer is a protobuf `uint32`,
  and protobuf decides its encoding.
- The bytes of an Ed25519 key are read as RFC 8032 defines them. Section 3.3 states the
  one place where this document reads them as a little-endian integer.

### 2.3 Lengths

A length is a count of bytes. `(32)` after a field name in a layout means exactly 32 bytes.
In a frame table, a length is exact unless it is written as a range. KiB is 1024 bytes,
MiB is 1024 KiB, GiB is 1024 MiB.

A length-prefixed field is one byte L followed by L bytes.

### 2.4 Requirement words

Four terms are defined. They are written in capitals and have no other use in this
document.

- MUST: an implementation that does otherwise does not implement this protocol.
- MUST NOT: an implementation that does this does not implement this protocol.
- SHOULD: the expected behaviour. Interoperability does not depend on it, and an
  implementation departs from it only for a reason it can state.
- MAY: permitted. A peer works with either choice.

A sentence in the present tense about the relay or about a client ("the relay closes the
connection", "a client pins the key") is a rule for that implementation with the force of
MUST. For the relay it is also a guarantee to its clients.

### 2.5 Terms

- The relay: the server process. It stores and forwards frames.
- A client: a program that holds the private key of one identity and speaks to the relay.
- An identity: an Ed25519 key pair made on a device (section 3). It names one user. One
  device holds it.
- The identity key: the 32-byte public key of an identity, `IKsig` in layouts.
- The user id: the identity key as text (section 3.2).
- A connection: one WebSocket connection between a client and the relay.
- A frame: one WebSocket binary message that holds one envelope message (section 7).
- Logged in: the state of a connection after the relay accepted its Login (section 8).
- Registered: an identity whose bundle the relay holds (section 8.6).
- The queue of an identity: the messages the relay holds for it as recipient, delivered or
  not.
- Random: taken from the random number generator of the operating system.

### 2.6 Citations

A guarantee is followed by a citation in square brackets, at the place that states the
rule.

- A citation covers the text before it, back to the citation before it or to the start of
  the paragraph or list item.
- A citation in the sentence that introduces a list or a table also covers every item of
  it.
- A sentence that points to a rule by the number of its section, or that gives the reason
  for a rule, carries no citation of its own.

A citation is written on one line and has one form, shown here by a real example:
`[test: tests/test_routing.py::test_healthz_answers_200]` names the test function that
holds the statement: the path of the test file from the root of the repository, two
colons, the name of the function. A parametrized test is cited by its function name. A
statement of part 1 that rests on a rule of part 2 names the section of that rule and
carries the citation of the test behind it.

The form is checked by machine, here and in the other documents of `docs/` and in the
README. A citation has to name a test function that exists
[test: tests/test_docs.py::test_cited_tests_exist]. Three marks appear only inside a
citation: an opening square bracket followed by a word and a colon, a path into the test
folder and a pair of colons. Text that carries one of the marks and is not a citation
fails the check [test: tests/test_docs.py::test_citations_are_well_formed]. The check
sees the form of a citation, not whether a guarantee has one.

A point that is not decided is marked `OPEN:`, at the start of a line, of a list item or of
a table cell. A merged revision carries the mark only directly after a backtick, as in this
paragraph [test: tests/test_docs.py::test_docs_have_no_open_point].

## 3. Identity and user id

### 3.1 The identity key

An identity is an Ed25519 key pair as defined in RFC 8032 section 5.1.

- The private part is a 32-byte seed. It is random, it is made on the device that uses the
  identity, and no frame of this protocol carries it.
- The public part is the 32-byte encoding of RFC 8032 section 5.1.5. It is the identity
  key.

Both libraries use exactly these raw forms: `Ed25519PrivateKey.from_private_bytes`,
`private_bytes_raw` and `public_bytes_raw` in the Python package cryptography;
`Curve25519.Signing.PrivateKey(rawRepresentation:)` and `publicKey.rawRepresentation` in
CryptoKit. The first shared test vector pins the step from a seed to its identity key
[test: tests/crypto/test_identity_vectors.py::test_first_vector_is_rfc_8032_test_1].

Example, RFC 8032 section 7.1, TEST 1:

```
seed          9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
identity key  d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
```

### 3.2 The user id

The user id is the identity key in hex: 64 characters from `0123456789abcdef`. The id of
the example above is

```
d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
```

The id is the whole key, not a digest of it. Two parties that hold each other's ids hold
each other's identity keys, and every later check compares or verifies against all 32
bytes. The id has to reach the other party over a channel the two trust; this protocol
does not provide one.

### 3.3 Decoding a user id

A decoder takes a text string and returns 32 bytes or the result INVALID_ID
(section 11.4). It applies these four steps in order and nothing else, so that every
implementation accepts the same strings
[test: tests/crypto/test_identity.py::test_decoder_accepts_exactly_what_the_four_steps_allow].

1. The string has exactly 64 characters and each is one of `0123456789abcdef`: the whole
   string matches `[0-9a-f]{64}`. Nothing is trimmed, folded or normalized first:
   whitespace around the id, an uppercase letter, a prefix such as `0x` and a separator
   each make the string invalid.
2. The 64 characters are the hex form of 32 bytes K, K[0] first.
3. Let Y be K with the most significant bit of the last byte cleared: Y[31] is K[31] AND
   0x7f, the other bytes are equal. The string is invalid when Y, read as a little-endian
   integer, is 2^255 - 19 or more. In bytes: Y[31] is 0x7f, each of Y[1] to Y[30] is 0xff,
   and Y[0] is 0xed or more.
4. The string is invalid when Y is one of these five byte strings:

   ```
   0000000000000000000000000000000000000000000000000000000000000000
   0100000000000000000000000000000000000000000000000000000000000000
   ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
   26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05
   c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a
   ```

What the steps exclude:

- Step 3 excludes the non-canonical encodings: a y coordinate that is not reduced modulo
  2^255 - 19. There are 19 such values of y, each with either value of the cleared bit.
  Without this step one point would have two ids.
- Step 4 compares Y, so it excludes each listed string with the top bit of K[31] clear and
  with it set: the eight points of small order (orders 1, 2, 4 and 8) and two further
  encodings, with the bit set, of the two points that have x = 0. A signature under a key
  of small order can be forged by anyone, so such a key cannot name a user. The points are
  those of Chalkias, Garillot and Nikolaenko, "Taming the many EdDSAs", IACR ePrint
  2020/1244, table 1; table 2 of that paper lists the 19 values of step 3.

Both steps compare bytes, so their result does not depend on what a library accepts when
it loads a key.

Whether K is the encoding of a point of the curve is not a step of the decoder. About half
of all 32-byte strings are not, and an id of that kind passes the decoder. It names nobody:
RFC 8032 verification fails for every signature under such a key, so the key cannot log in
(section 8.3) and no bundle verifies under it (section 5.4). An implementation treats an
error of its library on loading such a key as a signature that does not verify.

### 3.4 The QR payload

A QR code that carries an id holds the id string and nothing else: 64 ASCII characters,
with no scheme, no whitespace and no line end. A scanner passes the scanned string to the
decoder of section 3.3 unchanged.

### 3.5 Identity keys in frames

A frame carries an identity as the 32 bytes of the identity key, never as text. The relay
applies steps 3 and 4 of section 3.3 to the identity key of a Login and refuses the login
when either fails (section 8.3). It applies no such check to the recipient of a Send or to
the identity of a FetchBundle: a key that those steps exclude cannot log in, so it is
never registered and the frame gets the answer for an identity that is not registered
[test: tests/test_bundles.py::test_fetch_for_an_identity_that_is_not_registered_answers_not_found]
[test: tests/test_messages.py::test_send_to_an_identity_that_is_not_registered_answers_unknown_recipient].

## 4. Signed strings

### 4.1 Common rules

An identity key signs exactly three kinds of byte string: the login string (4.2), the
X25519 identity key string (4.3) and the signed prekey string (4.4).

1. The signature is Ed25519 as in RFC 8032 section 5.1: no prehash and no context. It is
   made and verified by the library of the platform: `Ed25519PrivateKey.sign` and
   `Ed25519PublicKey.verify` in the Python package cryptography,
   `Curve25519.Signing.PrivateKey.signature(for:)` and
   `Curve25519.Signing.PublicKey.isValidSignature(_:for:)` in CryptoKit. A signature is 64
   bytes. Whether the two libraries give the same verdict on a signature that no honest
   signer produces, for example one under a key with a component of small order, is not
   settled by this document. Such a signature can verify in one implementation and fail in
   another; it harms only the identity that made it. A verifier MAY refuse a signature
   under an identity key that step 3 or 4 of section 3.3 excludes, before it asks the
   library; no rule of this document lets such a key reach a verification.
2. Every signed string is `prefix || 0x00 || fields`. The prefix is ASCII text and holds no
   0x00 byte, so the first 0x00 byte of a signed string ends its prefix. The three
   prefixes differ, so a signed string of one kind is never a signed string of another
   kind, whatever its fields hold
   [test: tests/crypto/test_identity.py::test_signed_strings_of_two_purposes_never_coincide].
   Without the prefixes the relay could choose a login nonce that makes the login string a
   valid prekey statement.
3. An implementation MUST NOT sign any other byte string with the private key of an
   identity.
4. A signed string is built from raw values: the bytes of each field exactly as they were
   generated or received. Nothing signed is ever a serialized protobuf message, because
   protobuf serialization is not canonical and two implementations can serialize one
   message to different bytes. A verifier builds the string itself from the fields it
   received and verifies the signature over that string.
5. Signature bytes are not an identifier. CryptoKit signs with randomization, so two
   signatures of one string by one key differ and both verify. An implementation MUST NOT
   compare signatures, derive anything from signature bytes or use them as a key of a
   lookup. No test vector asks for signature bytes to be produced (section 15.3).
6. The layouts below are frozen. A string with other fields or another order gets a new
   prefix (section 14.3).

### 4.2 The login string

| Offset | Length | Field         | Value                                                  |
|--------|--------|---------------|--------------------------------------------------------|
| 0      | 13     | prefix        | ASCII `sotto/1 login`, hex `736f74746f2f31206c6f67696e` |
| 13     | 1      | terminator    | `00`                                                   |
| 14     | 1      | name length N | u8, 1 to 255                                           |
| 15     | N      | server name   | ASCII, section 8.2                                     |
| 15 + N | 32     | server nonce  | the `nonce` of the Hello of this connection            |
| 47 + N | 32     | client nonce  | the `client_nonce` of the Login                        |

Total length: 79 + N bytes, 80 to 334.

- Signed by: the client, with the private key of its identity, once per connection, after
  it received the Hello.
- Verified by: the relay, once per connection, when the Login arrives. The relay builds the
  string from its own server name, the nonce it sent on this connection and the client
  nonce of the Login (section 8.3).

Example with the server name `127.0.0.1` (N = 9), the server nonce `00` to `1f` and the
client nonce `20` to `3f`, 88 bytes, one field per line:

```
736f74746f2f31206c6f67696e
00
09
3132372e302e302e31
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
```

### 4.3 The X25519 identity key string

| Offset | Length | Field      | Value                                                                    |
|--------|--------|------------|--------------------------------------------------------------------------|
| 0      | 19     | prefix     | ASCII `sotto/1 identity-dh`, hex `736f74746f2f31206964656e746974792d6468` |
| 19     | 1      | terminator | `00`                                                                     |
| 20     | 32     | IKsig      | the identity key of the signer                                           |
| 52     | 32     | IKdh       | the X25519 identity key of the signer (section 5.1)                      |

Total length: 84 bytes.

- Signed by: the owner of the identity, with the private key of the identity, when the
  identity is made. The X25519 identity key of an identity never changes (section 5.3).
- Verified by: the relay on every UploadBundle (section 9.1); a client on every Bundle it
  fetched (section 5.4) and on the X25519 identity key that the first messages of a
  session carry (section 16.8)
  [test: tests/client/test_session.py::test_initial_header_that_fails_step_1_or_2_changes_nothing].

### 4.4 The signed prekey string

| Offset | Length | Field      | Value                                                                          |
|--------|--------|------------|--------------------------------------------------------------------------------|
| 0      | 21     | prefix     | ASCII `sotto/1 signed-prekey`, hex `736f74746f2f31207369676e65642d7072656b6579` |
| 21     | 1      | terminator | `00`                                                                           |
| 22     | 32     | IKsig      | the identity key of the signer                                                 |
| 54     | 32     | SPK        | the signed prekey (section 5.1)                                                |

Total length: 86 bytes.

- Signed by: the owner of the identity, with the private key of the identity, each time it
  makes a signed prekey.
- Verified by: the relay on every UploadBundle (section 9.1); a client on every Bundle it
  fetched (section 5.4).

The id of a signed prekey is not part of the string (section 5.2).

## 5. Prekey bundle

### 5.1 The keys

| Key   | Kind               | Length | Lifetime                                       |
|-------|--------------------|--------|------------------------------------------------|
| IKsig | Ed25519 public key | 32     | The identity. Never changes.                   |
| IKdh  | X25519 public key  | 32     | One per identity. Never changes (section 5.3). |
| SPK   | X25519 public key  | 32     | Replaced by its owner from time to time.       |
| OPK   | X25519 public key  | 32     | Handed out once, then deleted (section 9.3).   |

An X25519 public key is the 32-byte string of RFC 7748 section 5. The rules for using
these keys are in section 16
[test: tests/crypto/test_x3dh.py::test_both_sides_derive_the_same_secret_and_associated_data];
those for rotating the signed prekey and for choosing prekey ids are in section 21
[test: tests/client/test_lifecycle.py::test_rotation_follows_the_age_of_the_newest_signed_prekey]
[test: tests/client/test_lifecycle.py::test_prekey_ids_are_never_reused_and_stop_at_the_last_id].

### 5.2 The fields of a bundle

A bundle is what one identity publishes through the relay so that another identity can
start a session with it while it is offline.

| Field                       | Type  | Length | Signed                                      |
|-----------------------------|-------|--------|---------------------------------------------|
| Identity key (IKsig)        | bytes | 32     | Part of both signed strings; it is the signer |
| X25519 identity key (IKdh)  | bytes | 32     | Yes, by the string of section 4.3           |
| Signature over IKdh         | bytes | 64     |                                             |
| Signed prekey id            | u32   |        | No                                          |
| Signed prekey (SPK)         | bytes | 32     | Yes, by the string of section 4.4           |
| Signature over SPK          | bytes | 64     |                                             |
| One-time prekey id          | u32   |        | No                                          |
| One-time prekey (OPK)       | bytes | 32     | No                                          |

- A prekey id is any value from 0 to 2^32 - 1.
- An upload carries any number of one-time prekeys, none included (section 7.8). A fetched
  bundle carries at most one (section 7.11).
- The two prekey ids and the one-time prekey are not signed. The relay, or whoever sits
  between a client and the relay, can change them. The result is a session that does not
  start or a session without a one-time prekey, not a session with someone else
  (section 16.9)
  [test: tests/crypto/test_x3dh.py::test_replaced_one_time_prekey_gives_the_responder_another_secret]
  [test: tests/client/test_session.py::test_substituted_one_time_prekey_ends_in_a_decrypt_failure_and_keeps_the_prekey]
  [test: tests/client/test_session.py::test_unknown_signed_prekey_id_is_refused].

### 5.3 The X25519 identity key is written once

A signature over an X25519 identity key has no expiry, so the key it covers does not
change for the life of the identity.

- The relay keeps the X25519 identity key of the first accepted upload of an identity and
  refuses every later upload that carries another one with IDENTITY_KEY_MISMATCH
  [test: tests/test_bundles.py::test_refused_upload_gets_the_code_of_its_reason_and_stores_nothing].
  It compares the 32 bytes of the key, not the signature (section 4.1, rule 5), and keeps
  the signature of the first upload
  [test: tests/test_storage.py::test_same_key_under_another_signature_is_stored_and_keeps_the_first_signature].
- A client pins the X25519 identity key of a contact in the transaction that stores its
  first session with that contact: the key of a bundle that passed the checks of
  section 5.4, when the client made the session (section 16.6), or the key of the initial
  header, when it accepted the first initial message of the contact (section 16.8)
  [test: tests/client/test_session.py::test_bundle_with_another_x25519_key_than_the_pin_is_refused_before_any_diffie_hellman]
  [test: tests/client/test_session.py::test_stored_responder_session_holds_neither_the_secret_nor_the_signed_prekey]. It refuses every later bundle of that contact that carries another
  key
  [test: tests/crypto/test_identity.py::test_pinned_x25519_identity_key_refuses_another_one]
  and every later initial header that does (section 16.8)
  [test: tests/client/test_session.py::test_initial_header_that_fails_step_1_or_2_changes_nothing].

### 5.4 The client's checks

A client that received a Bundle for a contact runs these checks in this order and stops at
the first that fails
[test: tests/crypto/test_identity.py::test_bundle_checks_stop_at_the_first_failure].
The lengths of the fields were checked before, when the frame was parsed (section 7.3).

| No. | Check                                                                                         | Result on failure     |
|-----|-----------------------------------------------------------------------------------------------|-----------------------|
| 1   | `identity` equals the 32 bytes that the id of the contact decodes to                          | BAD_BUNDLE            |
| 2   | `identity_dh_signature` verifies under `identity` over the string of section 4.3, built from `identity` and `identity_dh_key` | BAD_BUNDLE |
| 3   | If the client has a pinned X25519 identity key for the contact: `identity_dh_key` equals it   | IDENTITY_KEY_MISMATCH |
| 4   | `signed_prekey.signature` verifies under `identity` over the string of section 4.4, built from `identity` and `signed_prekey.key` | BAD_BUNDLE |

- When all four pass and the client has no pin for the contact, it pins `identity_dh_key`
  in the transaction that stores the session made from the bundle (section 16.6, step 8)
  [test: tests/client/test_session.py::test_bundle_with_another_x25519_key_than_the_pin_is_refused_before_any_diffie_hellman]. A key agreement that fails after the checks pins nothing
  [test: tests/client/test_session.py::test_key_agreement_that_fails_after_the_checks_stores_no_session_and_no_pin].
- A bundle that fails a check is not used: the client computes no Diffie-Hellman value
  with any of its keys and pins nothing.
- The prekey ids and the one-time prekey have no check of their own (section 5.2).

## 6. Transport

### 6.1 WebSocket and paths

A connection is a WebSocket connection (RFC 6455). The relay serves three kinds of path on
one port:

| Path          | Answer                                                              |
|---------------|---------------------------------------------------------------------|
| `/ws`         | The WebSocket upgrade [test: tests/test_routing.py::test_websocket_opens_on_ws] |
| `/healthz`    | `200`, no upgrade [test: tests/test_routing.py::test_healthz_answers_200] |
| anything else | `404`, no upgrade [test: tests/test_routing.py::test_unknown_path_answers_404] |

The match is exact. A query string or a trailing slash makes another path, and an upgrade
request on any path but `/ws` gets the plain answer of that path
[test: tests/test_routing.py::test_websocket_is_refused_off_ws].

`/healthz` says that the process accepts connections and asks for no credentials
[test: tests/test_routing.py::test_healthz_answers_200]. Its body is a fixed text that
does not depend on the request, on a client or on the database
[test: tests/test_routing.py::test_healthz_body_is_the_same_for_every_request_and_after_an_upload].
The WebSocket port serves no metrics
[test: tests/test_routing.py::test_websocket_port_answers_404_for_metrics]. The relay serves
them on a listener of its own, which is off unless it is configured (threat model, "What
the relay learns").

### 6.2 Binary frames only

One frame is one WebSocket binary message that holds one serialized envelope message
(section 7.1). A receiver that gets a WebSocket text message closes the connection with
close code 1003, in every state of the connection, before login and after it
[test: tests/test_login.py::test_text_message_closes_with_1003]. A text message that is not
valid UTF-8 does not reach this rule: the WebSocket library of the receiver ends the
connection with close code 1007 (RFC 6455 section 8.1)
[test: tests/test_login.py::test_text_message_that_is_not_utf_8_closes_with_1007].

A client MUST answer a WebSocket ping with a pong (RFC 6455 section 5.5.2). The relay MAY
end a connection that leaves its pings unanswered.

### 6.3 The largest frame

A frame is at most MAX_FRAME_BYTES long, 65536 bytes (section 12.1). The length is that of
the whole WebSocket message, after fragments are joined. A receiver that gets a longer
message closes the connection with close code 1009; the WebSocket library sends that code
before any frame is parsed
[test: tests/test_login.py::test_message_above_the_largest_frame_closes_with_1009]. A client MUST set the receive limit of its
WebSocket library to the same value. The relay sends no frame above the limit
[test: tests/test_messages.py::test_largest_payload_is_delivered_in_a_frame_within_the_limit].

### 6.4 No compression, no extension, no subprotocol

The relay negotiates no WebSocket extension: its handshake answer carries no
`Sec-WebSocket-Extensions` header, so no message is compressed
[test: tests/test_routing.py::test_websocket_opens_on_ws]. Ciphertext does not compress.
The relay selects no subprotocol
[test: tests/test_routing.py::test_no_subprotocol_is_selected], and a client MUST NOT require
one.

### 6.5 TLS

The relay process speaks WebSocket without TLS
[test: tests/test_routing.py::test_websocket_opens_on_ws]. In a deployment a reverse proxy
in front of it ends TLS and forwards the path `/ws`. The protocol makes no use of the TLS
session: the login is not bound to it (section 8.7). What a client refuses to dial without
TLS is specified in section 23.1 [test: tests/client/test_transport.py::test_url_rules_of_sections_8_2_and_23_1].

## 7. Frames

### 7.1 The schema

The frames are protobuf messages, proto3 syntax. The schema lives in `proto/sotto.proto`,
which is normative for the names, numbers and types of the fields; this section lists its
content for the relay protocol and adds the rules that a schema cannot express. A message
enters the file with the pull request that implements its handler; the login frames and
Error come first. Until every frame is in the file, the file is a part of the listing
below: an envelope lacks the members whose frames the file does not have, and every other
message and enum of the file is as listed
[test: tests/test_docs.py::test_schema_file_is_a_part_of_the_listing_in_the_spec]. The messages of the end-to-end protocol are in the same file and are
listed in section 19.1. The listing holds the blob frames of part 3 as well, which
section 30 specifies.

```proto
syntax = "proto3";

package sotto;

// Client to relay: one frame is one ClientFrame.
message ClientFrame {
  oneof frame {
    Login login = 1;
    UploadBundle upload_bundle = 2;
    FetchBundle fetch_bundle = 3;
    Send send = 4;
    Ack ack = 5;
    StartBlob start_blob = 6;
    PutBlob put_blob = 7;
    FetchBlob fetch_blob = 8;
    DeleteBlob delete_blob = 9;
  }
}

// Relay to client: one frame is one ServerFrame.
message ServerFrame {
  oneof frame {
    Hello hello = 1;
    LoggedIn logged_in = 2;
    BundleStored bundle_stored = 3;
    Bundle bundle = 4;
    Stored stored = 5;
    Deliver deliver = 6;
    Error error = 7;
    BlobStored blob_stored = 8;
    BlobData blob_data = 9;
  }
}

message Hello {
  uint32 version = 1;
  bytes nonce = 2;
}

message Login {
  bytes identity_key = 1;
  bytes client_nonce = 2;
  bytes signature = 3;
}

message LoggedIn {
  uint32 one_time_prekey_count = 1;
  uint32 blob_max_bytes = 2;
}

message SignedPrekey {
  uint32 id = 1;
  bytes key = 2;
  bytes signature = 3;
}

message OneTimePrekey {
  uint32 id = 1;
  bytes key = 2;
}

message UploadBundle {
  bytes identity_dh_key = 1;
  bytes identity_dh_signature = 2;
  SignedPrekey signed_prekey = 3;
  repeated OneTimePrekey one_time_prekeys = 4;
}

message BundleStored {
  uint32 one_time_prekey_count = 1;
}

message FetchBundle {
  bytes identity = 1;
}

message Bundle {
  bytes identity = 1;
  bytes identity_dh_key = 2;
  bytes identity_dh_signature = 3;
  SignedPrekey signed_prekey = 4;
  OneTimePrekey one_time_prekey = 5;
}

message Send {
  bytes message_id = 1;
  bytes recipient = 2;
  bytes payload = 3;
}

message Stored {
  bytes message_id = 1;
}

message Deliver {
  bytes message_id = 1;
  bytes sender = 2;
  bytes payload = 3;
}

message MessageRef {
  bytes message_id = 1;
  bytes sender = 2;
}

message Ack {
  repeated MessageRef messages = 1;
}

enum ErrorCode {
  ERROR_CODE_UNSPECIFIED = 0;
  UNKNOWN_RECIPIENT = 1;
  QUEUE_FULL = 2;
  STORAGE_FULL = 3;
  RATE_LIMITED = 4;
  NOT_FOUND = 5;
  BAD_BUNDLE = 6;
  IDENTITY_KEY_MISMATCH = 7;
  QUOTA_FULL = 8;
  BLOB_TOO_LARGE = 9;
}

message Error {
  ErrorCode code = 1;
  bytes message_id = 2;
  bytes identity = 3;
  bytes blob_id = 4;
}

// The blob frames of part 3 (section 30).
message StartBlob {
  bytes blob_id = 1;
  bytes recipient = 2;
  uint32 length = 3;
}

message PutBlob {
  bytes blob_id = 1;
  uint32 offset = 2;
  bytes data = 3;
}

message BlobStored {
  bytes blob_id = 1;
  uint32 stored_length = 2;
}

message FetchBlob {
  bytes blob_id = 1;
  bytes uploader = 2;
  uint32 offset = 3;
  uint32 length = 4;
}

message BlobData {
  bytes blob_id = 1;
  bytes uploader = 2;
  uint32 offset = 3;
  bytes data = 4;
}

message DeleteBlob {
  bytes blob_id = 1;
  bytes uploader = 2;
}
```

No client frame names its own sender. After the login the relay takes the identity of a
frame from the connection that carried it, never from a field: Send has a recipient only,
UploadBundle has no identity field, and the `sender` of a MessageRef is the sender of the
acked message, not of the Ack
[test: tests/test_messages.py::test_no_client_frame_names_its_sender]
[test: tests/test_messages.py::test_message_to_an_online_recipient_is_delivered_byte_for_byte]
[test: tests/test_messages.py::test_ack_of_a_message_queued_for_another_identity_deletes_nothing]. The identity key of a Login is not an
exception: it is the claim that the signature of the same frame proves.

### 7.2 Field numbers are frozen

From the merge of the pull request that adds a message to `proto/sotto.proto`, the number
and the type of each of its fields never change, and neither does the number of an enum
value. A field that goes out of use keeps its number through a `reserved` statement. A new
field or a new frame takes the next free number.

The numbers above were chosen by these rules: every message counts from 1 without a gap;
every number is 15 or less, so every tag is one byte; `message_id` is field 1 of every
message that has one, Error excepted, so that a MessageRef has the numbers and types of
the first two fields of the Deliver it confirms.

### 7.3 Parsing and malformed frames

Each direction has one parse step that turns a received WebSocket binary message into a
frame or into the verdict "malformed". A message is a malformed frame when one of these
holds:

1. It does not parse as the envelope message of its direction: ClientFrame for the relay,
   ServerFrame for a client.
2. No member of the `frame` oneof is set. A member that the receiver's schema does not
   have counts as not set.
3. A field of the frame breaks the length, the count or the presence that the table of the
   frame states (sections 7.5 to 7.16). For a Hello a client applies this rule only after
   it read the `version` (section 7.5).

A field that the receiver's schema does not have is ignored
[test: tests/test_login.py::test_login_with_unknown_fields_is_accepted]. A frame that
parses is not valid by that alone: proto3 has no required fields and reads an absent field
as empty, so rule 3 is what makes a frame complete.

The receiver of a malformed frame closes the connection with close code 1008. For the
relay this holds for every malformed frame, before login and after it
[test: tests/test_login.py::test_malformed_frame_closes_with_1008]. A client that closed for this reason retries (section 11.1).

Nothing in this protocol depends on how a peer serialized a message: no serialized message
is signed, hashed or compared.

### 7.4 Who sends what, and when

| Frame        | Sent by | Valid                                                  | Answer                         |
|--------------|---------|--------------------------------------------------------|--------------------------------|
| Hello        | relay   | First frame of the connection, once                    | Login                          |
| Login        | client  | First frame the client sends, once                     | LoggedIn, or a close           |
| LoggedIn     | relay   | Once, as the answer to an accepted Login               | none                           |
| UploadBundle | client  | After the Login of the connection                      | BundleStored or Error          |
| FetchBundle  | client  | After the Login of the connection                      | Bundle or Error                |
| Send         | client  | After the Login of the connection                      | Stored or Error                |
| Ack          | client  | After the Login of the connection                      | none                           |
| Deliver      | relay   | After LoggedIn, at any time                            | an Ack, when the client saved the message |
| BundleStored, Bundle, Stored, Error | relay | As answers only                       | none                           |
| StartBlob, PutBlob, FetchBlob, DeleteBlob | client | After the Login of the connection, to a relay that announced them (section 30.1) | Section 30.1 |
| BlobStored, BlobData | relay | As answers only                                     | none                           |

Rules of state for the relay:

- A first client frame that is not a Login closes the connection with 1008. This is the
  case of a frame before login
  [test: tests/test_login.py::test_frame_before_login_closes_with_1008].
- A Login that is not the first client frame closes the connection with 1008
  [test: tests/test_login.py::test_second_login_on_a_connection_closes_with_1008].
- A client MAY send further frames right after its Login without waiting for LoggedIn. The
  relay handles them only after it accepted the Login
  [test: tests/test_login.py::test_frames_sent_with_the_login_are_handled_after_it]; when it
  refuses the Login it closes the connection and handles none of them
  [test: tests/test_login.py::test_frames_sent_with_a_refused_login_are_not_handled].
- The relay handles the frames of one connection one at a time, in the order it received
  them, and sends the answer to a frame before it handles the next frame of that
  connection [test: tests/test_login.py::test_frames_sent_with_the_login_are_handled_after_it].
  A Deliver is not an answer and can arrive between any two other frames that follow the
  LoggedIn
  [test: tests/test_messages.py::test_every_send_gets_one_answer_in_the_order_of_the_requests].
- Every UploadBundle and FetchBundle gets exactly one answer
  [test: tests/test_bundles.py::test_every_upload_and_fetch_gets_one_answer_in_the_order_of_the_requests],
  and so does every Send
  [test: tests/test_messages.py::test_every_send_gets_one_answer_in_the_order_of_the_requests].

Rules of state for a client [test: tests/client/test_transport.py::test_frame_out_of_its_state_closes_with_1008] [test: tests/client/test_transport.py::test_answer_that_matches_no_request_is_ignored]:

- A first frame that is not a Hello and a second Hello are treated as a malformed frame.
- Between the Hello and the LoggedIn, every frame other than LoggedIn is treated as a
  malformed frame. So are a LoggedIn that arrives before the client sent its Login and a
  second LoggedIn.
- After the LoggedIn, an answer that matches no request of this connection is ignored. A
  repeated Send, for one, gets a Stored for each repeat.

### 7.5 Hello

| Field     | No. | Type   | Length or value                                  |
|-----------|-----|--------|--------------------------------------------------|
| `version` | 1   | uint32 | 1, the relay protocol version (section 14.1)     |
| `nonce`   | 2   | bytes  | 32, random, made for this connection only        |

- Sent by the relay as the first frame of every connection
  [test: tests/test_login.py::test_relay_speaks_first_with_a_nonce_of_its_own].
- Valid answer: Login.
- Violations, seen by the client: `version` is read first. When it is not 1, section 14.1
  applies whatever the other fields hold. With `version` 1, a `nonce` that is not 32 bytes
  is a malformed frame.

### 7.6 Login

| Field          | No. | Type  | Length or value                                         |
|----------------|-----|-------|---------------------------------------------------------|
| `identity_key` | 1   | bytes | 32, the identity key of the client                      |
| `client_nonce` | 2   | bytes | 32, random, made for this Login only                    |
| `signature`    | 3   | bytes | 64, over the login string of section 4.2                |

- Sent by the client as its first frame, once per connection.
- Valid answer: LoggedIn. A Login that is refused gets no frame: the connection closes
  (section 8.3).
- Violations: a malformed Login closes with 1008
  [test: tests/test_login.py::test_malformed_frame_closes_with_1008]; an `identity_key` that
  fails step 3 or 4 of section 3.3 closes with 3000
  [test: tests/test_login.py::test_login_with_an_excluded_key_closes_with_3000]; a signature
  that does not verify closes with 3000
  [test: tests/test_login.py::test_login_whose_signature_does_not_verify_closes_with_3000];
  no Login within LOGIN_DEADLINE_SECONDS closes with 3008
  [test: tests/test_connection.py::test_silence_after_the_hello_closes_with_3008]; a second Login
  on the connection closes with 1008
  [test: tests/test_login.py::test_second_login_on_a_connection_closes_with_1008]. Section 8
  has the full rules.

### 7.7 LoggedIn

| Field                   | No. | Type   | Length or value                                         |
|-------------------------|-----|--------|---------------------------------------------------------|
| `one_time_prekey_count` | 1   | uint32 | The number of one-time prekeys the relay holds for the identity, 0 for an identity that is not registered |
| `blob_max_bytes`        | 2   | uint32 | BLOB_MAX_BYTES of a relay that serves the blob frames of part 3, 0 for a relay that does not (section 28.2) |

- Sent by the relay once, when it accepted the Login
  [test: tests/test_login.py::test_login_is_accepted]
  [test: tests/test_login.py::test_second_login_on_a_connection_closes_with_1008]. The count
  is that of section 9.4
  [test: tests/test_bundles.py::test_counts_of_logged_in_and_bundle_stored_follow_the_stored_one_time_prekeys].
- No answer.
- The relay of this repository serves the blob frames and sets `blob_max_bytes` to its
  BLOB_MAX_BYTES [test: tests/test_blobs.py::test_logged_in_announces_the_largest_blob].
- Violations, seen by the client: a second LoggedIn, or one that arrives before the client
  sent its Login, is a malformed frame (section 7.4).

### 7.8 UploadBundle

| Field                      | No. | Type          | Length or value                               |
|----------------------------|-----|---------------|-----------------------------------------------|
| `identity_dh_key`          | 1   | bytes         | 32                                            |
| `identity_dh_signature`    | 2   | bytes         | 64, over the string of section 4.3            |
| `signed_prekey`            | 3   | SignedPrekey  | present                                       |
| `signed_prekey.id`         | 1   | uint32        | 0 to 2^32 - 1                                 |
| `signed_prekey.key`        | 2   | bytes         | 32                                            |
| `signed_prekey.signature`  | 3   | bytes         | 64, over the string of section 4.4            |
| `one_time_prekeys`         | 4   | repeated OneTimePrekey | 0 or more, as many as fit in one frame |
| `one_time_prekeys[].id`    | 1   | uint32        | 0 to 2^32 - 1                                 |
| `one_time_prekeys[].key`   | 2   | bytes         | 32                                            |

- Sent by a logged-in client. The bundle is that of the identity of the connection
  (section 9.1).
- Valid answers: BundleStored; or Error with RATE_LIMITED, BAD_BUNDLE,
  IDENTITY_KEY_MISMATCH or STORAGE_FULL, with no key field set (section 7.16).
- Violations: a malformed UploadBundle closes with 1008, a wrong length of a key or a
  signature included
  [test: tests/test_bundles.py::test_malformed_upload_closes_with_1008_and_stores_nothing];
  an UploadBundle before login closes with 1008
  [test: tests/test_login.py::test_frame_before_login_closes_with_1008]. Section 9.1 has the
  full rules.

### 7.9 BundleStored

| Field                   | No. | Type   | Length or value                                              |
|-------------------------|-----|--------|--------------------------------------------------------------|
| `one_time_prekey_count` | 1   | uint32 | The number of one-time prekeys the relay holds for the identity after the upload |

- Sent by the relay as the answer to an accepted UploadBundle
  [test: tests/test_bundles.py::test_uploaded_bundle_is_fetched_byte_for_byte].
- No answer.
- Violations, seen by the client: none of a field. A BundleStored that answers no
  UploadBundle of the connection is ignored (section 7.4).

### 7.10 FetchBundle

| Field      | No. | Type  | Length or value                                   |
|------------|-----|-------|---------------------------------------------------|
| `identity` | 1   | bytes | 32, the identity key whose bundle is asked for    |

- Sent by a logged-in client.
- Valid answers: Bundle; or Error with RATE_LIMITED or NOT_FOUND, with `identity` set to
  the `identity` of the request (section 7.16).
- Violations: a malformed FetchBundle closes with 1008
  [test: tests/test_bundles.py::test_malformed_fetch_closes_with_1008]; a FetchBundle before login
  closes with 1008 [test: tests/test_login.py::test_frame_before_login_closes_with_1008].
  Section 9.2 has the full rules.

### 7.11 Bundle

| Field                     | No. | Type          | Length or value                                |
|---------------------------|-----|---------------|------------------------------------------------|
| `identity`                | 1   | bytes         | 32, the `identity` of the FetchBundle          |
| `identity_dh_key`         | 2   | bytes         | 32                                             |
| `identity_dh_signature`   | 3   | bytes         | 64                                             |
| `signed_prekey`           | 4   | SignedPrekey  | present; `key` 32, `signature` 64              |
| `one_time_prekey`         | 5   | OneTimePrekey | present or absent; `key` 32 when present       |

- Sent by the relay as the answer to a FetchBundle for a registered identity
  [test: tests/test_bundles.py::test_uploaded_bundle_is_fetched_byte_for_byte].
- No answer. The client runs the checks of section 5.4.
- Violations, seen by the client: a wrong length or an absent `signed_prekey` is a
  malformed frame.

### 7.12 Send

| Field        | No. | Type  | Length or value                                              |
|--------------|-----|-------|--------------------------------------------------------------|
| `message_id` | 1   | bytes | 16, random, chosen by the sender (section 10.1)              |
| `recipient`  | 2   | bytes | 32, the identity key of the recipient                        |
| `payload`    | 3   | bytes | 1 to MAX_FRAME_BYTES - 64, that is 65472 bytes               |

- Sent by a logged-in client.
- Valid answers: Stored; or Error with RATE_LIMITED, UNKNOWN_RECIPIENT, QUEUE_FULL or
  STORAGE_FULL, with `message_id` set to the `message_id` of the request (section 7.16).
- Violations: a malformed Send closes with 1008, an empty payload and a payload above the
  limit included
  [test: tests/test_messages.py::test_malformed_send_closes_with_1008]; a Send before login closes
  with 1008 [test: tests/test_login.py::test_frame_before_login_closes_with_1008]. Section 10.2 has
  the full rules.

The payload is opaque to the relay: the relay stores and forwards its bytes and parses
none of them
[test: tests/test_messages.py::test_message_to_an_online_recipient_is_delivered_byte_for_byte]. The 64 bytes are a bound on what the envelope and the
other fields add to a payload in a Send or a Deliver (60 bytes in the shortest encoding),
so that every stored payload fits into a Deliver.

### 7.13 Stored

| Field        | No. | Type  | Length or value                        |
|--------------|-----|-------|----------------------------------------|
| `message_id` | 1   | bytes | 16, the `message_id` of the Send       |

- Sent by the relay as the answer to a Send, after the message is committed
  (section 10.2)
  [test: tests/test_storage.py::test_stored_is_sent_after_the_commit_of_the_message].
- No answer.
- Violations, seen by the client: a `message_id` that is not 16 bytes is a malformed
  frame.

### 7.14 Deliver

| Field        | No. | Type  | Length or value                                            |
|--------------|-----|-------|------------------------------------------------------------|
| `message_id` | 1   | bytes | 16, as the sender chose it                                 |
| `sender`     | 2   | bytes | 32, the identity key of the connection that sent the Send  |
| `payload`    | 3   | bytes | 1 to MAX_FRAME_BYTES - 64, the bytes of the Send           |

- Sent by the relay to the logged-in recipient (section 10.4)
  [test: tests/test_messages.py::test_message_to_an_online_recipient_is_delivered_byte_for_byte].
- Answer: an Ack that names the message, sent when the client has saved it. The relay does
  not wait for it (section 10.4).
- Violations, seen by the client: a wrong length is a malformed frame.

### 7.15 Ack

| Field                   | No. | Type                | Length or value                          |
|-------------------------|-----|---------------------|------------------------------------------|
| `messages`              | 1   | repeated MessageRef | 1 or more, as many as fit in one frame   |
| `messages[].message_id` | 1   | bytes               | 16, the `message_id` of a Deliver        |
| `messages[].sender`     | 2   | bytes               | 32, the `sender` of the same Deliver     |

- Sent by a logged-in client.
- No answer and no Error, whatever the pairs name (section 10.5).
- Violations: a malformed Ack closes with 1008, an Ack without a pair included
  [test: tests/test_messages.py::test_malformed_ack_closes_with_1008]; an Ack before login closes with 1008
  [test: tests/test_login.py::test_frame_before_login_closes_with_1008].

### 7.16 Error

| Field        | No. | Type      | Length or value                                              |
|--------------|-----|-----------|--------------------------------------------------------------|
| `code`       | 1   | ErrorCode | One of the codes of section 11.2                             |
| `message_id` | 2   | bytes     | 16 when the refused frame is a Send, its `message_id`; otherwise empty |
| `identity`   | 3   | bytes     | 32 when the refused frame is a FetchBundle, its `identity`, or a FetchBlob, its `uploader`; otherwise empty |
| `blob_id`    | 4   | bytes     | 16 when the refused frame is a StartBlob, a PutBlob or a FetchBlob, its `blob_id`; otherwise empty (section 30.8) |

- Sent by the relay as the answer to a Send, an UploadBundle or a FetchBundle that it
  refuses. The connection stays open
  [test: tests/test_bundles.py::test_refused_frames_get_an_error_with_their_key_and_the_connection_goes_on].
- The key fields tell the client which frame was refused: `message_id` set means a Send,
  `identity` set alone means a FetchBundle, no key field set means an UploadBundle
  [test: tests/test_bundles.py::test_refused_frames_get_an_error_with_their_key_and_the_connection_goes_on]
  [test: tests/test_messages.py::test_send_to_an_identity_that_is_not_registered_answers_unknown_recipient]. Answers arrive in the order of their requests
  (section 7.4), which tells two requests with one key apart.
- No answer.
- Violations, seen by the client: a `message_id` that is neither empty nor 16 bytes, an
  `identity` that is neither empty nor 32 bytes and an Error with both set are malformed
  frames. A `code` that the client does not know, 0 included, is not: the client treats
  the request as refused and stops repeating it (section 11.1).
- The relay answers the blob frames of part 3 with an Error as well. Such an Error has
  `blob_id` set; section 30.8 says how its key fields are set and read
  [test: tests/test_blobs.py::test_put_of_an_unknown_blob_or_of_another_uploader_is_not_found]
  [test: tests/test_blobs.py::test_fetch_of_a_blob_that_is_not_a_complete_one_of_the_recipient_is_not_found].

## 8. Login

### 8.1 The exchange

```
client                                        relay
  |  ------ WebSocket upgrade on /ws ------>   |
  |  <----- Hello{version, nonce} ----------   |   the login deadline starts
  |  ------ Login{identity_key,                |
  |               client_nonce, signature} ->  |
  |  <----- LoggedIn{one_time_prekey_count} -  |   or a close with 3000, 3008, 1008
```

The relay speaks first. Its Hello carries a 32-byte nonce that is random and that the
relay uses for this connection only
[test: tests/test_login.py::test_relay_speaks_first_with_a_nonce_of_its_own]. The client answers with its
identity key, a 32-byte random nonce of its own and a signature over the login string of
section 4.2. The client nonce means that the relay never chooses all the bytes an
identity key signs.

### 8.2 The server name

The server name is a field of the login string (section 4.2). No frame carries it: each
side takes it from its own configuration.

The client derives it from the URL it dialed:

1. Take the host of the URL as RFC 3986 section 3.2.2 delimits it, in the characters of
   the URL as it was given. Nothing is decoded or rewritten first: no percent-decoding, no
   conversion of a name with characters outside ASCII, no rewriting of an IP address. The
   scheme, the port, the path and any user information are not part of the name.
2. When the host is an IPv6 literal, remove the square brackets around it.
3. Replace each ASCII letter `A` to `Z` by its lowercase letter.
4. The result has to be 1 to 255 bytes long and hold only the bytes `a` to `z`, `0` to
   `9`, `.`, `-`, `_` and `:`. A client MUST NOT dial a URL whose host gives any other
   result [test: tests/client/test_transport.py::test_url_rules_of_sections_8_2_and_23_1].

| URL as given                      | Server name                                           |
|-----------------------------------|-------------------------------------------------------|
| `wss://Relay.Example.org:8443/ws` | `relay.example.org`, 17 bytes                         |
| `ws://127.1:8765/ws`              | `127.1`: the short form of an address is kept         |
| `wss://%72elay.example.org/ws`    | none: `%` breaks rule 4, and the URL is not dialed    |

A host name with characters outside ASCII breaks rule 4 as well, percent-encoded or not.
Such a name is given to the client in its ASCII form, the A-label of RFC 5890 (`xn--` and
what follows), and RELAY_NAME holds the same form.

The relay takes the name from its setting RELAY_NAME, default `127.0.0.1`
[test: tests/test_connection.py::test_login_is_verified_under_the_name_in_the_settings], and
does not start with a value that breaks rule 4
[test: tests/test_process.py::test_relay_does_not_start_with_a_server_name_that_breaks_rule_4].
The operator sets it to the host
that clients dial, in the form that steps 1 to 3 give.

No frame carries the name, so the relay compares it with RELAY_NAME through the signature:
it builds the login string with RELAY_NAME, and a signature that a client made for another
name does not verify. The login is refused with 3000
[test: tests/test_login.py::test_login_signed_for_another_server_name_closes_with_3000]. This is the case
of a login answer replayed to another server: a relay that received a login cannot use it
to log in at a relay with another server name. Relays that clients dial under one host, on
different ports, have one server name, and the login does not tell them apart: either of
them can pass a login it receives on to the other. It is for the operator to give a relay
a host that no relay of another party shares. A recorded login is of no use on another
connection of the same relay either, because every connection has its own nonce
[test: tests/test_login.py::test_login_replayed_on_another_connection_closes_with_3000].

### 8.3 The relay's checks

For every connection, in this order
[test: tests/test_login.py::test_login_checks_stop_at_the_first_that_fails]:

1. The relay sends Hello and starts the login deadline.
2. When no client frame arrived LOGIN_DEADLINE_SECONDS after the Hello was sent, the relay
   closes with 3008.
3. A text message closes with 1003, a message above the largest frame with 1009, a
   malformed frame or a frame that is not a Login with 1008.
4. When `identity_key` fails step 3 or 4 of section 3.3, the relay closes with 3000.
5. The relay builds the login string from RELAY_NAME, the nonce of step 1 and the
   `client_nonce` of the Login. When `signature` does not verify over it under
   `identity_key`, the relay closes with 3000. A key that is not a point of the curve ends
   here (section 3.3).
6. The connection is logged in as `identity_key`. A live connection of the same identity
   is replaced (section 8.5).
7. The relay sends LoggedIn.

### 8.4 One nonce, one attempt

A connection has one nonce and one login attempt. Every failure of section 8.3 closes the
connection; a client that tries again opens a new connection and gets a new nonce. The
relay sends no second Hello and accepts no second Login (section 7.4)
[test: tests/test_login.py::test_second_login_on_a_connection_closes_with_1008].

### 8.5 One live connection per identity

The relay keeps at most one logged-in connection per identity. When a login succeeds for
an identity that has a live connection, the relay closes the older connection with close
code 4001 and serves the newer one
[test: tests/test_login.py::test_every_login_of_an_identity_replaces_the_one_before]. From
that login on, the relay handles no further frame of the older connection
[test: tests/test_connection.py::test_frame_of_a_replaced_connection_is_not_handled]
[test: tests/test_connection.py::test_upload_of_a_replaced_connection_stores_nothing] and sends
it nothing but the close
[test: tests/test_login.py::test_every_login_of_an_identity_replaces_the_one_before].

A client that is closed with 4001 stops: it does not reconnect by itself
[test: tests/client/test_transport.py::test_replaced_client_stops]. Two copies of one identity would otherwise replace each other without
end. This is the case of a second login of one identity.

### 8.6 Registration

There is no registration frame and no account. An identity is registered at a relay from
the first UploadBundle that the relay accepts for it (section 9.1): registration is the
first login plus a bundle upload.

- An identity that is logged in and not registered can send every frame. It can receive
  nothing, because a Send to it is refused with UNKNOWN_RECIPIENT (section 10.2) and a
  FetchBundle for it with NOT_FOUND (section 9.2).
- The relay keeps a registered identity and its bundle without an expiry, and no frame
  removes either
  [test: tests/test_storage.py::test_sweep_deletes_a_message_once_its_ttl_has_passed].

### 8.7 What the login does not do

- No session token and no timestamp: a login proves possession of the identity key for
  one connection and nothing lasts beyond that connection.
- No channel binding: the login string does not name the TLS session, and TLS ends at a
  proxy in front of the relay (section 6.5). Whoever can make a client take another
  endpoint for the relay it dialed, with the same server name, can pass the client's login
  on to the real relay and holds a logged-in connection of that identity. The threat
  model states what that gives and what it does not.
- No proof to the client: the login proves nothing about the relay. A client knows the
  relay only through the TLS certificate of the proxy.

## 9. Bundle upload and fetch

### 9.1 Upload

The relay handles a well-formed UploadBundle of a logged-in connection in this order
[test: tests/test_bundles.py::test_upload_checks_stop_at_the_first_that_fails]:

1. It takes a token from the frame bucket of the identity (section 12.2). Without a token
   the answer is Error RATE_LIMITED
   [test: tests/test_limits.py::test_frames_over_the_bucket_are_rate_limited_and_change_nothing].
2. It builds the string of section 4.3 from the identity key of the connection and
   `identity_dh_key` and verifies `identity_dh_signature` over it. On failure the answer is
   Error BAD_BUNDLE.
3. It builds the string of section 4.4 from the identity key of the connection and
   `signed_prekey.key` and verifies `signed_prekey.signature` over it. On failure the
   answer is Error BAD_BUNDLE.
4. In one transaction:
   1. When the relay holds an X25519 identity key for the identity and `identity_dh_key`
      differs from it, the answer is Error IDENTITY_KEY_MISMATCH and nothing of the frame
      is stored.
   2. When the relay holds none, it stores `identity_dh_key` and `identity_dh_signature`.
      The identity is registered.
   3. The signed prekey of the frame, with its id and its signature, replaces the stored
      one.
   4. The one-time prekeys are taken in the order of the frame. One whose id is already
      stored for the identity is skipped
      [test: tests/test_bundles.py::test_later_upload_replaces_the_signed_prekey_and_keeps_the_first_identity_dh_key].
      One is stored while the identity has fewer than ONE_TIME_PREKEY_CAP stored. The rest
      are dropped
      [test: tests/test_bundles.py::test_one_time_prekeys_are_stored_in_the_order_of_the_frame_up_to_the_cap].
   5. When the transaction fails because the database is at its page ceiling
      (section 12), it is rolled back, the answer is Error STORAGE_FULL and nothing of the
      frame is stored.
5. The answer is BundleStored with the number of one-time prekeys stored for the identity
   after the transaction.

The relay verifies both signatures because the X25519 identity key is written once: an
upload that was not verified would fix a wrong key for the identity for good.

The answer does not say which one-time prekeys of the frame were stored; a client learns
the room it has from the counts of LoggedIn and BundleStored and from ONE_TIME_PREKEY_CAP.

The relay keeps no record of the one-time prekeys it handed out. One that is uploaded
again after it was handed out is stored again and handed out a second time
[test: tests/test_bundles.py::test_one_time_prekey_uploaded_again_after_its_handout_is_handed_out_again].
A client therefore MUST NOT upload a one-time prekey a second time,
unless the relay refused the frame that carried it with an Error: after an UploadBundle
that got no answer, the client counts the one-time prekeys of that frame as uploaded
[test: tests/client/test_lifecycle.py::test_unanswered_upload_keeps_its_keys_and_a_refused_one_deletes_them].
The other fields of an UploadBundle are safe to repeat.

### 9.2 Fetch

The relay handles a well-formed FetchBundle of a logged-in connection in this order
[test: tests/test_bundles.py::test_fetch_for_an_identity_that_is_not_registered_answers_not_found]
[test: tests/test_bundles.py::test_uploaded_bundle_is_fetched_byte_for_byte]:

1. It takes a token from the frame bucket of the requesting identity. Without a token the
   answer is Error RATE_LIMITED
   [test: tests/test_limits.py::test_frames_over_the_bucket_are_rate_limited_and_change_nothing].
2. When the identity of the request is not registered, the answer is Error NOT_FOUND.
3. It decides the handout of a one-time prekey (section 9.3).
4. The answer is Bundle: the identity of the request, its X25519 identity key and
   signature, its stored signed prekey with id and signature, and the one-time prekey of
   step 3 when there is one.

Any logged-in identity can fetch the bundle of any registered identity, its own included.
The relay returns the stored bytes of every key and signature unchanged
[test: tests/test_bundles.py::test_uploaded_bundle_is_fetched_byte_for_byte].

### 9.3 The handout of a one-time prekey

A fetched bundle carries at most one one-time prekey, and a one-time prekey is handed out
at most once
[test: tests/test_bundles.py::test_each_fetch_hands_out_the_one_time_prekey_that_was_stored_first].

1. When the handout bucket of the target identity (section 12.2) has no token, the bundle
   goes out without a one-time prekey and the stored ones stay untouched
   [test: tests/test_limits.py::test_fetches_past_the_handout_bucket_leave_the_stored_one_time_prekeys].
2. Otherwise the relay takes the one-time prekey of the target that was stored first and
   deletes it in the same transaction that reads it
   [test: tests/test_bundles.py::test_each_fetch_hands_out_the_one_time_prekey_that_was_stored_first].
   The bundle is sent after the commit
   [test: tests/test_storage.py::test_bundle_is_sent_after_the_commit_that_deleted_its_one_time_prekey].
   When the deletion cannot be written because the database or the disk is full
   (section 12.3), it is rolled back, the bundle goes out without a one-time prekey and the
   stored ones stay untouched
   [test: tests/test_storage.py::test_fetch_whose_handout_cannot_be_written_gets_the_bundle_without_one].
3. When step 2 handed out a key, one token is taken from the handout bucket of the target.
   When the target has no one-time prekey stored, the bundle goes out without one and no
   token is taken
   [test: tests/test_limits.py::test_fetches_past_the_handout_bucket_leave_the_stored_one_time_prekeys]
   [test: tests/test_limits.py::test_fetch_of_a_target_without_one_time_prekeys_takes_no_handout_token].

A fetch never fails for lack of a one-time prekey: a registered identity always gets a
Bundle [test: tests/test_bundles.py::test_each_fetch_hands_out_the_one_time_prekey_that_was_stored_first].
A bundle without a one-time prekey still starts a session
(section 16.6)
[test: tests/crypto/test_x3dh.py::test_both_sides_derive_the_same_secret_and_associated_data].

### 9.4 The count of one-time prekeys

LoggedIn and BundleStored carry the number of one-time prekeys that the relay holds for
the identity at that moment
[test: tests/test_bundles.py::test_counts_of_logged_in_and_bundle_stored_follow_the_stored_one_time_prekeys].
A client uses it to decide when to upload more (section 21.3) [test: tests/client/test_transport.py::test_steps_after_the_login_upload_once_then_send_the_outbox]. The relay
sends no other notice when the number falls
[test: tests/test_bundles.py::test_owner_gets_no_notice_when_a_one_time_prekey_is_handed_out].

## 10. Messages

### 10.1 The message id

The sender chooses the id of a message: 16 random bytes. The relay assigns no id of its
own: no frame carries an id, a counter or a position that the relay gave to a message
[test: tests/test_messages.py::test_message_to_an_online_recipient_is_delivered_byte_for_byte].

- A client uses one id for one message and repeats a message with the id, the recipient
  and the payload unchanged.
- A client MUST NOT use the id of one message for another message.
- An id is unique per sender only. The key of a message at the relay and at the recipient
  is the pair (sender, message id) (sections 10.3 and 10.5).

### 10.2 Send and Stored

The relay handles a well-formed Send of a logged-in connection in this order
[test: tests/test_messages.py::test_repeated_send_is_stored_once_and_delivered_once]
[test: tests/test_messages.py::test_send_to_an_identity_that_is_not_registered_answers_unknown_recipient]
[test: tests/test_storage.py::test_send_into_a_full_database_answers_storage_full_and_stores_nothing]. The sender is the identity of the connection. Steps 2 to 5 are one
transaction.

1. It takes a token from the frame bucket of the sender (section 12.2). Without a token
   the answer is Error RATE_LIMITED
   [test: tests/test_limits.py::test_frames_over_the_bucket_are_rate_limited_and_change_nothing].
2. When the relay holds a message with this sender and this `message_id`, the answer is
   Stored and nothing else happens (section 10.3).
3. When `recipient` is not registered, the answer is Error UNKNOWN_RECIPIENT.
4. When the queue of the recipient holds QUEUE_MAX_MESSAGES messages, or the payloads in
   it together with this payload are more than QUEUE_MAX_BYTES, the answer is Error
   QUEUE_FULL and nothing is stored
   [test: tests/test_limits.py::test_send_over_a_queue_cap_answers_queue_full_until_an_ack_makes_room].
5. The relay stores the sender, the recipient, the message id, the payload and the time
   in whole seconds, and commits. When the transaction fails because the database is at
   its page ceiling, it is rolled back, the answer is Error STORAGE_FULL and nothing is
   stored.
6. The answer is Stored with the `message_id` of the Send.

Stored means: the message is committed. The relay sends Stored only after the commit, and
a committed message survives a kill of the relay process
[test: tests/test_storage.py::test_stored_is_sent_after_the_commit_of_the_message]
[test: tests/test_process.py::test_message_answered_with_stored_survives_a_kill_of_the_relay]. Whether it
survives a loss of power or a crash of the operating system depends on the host and its
storage honouring fsync; no test covers that.

Stored does not mean delivered. This protocol has no frame that tells a sender that the
recipient received a message. The answer to a repeated Send does show a sender whether the
relay still holds a message (section 10.3).

### 10.3 A repeated Send

A client that has neither a Stored nor an Error whose action is Stop for the `message_id`
of a Send, for example because the connection ended, sends the same Send again: after the
wait of Back off when an Error asked for one, after its next login when the connection
ended (section 11.1).

- While the relay holds the message, the repeat stores nothing and gets Stored again: one
  row, one delivery, a Stored for each Send. The relay compares only the sender and the
  `message_id`; the recipient and the payload of the repeat are not looked at
  [test: tests/test_messages.py::test_repeated_send_is_stored_once_and_delivered_once]
  [test: tests/test_storage.py::test_message_is_one_row_until_its_recipient_acks_it].
- When the relay does not hold the message, because the recipient acked it or it expired,
  the relay cannot know the repeat. It stores the message again and delivers it again
  [test: tests/test_messages.py::test_send_repeated_after_the_ack_is_a_new_message]. The recipient's client discards the second copy by the pair (sender,
  message id) and acks it (section 20.2)
  [test: tests/client/test_session.py::test_envelope_delivered_twice_gives_one_text_and_two_acks].

This is the case of a Send repeated after a lost Stored.

The two cases look different to a sender that repeats a message id with another recipient.
While the relay holds the first message, the repeat is answered with Stored and nothing is
stored for the other recipient. Once the first message is acked or expired, the repeat is
a new message: it is refused with UNKNOWN_RECIPIENT when the other recipient is not
registered, and stored and delivered when it is
[test: tests/test_messages.py::test_send_repeated_after_the_ack_is_a_new_message]. A sender learns in this
way when the recipient of the first message acked it (threat model, "Not protected").

### 10.4 Deliver, order and redelivery

- The relay sends the messages of a queue to the logged-in connection of the recipient,
  each as one Deliver with the sender, the message id and the payload as stored
  [test: tests/test_messages.py::test_message_to_an_online_recipient_is_delivered_byte_for_byte].
- Order: the messages of one queue go out in the order in which the relay committed them,
  across all senders
  [test: tests/test_messages.py::test_queue_is_delivered_in_the_order_the_messages_were_stored].
- After a login the relay first sends LoggedIn and then every message of the queue, oldest
  first, the ones that an earlier connection received and did not ack included. Messages
  committed during the connection follow as they are committed
  [test: tests/test_messages.py::test_queue_is_delivered_in_the_order_the_messages_were_stored]
  [test: tests/test_messages.py::test_unacked_message_is_delivered_again_after_the_next_login].
- On one connection a message is sent once. The relay does not wait for the Ack of a
  message before it sends the next one, and it does not send a message a second time on
  that connection, however long the Ack takes
  [test: tests/test_messages.py::test_message_is_sent_once_per_connection].
- A message that is not acked stays in the queue and is delivered again after the next
  login of the recipient, until it is acked or expires
  [test: tests/test_messages.py::test_unacked_message_is_delivered_again_after_the_next_login]
  [test: tests/test_storage.py::test_relay_restarted_on_the_same_file_delivers_the_queued_message].
- The relay delivers a message to its recipient only, and the handling of one sender's
  Send never waits for a recipient to read
  [test: tests/test_messages.py::test_message_to_an_online_recipient_is_delivered_byte_for_byte]
  [test: tests/test_messages.py::test_recipient_that_stops_reading_does_not_delay_stored].

Delivery is at least once. A client receives a message more than once after a lost Ack, a
replaced connection or a repeated Send, and discards the copies by the pair (sender,
message id) (section 20.2)
[test: tests/client/test_session.py::test_envelope_delivered_twice_gives_one_text_and_two_acks].

### 10.5 Ack

An Ack names messages by the pair (sender, message id), as the Deliver carried them.

- For every pair the relay deletes the message that has this sender, this message id and
  the identity of the acking connection as its recipient
  [test: tests/test_messages.py::test_ack_deletes_the_message_and_is_safe_to_repeat]
  [test: tests/test_storage.py::test_message_is_one_row_until_its_recipient_acks_it].
- A pair that matches no such message is ignored. This covers a message that is already
  deleted and a message that is queued for another identity: an Ack never deletes a
  message of another recipient's queue, and the acking client learns nothing about it
  [test: tests/test_messages.py::test_ack_of_a_message_queued_for_another_identity_deletes_nothing]. This is the case of an Ack for a message queued for someone else.
- An Ack is safe to repeat [test: tests/test_messages.py::test_ack_deletes_the_message_and_is_safe_to_repeat].
- An Ack has no answer, and the relay sends no Error for it
  [test: tests/test_messages.py::test_ack_of_a_message_queued_for_another_identity_deletes_nothing]
  [test: tests/test_messages.py::test_ack_deletes_the_message_and_is_safe_to_repeat]. It takes no
  token from the frame bucket (section 12.2).
- An Ack for a message of an earlier connection is valid: the pair is the whole key
  [test: tests/test_messages.py::test_unacked_message_is_delivered_again_after_the_next_login].

A client acks a message only after it saved everything it needs from it; the exact rule is
in section 22.2 [test: tests/client/test_transport.py::test_connection_cut_between_deliver_and_ack_gives_one_text]. An Ack tells the relay to delete the only other copy.

### 10.6 Lost frames

| Lost frame | What follows                                                                                   |
|------------|------------------------------------------------------------------------------------------------|
| Send       | No Stored arrives. The client repeats the Send (section 10.3). The message is stored once.      |
| Stored     | The client repeats the Send and gets Stored again, or a second copy is stored and discarded by the recipient (section 10.3). |
| Deliver    | The message stays in the queue and is delivered again after the next login (section 10.4).      |
| Ack        | The message stays in the queue and is delivered again after the next login. The client discards the copy and acks it again. A message that is never acked expires (section 10.7). |

The last row is the case of a lost Ack.

### 10.7 Expiry

The relay deletes a message MESSAGE_TTL_SECONDS after it stored it, at the first sweep
after that moment (section 13), whether the message was delivered or not. The sender gets
no notice
[test: tests/test_storage.py::test_sweep_deletes_a_message_once_its_ttl_has_passed]
[test: tests/test_storage.py::test_expired_message_is_deleted_by_the_sweep_and_never_delivered].

## 11. Errors and close codes

### 11.1 What the client does next

Three actions are named in the tables below.

- Retry: the connection is gone. The client opens a new connection, logs in and repeats
  every Send that has no Stored and no Error whose action is Stop. It waits before each
  attempt and lengthens the wait while attempts fail; the schedule is specified in
  section 23.4 [test: tests/client/test_transport.py::test_waits_follow_the_schedules] [test: tests/client/test_transport.py::test_relay_restarted_in_the_middle_of_a_conversation_loses_nothing].
- Stop: the client does not reconnect and does not repeat the frame by itself. It reports
  the condition, and the next step is taken by a person.
- Back off: the connection stays open. The client waits before it sends the refused frame
  again, unchanged. The wait is FRAME_REFILL_SECONDS or longer and grows while the same
  frame keeps being refused; the schedule is specified in section 23.5
  [test: tests/client/test_transport.py::test_waits_follow_the_schedules] [test: tests/client/test_transport.py::test_rate_limited_send_is_sent_again_after_the_back_off]. A frame that waits in Back off when the connection ends is sent
  again after the next login. An UploadBundle is the exception: section 21.4 says what
  the next login uploads.

### 11.2 Error codes

An Error keeps the connection open (section 7.16). The names are the enum values of
section 7.1.

| Code                  | No. | Refuses                          | Sent when                                                          | Client   |
|-----------------------|-----|----------------------------------|--------------------------------------------------------------------|----------|
| UNKNOWN_RECIPIENT     | 1   | Send                             | The recipient is not registered at this relay                      | Stop     |
| QUEUE_FULL            | 2   | Send                             | The queue of the recipient is at one of its caps                   | Back off |
| STORAGE_FULL          | 3   | Send, UploadBundle               | The database is at its page ceiling                                | Back off |
| RATE_LIMITED          | 4   | Send, UploadBundle, FetchBundle  | The frame bucket of the identity is empty                          | Back off |
| NOT_FOUND             | 5   | FetchBundle                      | The identity of the request is not registered at this relay        | Stop     |
| BAD_BUNDLE            | 6   | UploadBundle                     | A signature of the upload does not verify                          | Stop     |
| IDENTITY_KEY_MISMATCH | 7   | UploadBundle                     | The relay holds another X25519 identity key for the identity       | Stop     |

- A refused frame stored nothing and deleted nothing at the relay
  [test: tests/test_bundles.py::test_refused_upload_gets_the_code_of_its_reason_and_stores_nothing]
  [test: tests/test_storage.py::test_upload_into_a_full_database_answers_storage_full_and_the_relay_serves_on]
  [test: tests/test_storage.py::test_send_into_a_full_database_answers_storage_full_and_stores_nothing].
- Stop applies to the refused frame only: the connection and the other frames go on.
- BAD_BUNDLE and IDENTITY_KEY_MISMATCH are also results of the client's own checks of a
  fetched bundle (sections 5.4 and 11.4).
- A code that a client does not know is handled as Stop for the refused frame.
- The codes 8 and 9, QUOTA_FULL and BLOB_TOO_LARGE, refuse blob frames only. Section 31.6
  lists them with the codes of this table that refuse a blob frame.

The relay sends each code under the stated condition and no other
[test: tests/test_bundles.py::test_refused_upload_gets_the_code_of_its_reason_and_stores_nothing]
[test: tests/test_bundles.py::test_fetch_for_an_identity_that_is_not_registered_answers_not_found]
[test: tests/test_storage.py::test_upload_into_a_full_database_answers_storage_full_and_the_relay_serves_on]
[test: tests/test_messages.py::test_send_to_an_identity_that_is_not_registered_answers_unknown_recipient]
[test: tests/test_storage.py::test_send_into_a_full_database_answers_storage_full_and_stores_nothing]
[test: tests/test_limits.py::test_send_over_a_queue_cap_answers_queue_full_until_an_ack_makes_room]
[test: tests/test_limits.py::test_frames_over_the_bucket_are_rate_limited_and_change_nothing].

### 11.3 Close codes

A violation closes the connection. The number is the WebSocket close code; the name is
what a negative test vector uses (section 15.2). The reason text of a close carries no
meaning, and a peer MUST NOT parse it.

| Code | Name               | Sent by     | Sent when                                                                 | Client |
|------|--------------------|-------------|---------------------------------------------------------------------------|--------|
| 1001 | SHUTDOWN           | relay       | The relay shuts down                                                      | Retry  |
| 1003 | TEXT_FRAME         | either side | A WebSocket text message arrived (section 6.2)                            | Stop   |
| 1008 | PROTOCOL_VIOLATION | either side | A malformed frame (section 7.3), a frame before login or a second Login (section 7.4) | Stop |
| 1009 | FRAME_TOO_BIG      | either side | A message above MAX_FRAME_BYTES arrived (section 6.3)                     | Stop   |
| 3000 | LOGIN_REFUSED      | relay       | The identity key of a Login is excluded by section 3.3, or its signature does not verify | Stop |
| 3008 | LOGIN_TIMEOUT      | relay       | No Login arrived within LOGIN_DEADLINE_SECONDS                            | Retry  |
| 4001 | REPLACED           | relay       | A newer login of the same identity succeeded (section 8.5)                | Stop   |

- The column "Client" is what a client does when the relay closed with the code
  [test: tests/client/test_transport.py::test_close_codes_get_the_action_of_section_11_3] [test: tests/client/test_transport.py::test_replaced_client_stops]. 1003, 1008 and 1009 from the relay mean that the client broke the
  protocol, and a new connection would break it again.
- A client that closes because the relay sent a text message, a malformed frame or a
  message above the limit uses the same codes and then retries.
- Any other close code, and a connection that ends without a close, is handled as Retry.
- Close code 1000 is not a violation. A client that ends a connection for a reason of its
  own closes with it, the unknown version of section 14.1 included.
- The numbers and the names of the table are those in the code of the relay
  [test: tests/test_docs.py::test_close_codes_of_the_relay_are_those_of_the_spec].
- The relay sends each code under the stated condition. Sections 6.2, 6.3, 7.3, 7.4, 7.6
  and 8.5 state the conditions as rules and cite their tests.
- When the relay fails while it serves a connection, its WebSocket library closes the
  connection with 1011
  [test: tests/test_connection.py::test_failed_handler_closes_with_1011_and_logs_no_text_of_the_exception].
  Like the 1007 of section 6.2 it is no code of this protocol, and the rule for any other
  close code applies.
- On an orderly shutdown the relay closes every open connection with 1001
  [test: tests/test_connection.py::test_shutdown_closes_every_connection_with_1001] and exits with
  status 0 [test: tests/test_process.py::test_relay_logs_json_lines_and_exits_0_on_sigterm].

### 11.4 Local results

Some checks run inside one implementation and end in no frame. Their failures have names
too, so that a test vector can state them (section 15.2).

| Name                  | Where                         | Meaning                                                       |
|-----------------------|-------------------------------|---------------------------------------------------------------|
| INVALID_ID            | The decoder of section 3.3    | The string is not a user id                                   |
| BAD_BUNDLE            | The checks of section 5.4     | Check 1, 2 or 4 failed                                        |
| IDENTITY_KEY_MISMATCH | The checks of section 5.4     | Check 3 failed: the bundle carries another X25519 identity key than the pinned one |
| LOGIN_REFUSED         | The checks of section 8.3     | Step 4 or 5 failed                                            |

A check that ends in one of these names hands back nothing else: the decoder returns no
bytes
[test: tests/crypto/test_identity_vectors.py::test_negative_vectors_raise_their_named_error].
A client that gets one of the first three reports it and uses neither the id nor the
bundle
[test: tests/client/test_session.py::test_invalid_id_adds_no_contact]
[test: tests/client/test_session.py::test_bundle_of_another_identity_is_refused_before_any_diffie_hellman]
[test: tests/client/test_session.py::test_bundle_with_another_x25519_key_than_the_pin_is_refused_before_any_diffie_hellman]
[test: tests/client/test_transport.py::test_substituted_bundle_is_refused_and_nothing_is_sent]. Section 24.2 names the local results of the end-to-end protocol.

## 12. Limits

### 12.1 The table

| Name                    | Default  | Unit     | Meaning                                                               |
|-------------------------|----------|----------|-----------------------------------------------------------------------|
| MAX_FRAME_BYTES         | 65536    | bytes    | The largest frame in either direction, 64 KiB (section 6.3)           |
| LOGIN_DEADLINE_SECONDS  | 10       | seconds  | The time a client has to send its Login after the Hello (section 8.3) |
| MESSAGE_TTL_SECONDS     | 2592000  | seconds  | The time the relay keeps a message that is not acked, 30 days (section 10.7) |
| QUEUE_MAX_MESSAGES      | 1000     | messages | The largest number of messages in the queue of one recipient          |
| QUEUE_MAX_BYTES         | 16777216 | bytes    | The largest sum of payload lengths in the queue of one recipient, 16 MiB |
| ONE_TIME_PREKEY_CAP     | 100      | keys     | The largest number of one-time prekeys stored for one identity        |
| FRAME_BUCKET_SIZE       | 60       | tokens   | The size of the frame bucket of one identity                          |
| FRAME_REFILL_SECONDS    | 1        | seconds  | The time in which one token returns to a frame bucket                 |
| HANDOUT_BUCKET_SIZE     | 20       | tokens   | The size of the handout bucket of one target identity                 |
| HANDOUT_REFILL_SECONDS  | 300      | seconds  | The time in which one token returns to a handout bucket, 5 minutes    |
| MAX_PAGES               | 2097152  | pages    | The page ceiling of the database, 8 GiB at pages of 4096 bytes (section 31.7) |
| SWEEP_INTERVAL_SECONDS  | 60       | seconds  | The time between two sweeps (section 13)                              |
| BLOB_MAX_BYTES          | 104883216 | bytes   | The largest blob the relay accepts: the blob of a file of MAX_FILE_BYTES, 100 MiB (section 29.5). Announced in LoggedIn; at most 2^32 - 1 |
| BLOB_QUOTA_BYTES        | 268435456 | bytes   | The largest sum of the lengths of the blobs the relay holds for one uploader, 256 MiB |
| BLOB_TTL_SECONDS        | 3196800  | seconds  | The time after the last write of a blob at which it expires, 37 days: MESSAGE_TTL_SECONDS and one week |

MAX_FRAME_BYTES is a constant of the relay (see below). Every other value is the default
of a setting that the relay reads from the environment variable of the same name with the
prefix `RELAY_`. A test compares this table with the code, constant by constant
[test: tests/test_docs.py::test_limits_table_is_the_settings_of_the_relay].

One frame carries a limit of this table: LoggedIn carries BLOB_MAX_BYTES (section 28.2).
A client uses the defaults of the four others it needs:
MAX_FRAME_BYTES, ONE_TIME_PREKEY_CAP, FRAME_REFILL_SECONDS and MESSAGE_TTL_SECONDS.

- MAX_FRAME_BYTES is a constant of relay protocol version 1. A relay that serves clients
  MUST NOT run with another value: with a larger one it stores a message that no client
  can receive, with a smaller one it closes on a frame that this protocol allows.
- A relay with another ONE_TIME_PREKEY_CAP or FRAME_REFILL_SECONDS still works with a
  client that assumes the defaults (sections 9.1 and 11.1). These and the other settings
  of the table are the operator's to change.
- A client builds two times of its own on MESSAGE_TTL_SECONDS: how long it keeps a seen id
  and how long it keeps the private key of a signed prekey that it replaced
  (sections 20.4 and 21.2). A relay with a shorter value works with a client that assumes
  the default. With a longer value, a message that waited longer than the default and one
  week can name a signed prekey that the client has deleted, or be a copy of a message
  whose seen id is gone. Such a message fails and is never read a second time
  (sections 16.8 and 20.4).

### 12.2 Token buckets

A bucket holds at most its size in tokens and is full when it is made. Tokens return at
the rate of one per refill time, up to the size. Buckets live in the memory of the relay
process: a restart of the relay fills them, a new login does not. A bucket that is full
again is the same as a new one, and the relay MAY forget it
[test: tests/test_limits.py::test_rate_limited_frame_passes_after_the_refill]
[test: tests/test_limits.py::test_login_and_ack_take_no_token_and_a_new_login_keeps_the_bucket]
[test: tests/test_limits.py::test_full_bucket_is_forgotten_and_is_the_same_as_a_new_one].

- The frame bucket belongs to an identity. Every Send, UploadBundle and FetchBundle of the
  identity takes one token before anything else is done with the frame, whatever the
  answer turns out to be. A frame that finds no token is refused with RATE_LIMITED and
  changes nothing [test: tests/test_limits.py::test_frames_over_the_bucket_are_rate_limited_and_change_nothing].
  A Login and an Ack take no token
  [test: tests/test_limits.py::test_login_and_ack_take_no_token_and_a_new_login_keeps_the_bucket]. A Login comes
  before the identity is known. An Ack has no answer that could refuse it, and an Ack that
  is dropped keeps a message on the relay. Acks are therefore not limited: one identity
  can send them without bound, and each makes the relay look up every pair it names.
- Of the blob frames of part 3, a StartBlob takes a token and the others do not
  (section 31.2) [test: tests/test_blobs.py::test_start_takes_a_token_and_put_fetch_and_delete_take_none].
- The handout bucket belongs to a target identity. Handing out one of its one-time prekeys
  takes one token, whoever asks. A fetch that finds no token gets the bundle without a
  one-time prekey and no Error (section 9.3)
  [test: tests/test_limits.py::test_fetches_past_the_handout_bucket_leave_the_stored_one_time_prekeys].

Identities are free, so the frame bucket gives fairness between honest clients and bounds
no attacker: a new identity starts with a full one. The handout bucket is keyed by the
target, so it holds whatever the number of identities that ask: it bounds how fast the
one-time prekeys of one target are taken, not whether they stay available. The other
bounds that hold are the caps of the queue and the page ceiling (threat model, "Not
protected").

### 12.3 The other caps

- QUEUE_MAX_MESSAGES and QUEUE_MAX_BYTES count every message of a queue, delivered or
  not. A Send that would go over either gets QUEUE_FULL (section 10.2).
- ONE_TIME_PREKEY_CAP bounds what an upload stores (section 9.1).
- MAX_PAGES bounds the database file. A write that needs a page above it fails, the relay
  answers STORAGE_FULL and stays up
  [test: tests/test_storage.py::test_upload_into_a_full_database_answers_storage_full_and_the_relay_serves_on].
  The ceiling does not bound the write-ahead log (section 13.2). A write that fails
  because the disk is full is the same failure to the relay and gets the same answer; no
  test covers a full disk.

### 12.4 The limits of part 3

BLOB_MAX_BYTES, BLOB_QUOTA_BYTES and BLOB_TTL_SECONDS are settings of the table of
section 12.1. BLOB_CHUNK_BYTES is a constant in the table of section 31.7, which says how
each of the four bounds the blob frames. Blobs count toward MAX_PAGES.

## 13. Erasure on the relay

### 13.1 What is deleted, and when

The relay deletes a message in two cases:

- its recipient acked it (section 10.5): the deletion is part of the handling of the Ack;
- MESSAGE_TTL_SECONDS passed since it was stored (section 10.7): the deletion is part of a
  sweep.

The relay delivers no message that it deleted [test: tests/test_messages.py::test_ack_deletes_the_message_and_is_safe_to_repeat]
[test: tests/test_storage.py::test_expired_message_is_deleted_by_the_sweep_and_never_delivered]. A Send
that is repeated after the deletion is a new message for the relay (section 10.3).

### 13.2 What "deleted" means

"Deleted after the ack" means: after the first sweep that follows the deletion, the
payload of the message and its message id are in none of the files of the database: the
database file, its write-ahead log and the index of that log, the files that end in `-wal`
and `-shm`
[test: tests/test_storage.py::test_acked_message_is_in_no_file_of_the_database_after_the_sweep]
[test: tests/test_storage.py::test_expired_message_is_in_no_file_of_the_database_after_the_sweep].

How the relay gets there:

- The database runs with `secure_delete` on, so the deletion overwrites the bytes of the
  row with zeros instead of leaving them in a free page
  [test: tests/test_storage.py::test_every_open_sets_the_pragmas_of_the_relay].
- The database runs in write-ahead mode, so until a checkpoint the old pages of the row
  remain in the write-ahead log file. A sweep ends with a checkpoint that moves the log
  into the database file and truncates the log to zero length
  [test: tests/test_storage.py::test_acked_message_is_in_no_file_of_the_database_after_the_sweep].
- A sweep runs every SWEEP_INTERVAL_SECONDS while the relay runs, from one interval after
  the start. A sweep that fails is logged, and the next one runs at its time
  [test: tests/test_storage.py::test_expired_message_is_deleted_by_the_sweep_and_never_delivered]
  [test: tests/test_storage.py::test_failed_sweep_is_logged_and_the_next_sweep_runs].
  Between the deletion and the next sweep the bytes can be read from the log file
  [test: tests/test_storage.py::test_acked_message_is_in_no_file_of_the_database_after_the_sweep].
- On an orderly shutdown the relay closes the database, which runs a last checkpoint and
  removes the log file
  [test: tests/test_storage.py::test_relay_restarted_on_the_same_file_serves_the_bundle]
  [test: tests/test_process.py::test_relay_logs_json_lines_and_exits_0_on_sigterm].
- A relay that is killed runs no sweep. What was deleted after its last sweep stays in the
  log file until the relay runs again and sweeps.

### 13.3 Out of scope

- What lies below the files: blocks that the filesystem or the storage device keeps after
  an overwrite or a truncation, snapshots and backups of the host.
- A relay that does not run this code. The rules of this section describe the relay of
  this repository; whoever runs a relay can keep a copy of every frame (threat model,
  "What the relay can do").

### 13.4 Blobs

The blobs of part 3 are deleted by a DeleteBlob or by expiry, and "deleted" means for
them what section 13.2 says (section 31.8)
[test: tests/test_blobs.py::test_deleted_blob_is_in_no_file_of_the_database_after_the_sweep].

## 14. Versioning

### 14.1 The relay protocol version

The relay protocol version is 1. It appears in one place on the wire: the `version` field
of Hello, the first frame of every connection.

- In every version of the relay protocol the first frame of the relay is a ServerFrame
  with field 1, `hello`, set, and `version` is field 1 of that Hello.
- A client reads `version` before it applies any other rule to the Hello. A client that
  reads a `version` other than 1, 0 included, sends no Login, closes the connection with
  close code 1000, reports that the relay speaks a version it does not implement, and
  stops (section 11.1) [test: tests/client/test_transport.py::test_unknown_relay_version_ends_with_1000_and_stops].
- A client states no version. A client that stays on the connection speaks the version of
  the Hello.
- A change that an implementation of version 1 would refuse or misread is a new version:
  a new frame that a client could send to a relay without the frame, a new meaning of a
  field, a new layout of the login string. A new field that a receiver of version 1 can
  ignore is not, and neither is a new frame that a client sends only to a relay that
  announced it in its LoggedIn: the blob frames of part 3 are of this kind
  (section 28.2).

### 14.2 The end-to-end protocol version

The end-to-end protocol version is 1. It appears in one place on the wire, inside the
payload: the `version` field of the peer envelope (section 19.2). It is also the first
byte of the session associated data, which is not sent and which every message of a
session authenticates (section 16.5)
[test: tests/client/test_session.py::test_two_clients_exchange_texts_in_both_directions]. The relay does not read it and
has no rule about it (section 7.12).

- In every version of the end-to-end protocol the payload is a `PeerMessage` whose field 1
  is `version`.
- A client reads `version` before it applies any other rule to the envelope. A client that
  reads a `version` other than 1, 0 included, decrypts nothing and changes nothing in its
  store: it reports that the contact uses a version it does not implement and acks the
  message (section 19.4)
  [test: tests/client/test_session.py::test_other_version_is_acked_and_changes_nothing].
- A change that a client of version 1 would refuse or misread is a new version: another
  layout of the header, of the associated data or of the padding, another cipher or key
  derivation. A new member of the `Content` oneof is not: a client of version 1 reports
  such a message as UNKNOWN_CONTENT (section 19.5). `attachment` of part 3 and `profile`
  of part 4 are of this kind.
- A bundle has no version field. The keys and signatures of a bundle are those of version
  1; a version that adds a key adds a field and a signed string for it.

### 14.3 The label in the signed strings

The prefixes of section 4 are constants. The digit in `sotto/1` is part of the constant
and no implementation parses it. A signed string whose layout or meaning changes gets a
new prefix, so that a signature made for one layout never verifies for another.

## 15. Test vectors

### 15.1 Purpose

The implementations share test vectors: files `vectors/*.json` in this repository, written
by a generator that is run by hand from fixed seeds. An implementation that replays every
vector and gets the stated results agrees with the others on every byte the vectors cover
[test: tests/crypto/test_identity_vectors.py::test_positive_vectors_replay_byte_for_byte]
[test: tests/crypto/test_identity_vectors.py::test_negative_vectors_raise_their_named_error]
[test: tests/crypto/test_x3dh_vectors.py::test_positive_vectors_replay_byte_for_byte]
[test: tests/crypto/test_x3dh_vectors.py::test_negative_vectors_raise_their_named_error]
[test: tests/crypto/test_ratchet_vectors.py::test_positive_vectors_replay_byte_for_byte]
[test: tests/crypto/test_ratchet_vectors.py::test_negative_vectors_raise_their_named_error].
The first file is `vectors/identity.json`; section 15.5 names its operations and the keys
of their objects
[test: tests/crypto/test_identity_vectors.py::test_vectors_use_the_operations_and_keys_of_the_document].
The second is `vectors/x3dh.json`, whose operations section 15.6 names, and the third
`vectors/ratchet.json`, whose operations section 15.7 names. Section 24.3 says what the
vectors of the key agreement and of the ratchet record. The fourth is `vectors/blob.json`
of part 3, whose operations section 34 names
[test: tests/crypto/test_blob_vectors.py::test_positive_vectors_replay_byte_for_byte]
[test: tests/crypto/test_blob_vectors.py::test_negative_vectors_raise_their_named_error],
and the fifth `vectors/profile.json` of part 4, whose operations section 37 names
[test: tests/crypto/test_profile_vectors.py::test_positive_vectors_replay_byte_for_byte]
[test: tests/crypto/test_profile_vectors.py::test_negative_vectors_raise_their_named_error].

### 15.2 The schema of a vector file

A vector file is one JSON object in UTF-8.

| Key       | Type    | Meaning                                                          |
|-----------|---------|------------------------------------------------------------------|
| `schema`  | integer | The version of this schema, 1                                    |
| `vectors` | array   | The vectors, in the order in which they were added               |

Each vector is a JSON object.

| Key             | Type   | Presence                 | Meaning                                                        |
|-----------------|--------|--------------------------|----------------------------------------------------------------|
| `name`          | string | always                   | Unique within the file; lowercase letters, digits and `-`      |
| `operation`     | string | always                   | The operation the vector exercises                             |
| `inputs`        | object | always                   | Everything the operation consumes                              |
| `intermediates` | object | always, MAY be empty     | Every value the operation computes on the way to its result    |
| `outputs`       | object | positive case only       | The expected result, MAY be empty for a check that passes      |
| `error`         | string | negative case only       | The expected failure: one name of section 11, 24.2, 33.6 or 36.7 |

Rules:

- A vector has `outputs` or `error`, never both and never neither.
- Bytes are hex strings as in section 2.1. Text is a JSON string. A count or an id is a
  JSON number. A list of records is a JSON array of objects whose values follow these
  rules. A value that is absent in the operation is absent in the object.
- Every private key, ephemeral key, nonce and message id that an operation uses is in
  `inputs`: replaying a vector draws no random byte.
- `intermediates` holds each value an implementation needs to find where it went wrong,
  the signed strings of section 4 among them.
- `error` is an Error code of section 11.2, the name of a close code of section 11.3 or a
  local result of section 11.4, 24.2, 33.6 or 36.7, spelled as there.
- A reader refuses a file whose `schema` it does not know, and reports a vector whose
  `operation` it does not implement instead of skipping it.

### 15.3 Signatures

A signature appears in a vector only as a value to verify: it is an input, made by the
generator, and the expected result is that it verifies or that it does not. No vector
expects an implementation to produce particular signature bytes, because CryptoKit signs
with randomization (section 4.1, rule 5).

### 15.4 A tagged file is append-only

Protocol releases are tagged in this repository. From the first tag that contains a vector
file, the vectors of that file are frozen: a later commit appends vectors and never
changes or removes one. A change to an existing vector is a change of the protocol and
needs a new number for the version that covers the operation of the vector (section 1.3).

### 15.5 The operations of `vectors/identity.json`

The file covers sections 3 to 5 and the login checks of section 8.3. It is written by
`scripts/generate_vectors.py`. `user_id`, `contact_id` and `server_name` are text, the two
prekey ids are numbers, and every other value is a hex string.

| Operation | Rule | `inputs` | `intermediates` | `outputs` | `error` |
|-----------|------|----------|-----------------|-----------|---------|
| `identity-key` | 3.1, 3.2 | `seed` | | `identity_key`, `user_id` | |
| `x25519-public-key` | 5.1 | `private_key` | | `public_key` | |
| `decode-user-id` | 3.3 | `user_id` | | `identity_key` | INVALID_ID |
| `verify-login` | 8.3, steps 4 and 5 | `identity_key`, `client_nonce`, `signature`, `server_name`, `server_nonce` | `login_string` | | LOGIN_REFUSED |
| `check-bundle` | 3.3, 5.4 | `contact_id`, `pinned_identity_dh_key`, `identity`, `identity_dh_key`, `identity_dh_signature`, `signed_prekey_id`, `signed_prekey_key`, `signed_prekey_signature`, `one_time_prekey_id`, `one_time_prekey_key` | `identity_dh_string`, `signed_prekey_string` | | INVALID_ID, BAD_BUNDLE, IDENTITY_KEY_MISMATCH |

- `identity-key`: the identity key of the seed (section 3.1) and its user id
  (section 3.2).
- `x25519-public-key`: the public key of a 32-byte X25519 private key, which is X25519 of
  the private key and the base point 9 (RFC 7748 section 6.1):
  `X25519PrivateKey.from_private_bytes` and `public_bytes_raw` in the Python package
  cryptography; `Curve25519.KeyAgreement.PrivateKey(rawRepresentation:)` and
  `publicKey.rawRepresentation` in CryptoKit.
- `decode-user-id`: the decoder of section 3.3 on the text `user_id`.
- `verify-login`: steps 4 and 5 of section 8.3 on the fields of a Login (section 7.6),
  with `server_name` in the place of RELAY_NAME and `server_nonce` in the place of the
  nonce of the Hello.
- `check-bundle`: the decoder of section 3.3 on `contact_id`, which ends the operation
  with INVALID_ID when the id does not decode, then the four checks of section 5.4 on the
  fields of a Bundle (section 7.11). `signed_prekey_id`, `signed_prekey_key` and
  `signed_prekey_signature` are the fields of `signed_prekey`, `one_time_prekey_id` and
  `one_time_prekey_key` those of `one_time_prekey`; the last two are absent when the
  bundle has no one-time prekey. `pinned_identity_dh_key` is the pin the client holds for
  the contact and is absent when it holds none.
- The intermediates are the signed strings of section 4 that the inputs of a vector
  determine. A negative vector records them too, whichever step fails.
- A signature that is expected to fail is a valid signature over another string of
  section 4, a valid signature by another identity, or a valid signature with the lowest
  bit of its byte 32 changed. Under a key that step 3 or 4 of section 3.3 excludes it is
  the 32-byte encoding of the neutral point followed by 32 zero bytes, which a library can
  accept under such a key for every string; these vectors are refused before any signature
  is verified.

### 15.6 The operations of `vectors/x3dh.json`

The file covers the key agreement of section 16 and records what section 24.3 lists
[test: tests/crypto/test_x3dh_vectors.py::test_vectors_use_the_operations_and_keys_of_the_document].
It is written by `scripts/generate_vectors.py`. `contact_id` is text, the two prekey ids
are numbers, and every other value is a hex string.

| Operation | Rule | `inputs` | `intermediates` | `outputs` | `error` |
|-----------|------|----------|-----------------|-----------|---------|
| `x3dh-initiate` | 5.4, 16.6, steps 1 to 6 | `identity_key`, `identity_dh_private_key`, `ephemeral_private_key`, `contact_id`, `identity`, `identity_dh_key`, `identity_dh_signature`, `signed_prekey_id`, `signed_prekey_key`, `signed_prekey_signature`, `one_time_prekey_id`, `one_time_prekey_key` | `identity_dh_string`, `signed_prekey_string`, `dh1`, `dh2`, `dh3`, `dh4`, `input_key_material` | `sk`, `session_associated_data` | ZERO_DH |
| `x3dh-respond` | 16.8, steps 1, 2 and 5 to 7 | `identity_key`, `identity_dh_private_key`, `signed_prekey_private_key`, `one_time_prekey_private_key`, `sender`, `identity_dh_key`, `identity_dh_signature`, `ephemeral_key`, `signed_prekey_id`, `one_time_prekey_id` | `identity_dh_string`, `dh1`, `dh2`, `dh3`, `dh4`, `input_key_material` | `sk`, `session_associated_data` | ZERO_DH |

- In both operations `identity_key` is the identity key of the side that runs the
  operation and `identity_dh_private_key` the private key of its X25519 identity key. A
  private key is the 32 bytes of section 16.2. No vector holds a pinned X25519 identity
  key: check 3 of section 5.4 and step 2 of section 16.8 pass without one.
- `x3dh-initiate`: `contact_id` and the eight fields of the Bundle are those of
  `check-bundle` (section 15.5), and the operation starts as `check-bundle` does. Then it
  runs steps 3 to 6 of section 16.6 with `ephemeral_private_key` as the private key of
  EK_A, in the place of the random bytes of step 2.
- `x3dh-respond`: the key agreement for an initial message that matches no record.
  `sender` is the `sender` of the Deliver. `identity_dh_key`, `identity_dh_signature`,
  `ephemeral_key`, `signed_prekey_id` and `one_time_prekey_id` are the fields of the
  initial header (section 16.7). `signed_prekey_private_key` and
  `one_time_prekey_private_key` are the private keys that the responder holds under the
  two ids; `one_time_prekey_private_key` is absent exactly when `one_time_prekey_id` is.
  Steps 3 and 4 of section 16.8 are not part of the operation: the vector gives the keys
  that the ids name, and the ids are recorded as fields of the header that nothing reads.
- `identity_dh_string` and `signed_prekey_string` are the strings of sections 4.3 and 4.4
  that the operation verifies. `dh1` to `dh4` are DH1 to DH4, each the 32 bytes of the
  output; `dh4` is absent when the key agreement has no one-time prekey.
  `input_key_material` is the input of the key derivation of section 16.4, 160 or 128
  bytes. `sk` is SK, and `session_associated_data` is the 161 bytes of section 16.5.
- A vector with the `error` ZERO_DH records the signed strings and no other intermediate:
  the operation ends in step 4 of section 16.6 or in step 5 of section 16.8. In
  `x3dh-initiate-one-time-prekey-of-small-order` the one-time prekey of the Bundle is the
  u-coordinate 0, and DH4 is zero. In `x3dh-respond-ephemeral-key-of-small-order`
  `ephemeral_key` is a point of order 8, and DH2, DH3 and DH4 are zero.
- A vector of `x3dh-initiate` and the vector of `x3dh-respond` with the same name after
  the operation are the two sides of one key agreement: `ephemeral_key` of the responder
  is the public key of `ephemeral_private_key` of the initiator
  [test: tests/crypto/test_x3dh_vectors.py::test_vectors_of_one_name_are_the_two_sides_of_one_key_agreement].
  The pairs `with-a-one-time-prekey` and `without-a-one-time-prekey` have equal outputs.
  The Bundle of the first is the one of `check-bundle-first-fetch`.
- `replaced-one-time-prekey`: the Bundle reached the initiator with another
  `one_time_prekey_key` under the same id. The responder computes DH4 with the private key
  it holds under that id: the two vectors have the same session associated data and
  another `sk`.
- `unknown-key-share`: the contact of the initiator is a third identity, whose Bundle
  carries the X25519 keys of the responder under its own signatures. The two vectors have
  the same `sk`. Bytes 65 to 96 of the session associated data are the identity key of the
  contact at the initiator and the responder's own at the responder.
- `x3dh-respond-ephemeral-key-top-bit-set` and `x3dh-respond-ephemeral-key-inverse` are
  `x3dh-respond-with-a-one-time-prekey` with other bytes in `ephemeral_key`: the most
  significant bit of the last byte set, and the u-coordinate replaced by its inverse
  modulo 2^255 - 19. Both have the intermediates and the `sk` of that vector. Bytes 129
  to 160 of their session associated data are the bytes received
  [test: tests/crypto/test_x3dh_vectors.py::test_outputs_of_the_two_sides_differ_as_section_24_3_states].

### 15.7 The operations of `vectors/ratchet.json`

The file covers sections 17 and 18 and records what section 24.3 lists
[test: tests/crypto/test_ratchet_vectors.py::test_vectors_use_the_operations_and_keys_of_the_document]
[test: tests/crypto/test_ratchet_vectors.py::test_intermediates_are_the_values_of_the_core].
It is written by `scripts/generate_vectors.py`. `party` is text, `purged_count` is a
number, `stored_skipped_keys` and `purged_skipped_keys` are arrays of objects, and every
other value is a hex string.

| Operation | Rule | `inputs` | `intermediates` | `outputs` | `error` |
|-----------|------|----------|-----------------|-----------|---------|
| `ratchet-init-initiator` | 17.3 | `sk`, `session_associated_data`, `signed_prekey_key`, `ratchet_private_key` | `ratchet_key`, `dh`, `root_key`, `chain_key` | | |
| `ratchet-init-responder` | 17.3 | `sk`, `session_associated_data`, `signed_prekey_private_key` | `ratchet_key` | | |
| `ratchet-encrypt` | 17.6, 18 | `party`, `message_id`, `nonce`, `padded_plaintext` | `chain_key`, `message_key`, `header`, `associated_data` | `ciphertext` | NO_SENDING_CHAIN |
| `ratchet-decrypt` | 17.7, 17.8, 18 | `party`, `message_id`, `header`, `ciphertext`, `ratchet_private_key` | `dh_receiving`, `root_key_receiving`, `chain_key_receiving`, `ratchet_key`, `dh_sending`, `root_key_sending`, `chain_key_sending`, `chain_key`, `message_key`, `associated_data`, `stored_skipped_keys`, `purged_skipped_keys` | `padded_plaintext`, `purged_count` | DECRYPT_FAILED, TOO_MANY_SKIPPED, CHAIN_EXHAUSTED, ZERO_DH |

- The vectors are the steps of one conversation, in the order in which they run. A vector
  works on the states that the vectors before it in the file left, and `party`,
  `initiator` or `responder`, names the side whose state it uses. A vector with an `error`
  leaves that state as it was (section 17.7).
- The session is the one of the two vectors of section 15.6 named
  `with-a-one-time-prekey`: `sk` and `session_associated_data` of each initialisation are
  the outputs of the vector of its side, and `signed_prekey_key` is the public key of
  `signed_prekey_private_key`
  [test: tests/crypto/test_ratchet_vectors.py::test_conversation_runs_on_the_session_of_the_x3dh_vectors].
  The session associated data stays with the side for every later vector.
- `ratchet-init-initiator` takes `ratchet_private_key` as the 32 random bytes of
  section 17.3. `ratchet_key` is the public key of DHs, `dh` the Diffie-Hellman output,
  `root_key` and `chain_key` the two outputs of KDF_RK. `ratchet-init-responder` records
  the public key of its signed prekey as `ratchet_key`.
- `ratchet-encrypt`: `chain_key` is CKs before the message and `message_key` the message
  key derived from it; `header` is the 40 bytes of section 17.5, `associated_data` the
  217 bytes of section 18.2 and `ciphertext` the field of section 18.3. The padded
  plaintext of a message is a `Content` whose `text` is `message ` followed by the label
  of the message, padded by section 19.6. The labels `i0` to `i9` are the messages of the
  initiator and `r0` to `r6` those of the responder, numbered in the order in which they
  are encrypted.
- `ratchet-decrypt` takes `message_id`, `header` and `ciphertext` of the message it opens,
  as they were sent or as the vector changed them. `ratchet_private_key` is the 32 random
  bytes of section 17.7 and is present exactly when the decryption reaches sub-step 4 of
  step 5, a decryption that then fails included. The seven keys from `dh_receiving` to
  `chain_key_sending` are present exactly when a DH ratchet step was taken: the
  Diffie-Hellman output, the root key and the chain key of each KDF_RK, and the new
  ratchet public key between them. `chain_key` is CKr before the key of the message was
  derived and is absent when that key came from MKSKIPPED (step 2).
- An object of `stored_skipped_keys` or `purged_skipped_keys` is an entry of MKSKIPPED
  (section 17.2) with the keys `ratchet_key`, `number`, `message_key` and `step`; the two
  numbers are JSON numbers. `stored_skipped_keys` lists the entries the decryption added,
  `purged_skipped_keys` those that the cap or the purge of section 17.8 removed, and
  `purged_count` is the number of step 9 of section 17.7.
- A vector with an `error` records no intermediate. The vectors `ratchet-decrypt-tampered-`
  followed by `header`, `nonce`, `ciphertext` or `tag` change one byte of that part of a
  message that was sent, and `ratchet-decrypt-other-message-id` gives a message the id of
  another one. The other negative vectors of a decryption carry a header that names
  numbers or a ratchet key that no message of the conversation has, or a message a second
  time, or a message whose key was purged.

## 16. Key agreement

### 16.1 What it is

Two identities agree on a secret with X3DH Revision 1 and two deviations from it:
signatures are Ed25519 instead of XEdDSA, and an identity has an X25519 identity key of its
own, which its Ed25519 identity key signs (section 5.1). Section 25.1 lists every
difference from that text with its reason.

A key agreement gives both sides a 32-byte secret SK (section 16.4) and the session
associated data of 161 bytes (section 16.5). The relay takes part only by handing out the
bundle (section 9.2) and by passing on the messages that carry the initial header.

Terms of part 2:

- A contact: an identity whose user id the user gave to the client. The client holds the
  32 bytes that the id decodes to (section 3.3). The id of the client's own identity is
  never a contact: a client refuses to add it
  [test: tests/client/test_session.py::test_own_id_is_never_a_contact].
- The initiator, A in layouts: the client that starts a session from a fetched bundle.
- The responder, B in layouts: the client whose bundle was fetched.
- A session: what two clients share after a key agreement. At each client it is the
  ratchet state of section 17.2, the session associated data and, at the initiator, the
  initial header (section 16.7).
- An initial message: a message whose envelope carries an initial header (section 19.3).
- The peer: the identity at the other end of a session.

### 16.2 The keys

| Key              | Kind                                   | Made                                   | Role                                                                 |
|------------------|----------------------------------------|----------------------------------------|----------------------------------------------------------------------|
| IKsig_A, IKsig_B | Ed25519 identity key (section 3.1)     | Once, with the identity                | Signs IKdh and SPK (sections 4.3 and 4.4). Stands in the session associated data. Enters no Diffie-Hellman computation. |
| IKdh_A, IKdh_B   | X25519 identity key                    | Once, with the identity                | DH1 (IKdh_A) and DH2 (IKdh_B). Stands in the session associated data. |
| SPK_B            | Signed prekey, X25519, with a u32 id   | By B, replaced by section 21.2         | DH1 and DH3. Its key pair is the first ratchet key pair of B (section 17.3). |
| OPK_B            | One-time prekey, X25519, with a u32 id, not signed | By B, in batches (section 21.3) | DH4, in one key agreement.                                        |
| EK_A             | Ephemeral key, X25519                  | By A, for one key agreement            | DH2, DH3 and DH4. Stands in the session associated data as the bytes that were sent (section 16.5). |

- An X25519 private key is 32 random bytes. It is the scalar input of the X25519 function
  of RFC 7748 section 5, which clamps it. The public key is the output of that function
  for the private key and the base point 9: 32 bytes.
- Both libraries use these raw forms: `X25519PrivateKey.from_private_bytes`,
  `private_bytes_raw` and `public_key().public_bytes_raw()` in the Python package
  cryptography; `Curve25519.KeyAgreement.PrivateKey(rawRepresentation:)`,
  `rawRepresentation` and `publicKey.rawRepresentation` in CryptoKit. A test vector
  carries a private key as these 32 bytes
  [test: tests/crypto/test_x3dh_recompute.py::test_every_recorded_value_recomputes_without_the_core].
- A public key is stored, compared and put into a byte layout as the 32 bytes that were
  generated or received. No implementation decodes a public key and encodes it again
  [test: tests/crypto/test_x3dh.py::test_public_keys_enter_the_associated_data_as_the_bytes_received]
  [test: tests/crypto/test_ratchet.py::test_ratchet_keys_are_kept_as_the_bytes_received].
- An identity makes the key pair of IKdh together with its Ed25519 key pair and signs the
  string of section 4.3 for it. Any signature that verifies serves: the initial header and
  the bundle of one identity can carry different signature bytes (section 4.1, rule 5).

### 16.3 The Diffie-Hellman function

DH(k, P) is the X25519 function of RFC 7748 section 5 for the private key k and the public
key P. Its output is 32 bytes. The calls are `X25519PrivateKey.exchange` in the Python
package cryptography and `sharedSecretFromKeyAgreement(with:)` in CryptoKit, whose result
is read as its raw bytes.

An output of 32 zero bytes is refused: the operation that computed it ends with the result
ZERO_DH and uses the output for nothing
[test: tests/crypto/test_x3dh.py::test_dh_refuses_exactly_the_keys_of_small_order]
[test: tests/crypto/test_x3dh.py::test_zero_output_the_library_returns_is_refused].

- This is a rule of this text because the two libraries differ. The Python package
  cryptography raises an error for such an output. CryptoKit returns it, by a comment in
  the source of swift-crypto; nothing in this repository runs CryptoKit.
- Every implementation does both, whatever its library: it turns an error of the library
  on this call into ZERO_DH, and it compares the 32 bytes of an output with zero itself,
  by the OR of all bytes and not by a branch per byte.
- The rule holds for every Diffie-Hellman computation of this protocol: the four of the
  key agreement and those of the ratchet (section 17).
- The output is all zero exactly when P is a point of small order. An honest key never is.

### 16.4 The key derivation

SK is one call of HKDF (RFC 5869)
[test: tests/crypto/test_x3dh_recompute.py::test_every_recorded_value_recomputes_without_the_core]:

| Parameter          | Value                                                                    |
|--------------------|--------------------------------------------------------------------------|
| Hash               | SHA-256 (RFC 6234)                                                       |
| Salt               | 32 bytes `00`, passed to the library as an explicit value                |
| Input key material | With a one-time prekey: F \|\| DH1 \|\| DH2 \|\| DH3 \|\| DH4, 160 bytes. Without: F \|\| DH1 \|\| DH2 \|\| DH3, 128 bytes. F is 32 bytes `ff`. |
| Info               | ASCII `sotto/1 x3dh`, 12 bytes, hex `736f74746f2f312078336468`           |
| Output length      | 32 bytes                                                                 |
| Split              | None: the 32 bytes are SK                                                |

The calls are `HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes(32), info=...)` with
`derive` in the Python package cryptography and
`HKDF<SHA256>.deriveKey(inputKeyMaterial:salt:info:outputByteCount:)` in CryptoKit. An HKDF
object of the Python package serves one call.

### 16.5 The session associated data

Both sides build the same 161 bytes, the keys of the initiator first
[test: tests/crypto/test_x3dh.py::test_both_sides_derive_the_same_secret_and_associated_data]:

| Offset | Length | Field   | Value                                                  |
|--------|--------|---------|--------------------------------------------------------|
| 0      | 1      | version | `01`, the end-to-end protocol version as a u8          |
| 1      | 32     | IKsig_A | The identity key of the initiator                      |
| 33     | 32     | IKdh_A  | The X25519 identity key of the initiator               |
| 65     | 32     | IKsig_B | The identity key of the responder                      |
| 97     | 32     | IKdh_B  | The X25519 identity key of the responder               |
| 129    | 32     | EK_A    | The ephemeral key of the initiator: the bytes of `ephemeral_key` as the initiator sent them and as the responder received them |

Total length: 161 bytes.

The session associated data is the first part of the associated data of every message of
the session (section 18.2). The Diffie-Hellman values prove possession of the X25519 keys
only, while a user checks the Ed25519 key, the user id. A signature over an X25519 key
proves nothing about who holds its private key: anyone can sign the X25519 keys of someone
else. With both Ed25519 keys in the associated data, a message decrypts only when both
sides mean the same two identities. This is the case of an unknown key share: C publishes
the X25519 keys of B under its own signature, A starts a session with C, and the message
that reaches B does not decrypt there, because A put IKsig_C where B puts IKsig_B
[test: tests/crypto/test_x3dh.py::test_unknown_key_share_gives_the_same_secret_under_other_associated_data]
[test: tests/client/test_hostile_relay.py::test_lying_relay_gives_no_text_and_leaves_the_store_unchanged].

The ephemeral key stands in the associated data as bytes, because the Diffie-Hellman
values do not fix its bytes. The X25519 function gives one output for more than one
32-byte string: it ignores the most significant bit of the last byte (RFC 7748
section 5), and for a clamped private key a point and its sum with a point of small
order, which is another public key, give one output. Other bytes of either kind in
`ephemeral_key` therefore give the responder the same SK. They give another session
associated data, so no message decrypts under it
[test: tests/crypto/test_x3dh.py::test_other_ephemeral_key_bytes_give_the_same_secret_under_other_associated_data]
[test: tests/client/test_hostile_relay.py::test_lying_relay_gives_no_text_and_leaves_the_store_unchanged].
The record of an accepted initial message is found by these bytes and rests on that
(section 20.4).

### 16.6 The initiator

The initiator runs these steps in this order, for a contact and with a Bundle that it
fetched for this key agreement
[test: tests/crypto/test_x3dh.py::test_bundle_that_fails_a_check_reaches_no_diffie_hellman_computation]
[test: tests/crypto/test_x3dh.py::test_both_sides_derive_the_same_secret_and_associated_data].
One Bundle starts at most one session.

1. It runs the four checks of section 5.4 on the Bundle and stops at the first that
   fails. No later step runs for a bundle that failed a check.
2. It makes EK_A, a new X25519 key pair from 32 random bytes.
3. It computes, with the function of section 16.3:

   ```
   DH1 = DH(private key of IKdh_A, SPK_B)
   DH2 = DH(private key of EK_A,   IKdh_B)
   DH3 = DH(private key of EK_A,   SPK_B)
   DH4 = DH(private key of EK_A,   OPK_B)    only with a one-time prekey
   ```

   IKdh_B, SPK_B and OPK_B are `identity_dh_key`, `signed_prekey.key` and
   `one_time_prekey.key` of the Bundle. When the Bundle carries no one-time prekey, DH4
   is left out: it is not computed, and nothing stands in its place in step 5.
4. When one of the outputs is 32 zero bytes, the key agreement ends with ZERO_DH
   (section 16.3).
5. It derives SK (section 16.4).
6. It builds the session associated data (section 16.5) from its own two identity keys,
   from `identity` and `identity_dh_key` of the Bundle and from the public key of EK_A.
7. It deletes the private key of EK_A, the outputs DH1 to DH4 and the input of the key
   derivation: the key agreement of the core hands back SK and the session associated data
   and nothing else
   [test: tests/crypto/test_x3dh.py::test_key_agreement_hands_back_the_secret_and_the_associated_data_only].
8. It initialises the ratchet as initiator with SK, SPK_B and 32 random bytes
   (section 17.3) and deletes SK. In one transaction it stores the session with its
   initial header (section 16.7) and, when the contact has no pinned X25519 identity
   key, `identity_dh_key` of the Bundle as its pin
   [test: tests/crypto/test_ratchet_vectors.py::test_positive_vectors_replay_byte_for_byte]
   [test: tests/client/test_session.py::test_first_messages_to_an_offline_peer_decrypt_in_order_and_the_reply_ends_the_header]
   [test: tests/client/test_session.py::test_bundle_with_another_x25519_key_than_the_pin_is_refused_before_any_diffie_hellman]
   [test: tests/client/test_session.py::test_key_agreement_that_fails_after_the_checks_stores_no_session_and_no_pin].

A key agreement that ends in a failure stores nothing, a pin included, and the client
reports the result (section 20.3). A session without a one-time prekey is a session like
any other for every later step; the threat model states what its first messages lose.

### 16.7 The initial header

The initial header is what the responder needs to run the same key agreement. It is the
`InitialHeader` message of section 19.3, with these values
[test: tests/client/test_session.py::test_first_messages_to_an_offline_peer_decrypt_in_order_and_the_reply_ends_the_header]:

| Field                   | Length | Value                                                           |
|-------------------------|--------|-----------------------------------------------------------------|
| `identity_dh_key`       | 32     | IKdh_A                                                          |
| `identity_dh_signature` | 64     | A signature of A over the string of section 4.3 for IKdh_A      |
| `ephemeral_key`         | 32     | The public key of EK_A                                          |
| `signed_prekey_id`      | u32    | The `signed_prekey.id` of the Bundle                            |
| `one_time_prekey_id`    | u32    | The `one_time_prekey.id` of the Bundle. Present exactly when DH4 was computed |

IKsig_A is not a field. An initial header travels in a payload, and the identity key of
the sender of a payload is the `sender` of its Deliver (section 7.14): the relay of this
repository takes it from the connection that sent the message. There is no second copy
that a client could forget to compare.

When the initiator sends it, and when it stops
[test: tests/client/test_session.py::test_first_messages_to_an_offline_peer_decrypt_in_order_and_the_reply_ends_the_header]
[test: tests/client/test_session.py::test_outbox_bytes_sent_again_after_a_crash_give_one_text]:

- A session that a client made as initiator holds its initial header from the moment the
  session is stored.
- While a session holds an initial header, every message that the client encrypts on the
  session carries it, with the same value in every field each time.
- The session drops its initial header in the transaction that saves the first message
  decrypted on this session (section 22.2). No message encrypted on the session after
  that transaction carries one.
- A message that was encrypted before keeps its bytes when it is sent again
  (section 22.2), the initial header included.
- A session that a client made as responder never holds an initial header.

### 16.8 The responder

A client that received a Deliver from a contact with a payload that carries an initial
header runs these steps in this order and stops at the first that fails
[test: tests/client/test_session.py::test_initial_header_that_fails_step_1_or_2_changes_nothing]
[test: tests/client/test_session.py::test_unknown_signed_prekey_id_is_refused]
[test: tests/client/test_session.py::test_one_time_prekey_handed_to_two_initiators_starts_one_session]
[test: tests/client/test_session.py::test_substituted_one_time_prekey_ends_in_a_decrypt_failure_and_keeps_the_prekey]
[test: tests/client/test_session.py::test_key_agreement_that_fails_after_the_checks_stores_no_session_and_no_pin]
[test: tests/client/test_session.py::test_stored_responder_session_holds_neither_the_secret_nor_the_signed_prekey]
[test: tests/client/test_session.py::test_replayed_initial_message_gives_no_second_text]. Steps 1 and 2 run for every such message. Steps 3 to 9 run only when
the client holds no record for the pair of the `sender` and the `ephemeral_key`
(section 20.4); with a record, section 20.2 says what follows.

1. IKsig_A is the `sender` of the Deliver. The client builds the string of section 4.3
   from IKsig_A and `identity_dh_key` and verifies `identity_dh_signature` over it under
   IKsig_A. When it does not verify, the result is BAD_INITIAL_HEADER. Until this step
   passed, the client computes no Diffie-Hellman value with any key of the message.
2. When the client holds a pinned X25519 identity key for the contact (section 5.3),
   `identity_dh_key` has to equal it. Otherwise the result is IDENTITY_KEY_MISMATCH.
3. Among the signed prekeys it holds, the newest and those in their grace period
   (section 21.2), it finds the one whose id is `signed_prekey_id`. With none, the result
   is UNKNOWN_SIGNED_PREKEY. A signed prekey whose grace period is over counts as not
   held, whether or not its private key is deleted yet. The key is found by the id of
   the message, never by taking the newest.
4. When `one_time_prekey_id` is present, it finds the one-time prekey with that id among
   those whose private key it holds. With none, the result is UNKNOWN_ONE_TIME_PREKEY.
5. It computes, with the function of section 16.3:

   ```
   DH1 = DH(private key of SPK_B,  IKdh_A)
   DH2 = DH(private key of IKdh_B, EK_A)
   DH3 = DH(private key of SPK_B,  EK_A)
   DH4 = DH(private key of OPK_B,  EK_A)     only with `one_time_prekey_id`
   ```

   IKdh_A and EK_A are `identity_dh_key` and `ephemeral_key` of the initial header. When
   one of the outputs is 32 zero bytes, the result is ZERO_DH.
6. It derives SK (section 16.4), with the outputs in the same order as the initiator.
7. It builds the session associated data (section 16.5): IKsig_A of step 1 and IKdh_A of
   the initial header first, then its own identity key and X25519 identity key, then
   `ephemeral_key` as the bytes it received.
8. It initialises a ratchet as responder with SK and the key pair of the signed prekey of
   step 3 (section 17.3) and decrypts the message with it (section 17.7). When the
   message does not decrypt, the result is DECRYPT_FAILED: everything computed in steps 5
   to 8 is discarded, nothing is stored, and the one-time prekey of step 4 keeps its
   private key.
9. When the message decrypts, the client saves in the one transaction of section 22.2:
   the session; the record of the pair (IKsig_A, EK_A) with `signed_prekey_id`
   (section 20.4); the deletion of the private key of the one-time prekey of step 4; and,
   when the contact has no pinned X25519 identity key, `identity_dh_key` as its pin.

The message that the responder decrypts in step 8 is the first message of the initiator
that reaches it. It need not be number 0: every message of the initiator carries the
initial header until the initiator has decrypted a message of the responder. Any number
up to MAX_SKIP is decrypted in step 8, and the keys before it are skipped (section 17.7).

### 16.9 What is not authenticated

The prekey ids and the one-time prekey of a bundle are not signed (section 5.2). Of the
fields of an initial header, `identity_dh_key` is covered by its signature and
`ephemeral_key` by the session associated data of a message that decrypts
(section 16.5); nothing covers the two prekey ids. Whoever controls the relay can change
all of them. The table is about a Bundle and about the initial header of a message that
matches no record (section 20.4). Each change ends in one of three ways: the session
starts as it does without the change, the session does not start, or the session starts
without a one-time prekey. None ends in a session with someone else, and none in a
message that decrypts to another plaintext
[test: tests/crypto/test_x3dh.py::test_replaced_one_time_prekey_gives_the_responder_another_secret]
[test: tests/crypto/test_x3dh.py::test_one_time_prekey_id_taken_out_or_put_in_gives_another_secret]
[test: tests/crypto/test_x3dh.py::test_other_ephemeral_key_bytes_give_the_same_secret_under_other_associated_data]
[test: tests/client/test_session.py::test_substituted_one_time_prekey_ends_in_a_decrypt_failure_and_keeps_the_prekey]
[test: tests/client/test_session.py::test_one_time_prekey_handed_to_two_initiators_starts_one_session]
[test: tests/client/test_session.py::test_unknown_signed_prekey_id_is_refused]
[test: tests/client/test_session.py::test_initial_header_that_fails_step_1_or_2_changes_nothing]
[test: tests/client/test_hostile_relay.py::test_lying_relay_gives_no_text_and_leaves_the_store_unchanged]
[test: tests/client/test_lifecycle.py::test_initial_message_under_a_replaced_signed_prekey_decrypts_only_in_the_grace_period]:

| Change                                                              | What follows                                                                                   |
|---------------------------------------------------------------------|------------------------------------------------------------------------------------------------|
| The one-time prekey of a Bundle is replaced by another key          | A computes a DH4 that B cannot compute. B derives another SK: DECRYPT_FAILED. Other bytes that give the same Diffie-Hellman output (section 16.5) change nothing: the session starts |
| The one-time prekey id of a Bundle or of an initial header is changed | B holds no key with the id: UNKNOWN_ONE_TIME_PREKEY. Or it holds another key: DECRYPT_FAILED  |
| The one-time prekey is taken out of a Bundle                        | The session starts without a one-time prekey (section 16.6)                                    |
| One one-time prekey is handed to two initiators                     | The first initial message that B accepts starts its session and deletes the private key. The messages of the other initiator: UNKNOWN_ONE_TIME_PREKEY |
| The signed prekey id of a Bundle or of an initial header is changed | B holds no key with the id: UNKNOWN_SIGNED_PREKEY. Or it holds another key: DECRYPT_FAILED      |
| A Bundle carries a signed prekey that B replaced                    | During the grace period of that key (section 21.2) the session starts. After it: UNKNOWN_SIGNED_PREKEY |
| `one_time_prekey_id` is taken out of an initial header or put in    | B derives another SK, or finds no key: DECRYPT_FAILED or UNKNOWN_ONE_TIME_PREKEY                |
| `ephemeral_key` of an initial header is changed                     | B derives another SK, or the same SK under another session associated data (section 16.5): DECRYPT_FAILED. A key of small order: ZERO_DH |
| `identity_dh_key` of an initial header is changed                   | The signature does not verify, or the key is not the pinned one: BAD_INITIAL_HEADER or IDENTITY_KEY_MISMATCH |
| `identity_dh_signature` of an initial header is replaced            | By another signature of A over the same string: no effect (section 4.1, rule 5). By any other bytes: BAD_INITIAL_HEADER |

A message that matches a record belongs to a session that the responder made before
(section 20.4). Other rules hold for what the relay changes in the envelope of such a
message [test: tests/client/test_session.py::test_later_message_finds_its_session_with_and_without_the_initial_header]
[test: tests/client/test_hostile_relay.py::test_changed_prekey_ids_of_a_message_with_a_record_change_nothing]
[test: tests/client/test_hostile_relay.py::test_lying_relay_gives_no_text_and_leaves_the_store_unchanged]:

- Steps 1 and 2 of section 16.8 read `identity_dh_key` and its signature, and the
  record is found by `ephemeral_key`. The two prekey ids are not read: a change to them
  has no effect.
- A changed `ephemeral_key` does not match the record of its session, and the message
  fails: in steps 3 to 8 of section 16.8, at the latest in step 8 under another session
  associated data, or on the session of another record that the changed bytes match.
- A message whose initial header was taken off decrypts when the responder holds its
  session (section 20.2, I9). A later message of a session, in front of which the
  initial header of that session was put, decrypts as well (I4).
- How the fields of an envelope are encoded has no effect (section 19.4).

No change of this section gives a plaintext that the sender did not seal, another sender
or another message id: those are fixed by the associated data (section 18.2).

A session that does not start exists at the initiator only. Its messages fail at the
responder, each shown as a message that could not be read (section 20.3), until one of the
two users resets the session.

### 16.10 What each side deletes

| Value                            | Initiator                                              | Responder                                                   |
|----------------------------------|--------------------------------------------------------|-------------------------------------------------------------|
| Private key of EK_A              | Step 7, before the session is stored                   | Never holds it                                              |
| DH1 to DH4, the input of the KDF | Step 7                                                 | After step 6                                                |
| SK                               | Step 8: it lives on only as the input of the first root key derivation | Step 8: it is the first root key and is replaced by the first DH ratchet step, inside the same decryption |
| Private key of OPK_B             | Never holds it                                         | Step 9, in the transaction that accepts the initial message. Not deleted when a step fails |
| Private key of SPK_B             | Never holds it                                         | At the end of its grace period (section 21.2)                |
| The initial header               | With the first message decrypted on the session (section 16.7) | Not stored: the record of section 20.4 keeps IKsig_A and EK_A |

A deletion from memory is as good as the platform allows; the threat model says what
Python does not allow. A deletion from the client store follows section 22.3.

## 17. The Double Ratchet

### 17.1 What it is

The messages of a session are encrypted with the Double Ratchet of sections 2 and 3 of
Revision 4 of that specification: the algorithm without header encryption and without the
post-quantum parts. Section 25.2 lists every difference from that text with its reason.

An implementation is a state machine without input or output of its own: it takes the
state, the bytes of a message and every random value as arguments and returns the new
state
[test: tests/crypto/test_ratchet.py::test_same_arguments_give_the_same_bytes]
[test: tests/crypto/test_ratchet_vectors.py::test_positive_vectors_replay_byte_for_byte].
The same code can so be driven by a test, by a vector and by the client.

### 17.2 The state

| Variable  | Type                        | Length  | Meaning                                                                 |
|-----------|-----------------------------|---------|-------------------------------------------------------------------------|
| DHs       | X25519 key pair             | 32 + 32 | The client's own ratchet key pair: private key and public key           |
| DHr       | X25519 public key, or empty | 32      | The ratchet public key of the peer, the bytes as they were received     |
| RK        | bytes                       | 32      | The root key                                                            |
| CKs       | bytes, or empty             | 32      | The sending chain key                                                   |
| CKr       | bytes, or empty             | 32      | The receiving chain key                                                 |
| Ns        | u32                         |         | The number of the next message of the sending chain                     |
| Nr        | u32                         |         | The number of the next message expected on the receiving chain          |
| PN        | u32                         |         | The number of messages sent on the sending chain before the current one |
| DHSTEPS   | u64                         |         | The number of DH ratchet steps this state has taken (section 17.7, step 5) |
| MKSKIPPED | list of entries, in the order in which they were added | 0 to 2000 entries | The skipped message keys (section 17.8). An entry is a ratchet public key (32), a message number (u32), a message key (32) and a step (u64) |

- "Empty" is a value of its own, not 32 zero bytes.
- The state is no byte layout of this protocol. Its integers are numbers in memory with
  the stated range and have no byte order; how a client writes the state into its store
  is its own matter. Two of them reach the wire, PN and Ns, as big-endian fields of the
  header (section 17.5).
- Besides the ratchet state a session holds the session associated data (section 16.5)
  and, at the initiator, the initial header (section 16.7).

### 17.3 Initialisation

The initiator, from SK and SPK_B of the key agreement and from 32 random bytes
(section 16.6, step 8)
[test: tests/crypto/test_ratchet_recompute.py::test_every_recorded_value_recomputes_without_the_core]:

```
DHs       = a new X25519 key pair from the 32 random bytes
DHr       = SPK_B, the 32 bytes of the Bundle
RK, CKs   = KDF_RK(SK, DH(private key of DHs, DHr))
CKr       = empty
Ns, Nr, PN, DHSTEPS = 0
MKSKIPPED = no entry
```

The responder, from SK and the key pair of SPK_B (section 16.8, step 8)
[test: tests/crypto/test_ratchet_recompute.py::test_every_recorded_value_recomputes_without_the_core]:

```
DHs       = the key pair of SPK_B
DHr       = empty
RK        = SK
CKs, CKr  = empty
Ns, Nr, PN, DHSTEPS = 0
MKSKIPPED = no entry
```

The signed prekey pair of the responder is its first ratchet key pair, and SK is its first
root key. The responder cannot encrypt in this state. It never has to: the state is stored
only after it decrypted the first message of the initiator, and that decryption takes a DH
ratchet step, which gives the responder a ratchet key pair of its own and a sending chain
(section 17.7, step 5). A stored session of a responder holds neither SK nor the private
key of the signed prekey
[test: tests/client/test_session.py::test_stored_responder_session_holds_neither_the_secret_nor_the_signed_prekey].

### 17.4 The two key derivations

KDF_RK(rk, dh) is one call of HKDF (RFC 5869). It returns a root key and a chain key
[test: tests/crypto/test_ratchet_recompute.py::test_every_recorded_value_recomputes_without_the_core]:

| Parameter          | Value                                                                    |
|--------------------|--------------------------------------------------------------------------|
| Hash               | SHA-256                                                                  |
| Salt               | rk, the 32 bytes of the root key                                         |
| Input key material | dh, the 32 bytes of one Diffie-Hellman output (section 16.3)             |
| Info               | ASCII `sotto/1 ratchet`, 15 bytes, hex `736f74746f2f312072617463686574`  |
| Output length      | 64 bytes                                                                 |
| Split              | Bytes 0 to 31 are the new root key. Bytes 32 to 63 are the chain key     |

KDF_CK(ck) is two calls of HMAC (RFC 2104) with SHA-256 under the same key. It returns a
message key and the next chain key
[test: tests/crypto/test_ratchet_recompute.py::test_every_recorded_value_recomputes_without_the_core]:

| Output         | Key              | Data             | Length                                  |
|----------------|------------------|------------------|-----------------------------------------|
| Message key    | ck, 32 bytes     | The one byte `01` | 32 bytes, the whole HMAC value         |
| Next chain key | ck, 32 bytes     | The one byte `02` | 32 bytes, the whole HMAC value         |

KDF_CK has no salt, no info and no split. The calls are the `hmac` module of the Python
standard library and `HMAC<SHA256>` in CryptoKit.

This protocol calls HKDF in two places, sections 16.4 and 17.4, and their info strings
differ: `sotto/1 x3dh` and `sotto/1 ratchet`
[test: tests/crypto/test_ratchet_recompute.py::test_document_and_vectors_agree_on_the_layouts].

### 17.5 The message header

The header of a message is 40 bytes
[test: tests/crypto/test_ratchet_recompute.py::test_document_and_vectors_agree_on_the_layouts]
[test: tests/crypto/test_ratchet_recompute.py::test_every_recorded_value_recomputes_without_the_core]:

| Offset | Length | Field | Value                                                                  |
|--------|--------|-------|------------------------------------------------------------------------|
| 0      | 32     | DH    | The ratchet public key of the sender, the public key of its DHs        |
| 32     | 4      | PN    | u32, big-endian: the PN of the sender                                  |
| 36     | 4      | N     | u32, big-endian: the number of this message on its sending chain       |

Total length: 40 bytes.

The header is fixed bytes and not a protobuf message, because it is part of the associated
data and protobuf serialization is not canonical. A receiver authenticates and compares the
40 bytes exactly as it received them (section 18.2). In the steps below `H.DH`, `H.PN` and
`H.N` are the fields of a received header H.

### 17.6 Encryption

Inputs: the state; the padded plaintext P (section 19.6); A, the 177 bytes of the session
associated data followed by the message id (section 18.2); a nonce of 12 random bytes. The
steps, in this order
[test: tests/crypto/test_ratchet_recompute.py::test_every_recorded_value_recomputes_without_the_core]
[test: tests/crypto/test_ratchet_vectors.py::test_positive_vectors_replay_byte_for_byte]
[test: tests/crypto/test_ratchet.py::test_responder_has_no_sending_chain_before_its_first_decryption]:

1. When CKs is empty, the result is NO_SENDING_CHAIN; no stored session is in that state
   (section 17.3). When Ns is 2^32 - 1, the result is CHAIN_EXHAUSTED (section 17.9).
2. mk is the message key of KDF_CK(CKs), and CKs becomes its next chain key.
3. H is the public key of DHs, then PN, then Ns, in the layout of section 17.5.
4. Ns becomes Ns + 1.
5. W is P sealed under mk with the nonce and the associated data A || H (section 18).
6. mk is deleted.

The result is H, W and the new state. The client commits the new state together with the
message before any byte leaves (section 22.2).

### 17.7 Decryption

Inputs: the state; H, the 40 bytes of the `header` field as received; W, the bytes of the
`ciphertext` field as received; A, the 177 bytes of the session associated data followed
by the `message_id` of the Deliver; 32 random bytes, which become the private key of
sub-step 4 of step 5 when the decryption takes a DH ratchet step and are not used
otherwise. Every step works on a copy of the state. The steps, in this order
[test: tests/crypto/test_ratchet_recompute.py::test_every_recorded_value_recomputes_without_the_core]
[test: tests/crypto/test_ratchet_vectors.py::test_negative_vectors_raise_their_named_error]
[test: tests/crypto/test_ratchet.py::test_random_conversations_keep_the_invariants]
[test: tests/crypto/test_ratchet.py::test_a_ratchet_key_of_small_order_is_refused]:

1. When `H.N` is 2^32 - 1, the result is CHAIN_EXHAUSTED (section 17.9).
2. When MKSKIPPED has an entry for the pair (`H.DH`, `H.N`): mk is its message key, the
   entry is removed, and the steps go on at step 8.
3. When `H.DH` equals DHr, 32 bytes compared with 32 bytes, the message belongs to the
   current receiving chain:
   - when CKr is empty, the result is DECRYPT_FAILED;
   - when `H.N` is less than Nr, the result is DECRYPT_FAILED: the key of that number
     was used or purged;
   - when `H.N` is more than Nr + MAX_SKIP, the result is TOO_MANY_SKIPPED;
   - otherwise the steps go on at step 6.
4. Otherwise `H.DH` is a new ratchet key of the peer; an empty DHr equals no key. Before
   any key is derived:
   - when `H.PN` is more than Nr + MAX_SKIP, the result is TOO_MANY_SKIPPED;
   - when `H.N` is more than MAX_SKIP, the result is TOO_MANY_SKIPPED.
5. The DH ratchet step:
   1. When CKr is not empty: while Nr is less than `H.PN`, one key is skipped
      (section 17.8).
   2. PN becomes Ns. Ns and Nr become 0. DHr becomes `H.DH`.
   3. RK and CKr become the root key and the chain key of
      KDF_RK(RK, DH(private key of DHs, DHr)).
   4. DHs becomes a new X25519 key pair from the 32 random bytes of the inputs. The
      private key it replaces leaves the state of the session. In the first DH ratchet
      step of a responder that key is the private key of a signed prekey
      (section 17.3): the client keeps it in its store until section 21.2 deletes it.
      Every other replaced private key is deleted.
   5. RK and CKs become the root key and the chain key of
      KDF_RK(RK, DH(private key of DHs, DHr)).
   6. DHSTEPS becomes DHSTEPS + 1, and the entries that are too old are purged
      (section 17.8).

   A Diffie-Hellman output of 32 zero bytes in sub-step 3 or 5 gives the result
   ZERO_DH.
6. While Nr is less than `H.N`, one key is skipped (section 17.8).
7. mk is the message key of KDF_CK(CKr), CKr becomes its next chain key, and Nr becomes
   Nr + 1.
8. W is opened under mk with the associated data A || H (section 18). When it does not
   verify, the result is DECRYPT_FAILED.
9. mk is deleted. The copy is the new state. The result is the plaintext P and the number
   of entries that the cap and the purge of section 17.8 removed from MKSKIPPED in steps
   5 and 6. An entry that is replaced by a new one (section 17.8) is not counted.

Every result but that of step 9 discards the copy: the state is byte for byte what it was
before, and so are the skipped keys
[test: tests/crypto/test_ratchet.py::test_failed_decryption_leaves_the_state_as_it_was]
[test: tests/crypto/test_ratchet.py::test_random_conversations_keep_the_invariants].
A forged header can therefore not
move a chain, replace a ratchet key or remove a stored key. The client keeps the new state
only by the transaction of section 22.2.

Steps 3 and 4 make every check of a count before step 5, 6 or 7 derives a key: a header
that asks for more than MAX_SKIP keys costs the receiver no key derivation
[test: tests/crypto/test_ratchet.py::test_too_many_skipped_keys_are_refused_before_any_key_is_derived].

### 17.8 Skipped message keys

A message can arrive after a later message of its chain. The key of every message that was
passed over is kept until the message arrives or the key is purged.

To skip one key of the receiving chain:

```
mk'  = the message key of KDF_CK(CKr)
add the entry (DHr, Nr, mk', DHSTEPS) at the end of MKSKIPPED
CKr  = the next chain key of KDF_CK(CKr)
Nr   = Nr + 1
```

An entry that MKSKIPPED already has for the same ratchet public key and the same number
is removed before the new one is added
[test: tests/crypto/test_ratchet.py::test_an_entry_for_the_same_key_and_number_is_replaced_and_not_counted].

The rules
[test: tests/crypto/test_ratchet.py::test_a_header_may_skip_exactly_max_skip_keys]
[test: tests/crypto/test_ratchet.py::test_the_cap_removes_the_oldest_entry_and_counts_it]
[test: tests/crypto/test_ratchet.py::test_entries_are_purged_with_the_fifth_dh_ratchet_step]
[test: tests/crypto/test_ratchet.py::test_too_many_skipped_keys_are_refused_before_any_key_is_derived]
[test: tests/crypto/test_ratchet_recompute.py::test_every_recorded_value_recomputes_without_the_core]:

- MAX_SKIP is 1000. One decryption skips at most 1000 keys of the chain that ends and at
  most 1000 keys of the chain of its message (section 17.7, steps 3 and 4).
- SKIPPED_KEYS_CAP is 2000. A state holds at most 2000 entries. When an entry is added to
  a list of 2000, the entry that was added first is removed.
- SKIPPED_KEY_STEPS is 5. Step 5 of a decryption removes, after it raised DHSTEPS, every
  entry whose step plus 5 is DHSTEPS or less. The keys of a receiving chain are so kept
  while that chain and the four that follow it are the current one, and are purged with
  the fifth DH ratchet step after the chain began.
- An entry is removed when a message uses its key (section 17.7, step 2).
- Every entry that the cap or the purge removes stands for a message that the peer sent
  and that did not arrive in time. A decryption returns their number, and the client
  reports it (section 20.3).
- When more than MAX_SKIP messages of one chain in a row never arrive, every later
  message of that sender fails in this session with TOO_MANY_SKIPPED: on the same chain
  the number only grows, and the first header of a later chain carries the gap in its
  PN. The other direction keeps working. Only a reset repairs the session
  (section 20.6).

All of this happens on the copy of the state: a message that does not decrypt adds no
entry and removes none.

### 17.9 The end of a chain

A chain holds the message numbers 0 to 2^32 - 2. The number 2^32 - 1 is never sent, so
that Ns, Nr and PN, which count the messages of a chain, fit a u32
[test: tests/crypto/test_ratchet.py::test_a_chain_ends_at_the_number_before_the_last].

- A client whose Ns is 2^32 - 1 cannot encrypt on that sending chain: the result is
  CHAIN_EXHAUSTED. The next DH ratchet step, taken when a message of the peer with a new
  ratchet key decrypts, begins a new sending chain. Until then the user can reset the
  session (section 20.2).
- A received header with N = 2^32 - 1 gets the result CHAIN_EXHAUSTED before any key is
  derived.

## 18. Message encryption

### 18.1 The cipher

A message is sealed with ChaCha20-Poly1305, the AEAD of RFC 8439 section 2.8
[test: tests/crypto/test_ratchet_recompute.py::test_every_recorded_value_recomputes_without_the_core]:

| Input           | Value                                                                        |
|-----------------|------------------------------------------------------------------------------|
| Key             | The message key mk of the ratchet, 32 bytes. One key seals one message       |
| Nonce           | 12 random bytes, made for this encryption and sent with the message          |
| Associated data | The 217 bytes of section 18.2                                                |
| Plaintext       | The padded plaintext P of section 19.6, L bytes                              |
| Output          | L bytes of ciphertext and a tag of 16 bytes                                  |

The calls are `ChaCha20Poly1305(mk).encrypt(nonce, P, associated_data)` in the Python
package cryptography, which returns the ciphertext followed by the tag, and
`ChaChaPoly.seal(_:using:nonce:authenticating:)` in CryptoKit.

The nonce is random although a message key seals one message. A key that is used a second
time, for example after a state was restored from a copy, would with a fixed nonce give
away the XOR of two plaintexts. A test vector takes the nonce as an input (section 15.2).

### 18.2 The associated data

| Offset | Length | Field                       | Value                                                    |
|--------|--------|-----------------------------|----------------------------------------------------------|
| 0      | 161    | Session associated data     | Section 16.5                                             |
| 161    | 16     | Message id                  | The `message_id` of the Send and of the Deliver          |
| 177    | 40     | Header                      | Section 17.5: the bytes of the `header` field            |

Total length: 217 bytes
[test: tests/crypto/test_ratchet_recompute.py::test_document_and_vectors_agree_on_the_layouts]
[test: tests/crypto/test_ratchet_vectors.py::test_associated_data_is_the_session_data_the_message_id_and_the_header].

- The sender takes the message id that it puts into the Send. The receiver takes the
  `message_id` of the Deliver and the `header` field exactly as it received them. It
  never builds the header again from numbers
  [test: tests/crypto/test_ratchet.py::test_random_conversations_keep_the_invariants]
  [test: tests/client/test_session.py::test_two_clients_exchange_texts_in_both_directions].
- The three parts have fixed lengths, so the 217 bytes split in one way only and no
  length is written in front of a part.
- The message id is the key by which a receiver discards copies (section 20.4). In the
  associated data it is authentic: a message whose id was changed on the way does not
  decrypt
  [test: tests/client/test_hostile_relay.py::test_lying_relay_gives_no_text_and_leaves_the_store_unchanged].
- The caller of the ratchet passes the first 177 bytes with every call, and the ratchet
  adds the header
  [test: tests/crypto/test_ratchet_vectors.py::test_associated_data_is_the_session_data_the_message_id_and_the_header]
  [test: tests/crypto/test_ratchet.py::test_arguments_of_another_length_are_refused].

### 18.3 The wire layout

The `ciphertext` field of the envelope (section 19.2) holds, for a padded plaintext of L
bytes
[test: tests/crypto/test_ratchet_recompute.py::test_document_and_vectors_agree_on_the_layouts]
[test: tests/crypto/test_ratchet_recompute.py::test_every_recorded_value_recomputes_without_the_core]:

| Offset | Length | Field      | Value                                              |
|--------|--------|------------|----------------------------------------------------|
| 0      | 12     | Nonce      | The nonce of section 18.1                          |
| 12     | L      | Ciphertext | The output of the cipher                           |
| 12 + L | 16     | Tag        | The tag of the cipher                              |

Total length: L + 28 bytes.

This is the `combined` form of a CryptoKit `ChaChaPoly.SealedBox`. In the Python package
cryptography it is the nonce followed by what `encrypt` returns. To open, a receiver takes
the first 12 bytes as the nonce and passes the rest to the library with the associated
data of section 18.2.

## 19. The peer envelope and the plaintext

### 19.1 The schema

The payload of a Send and of a Deliver (sections 7.12 and 7.14) is one serialized
`PeerMessage`. The plaintext of a message is a `Content`. Both are protobuf messages,
proto3 syntax, in the schema file of the relay protocol, `proto/sotto.proto`, package
`sotto`: one file holds every message of this protocol, and the macOS client takes one
file. They enter the file with the pull request that implements the session
[test: tests/test_docs.py::test_schema_file_is_a_part_of_the_listing_in_the_spec].

```proto
// The payload of a Send and of a Deliver: one PeerMessage.
message PeerMessage {
  uint32 version = 1;
  InitialHeader initial_header = 2;
  bytes header = 3;
  bytes ciphertext = 4;
}

message InitialHeader {
  bytes identity_dh_key = 1;
  bytes identity_dh_signature = 2;
  bytes ephemeral_key = 3;
  uint32 signed_prekey_id = 4;
  optional uint32 one_time_prekey_id = 5;
}

// The plaintext of a message before padding.
message Content {
  oneof body {
    string text = 1;
    Attachment attachment = 2;
    Profile profile = 3;
  }
}

// A file that travels as a blob of the relay (section 32).
message Attachment {
  bytes blob_id = 1;
  bytes key = 2;
  uint32 size = 3;
  bytes digest = 4;
  string media_type = 5;
  string file_name = 6;
  uint32 width = 7;
  uint32 height = 8;
  bytes thumbnail = 9;
  string caption = 10;
}

// The name and the avatar that a client shows to its contacts (section 35).
message Profile {
  string name = 1;
  Attachment avatar = 2;
}
```

The field numbers are frozen by the rule of section 7.2 and were chosen by its rules:
every message counts from 1 without a gap and every tag is one byte. In addition:

- `version` is field 1 of `PeerMessage` in every version of the end-to-end protocol, so
  that a client of any version can read it (section 19.4).
- The first two fields of `InitialHeader` have the names, numbers and types of the first
  two fields of `UploadBundle`.
- `one_time_prekey_id` is the one field of this protocol with the proto3 label
  `optional`: 0 is a valid prekey id, so the field needs a presence of its own.
- `Content` is a oneof with three members: `text`, `attachment` of part 3 (section 32)
  and `profile` of part 4 (section 35). A kind of message that is added later is a new member of the oneof with
  the next number, and travels as a message of the ratchet like a text.

The relay parses none of this (section 7.12).

### 19.2 PeerMessage

| Field            | No. | Type          | Length or value                                                  |
|------------------|-----|---------------|------------------------------------------------------------------|
| `version`        | 1   | uint32        | 1, the end-to-end protocol version (section 14.2)                |
| `initial_header` | 2   | InitialHeader | Present while the session of the sender holds one (section 16.7) |
| `header`         | 3   | bytes         | 40, the message header of section 17.5                           |
| `ciphertext`     | 4   | bytes         | L + 28, the layout of section 18.3; L is a multiple of 256 and at least 256 |

### 19.3 InitialHeader

| Field                   | No. | Type            | Length or value                                         |
|-------------------------|-----|-----------------|---------------------------------------------------------|
| `identity_dh_key`       | 1   | bytes           | 32                                                      |
| `identity_dh_signature` | 2   | bytes           | 64, over the string of section 4.3                      |
| `ephemeral_key`         | 3   | bytes           | 32                                                      |
| `signed_prekey_id`      | 4   | uint32          | 0 to 2^32 - 1                                           |
| `one_time_prekey_id`    | 5   | optional uint32 | Present or absent; 0 to 2^32 - 1 when present           |

Section 16.7 gives the value of each field.

### 19.4 Parsing and malformed envelopes

A client has one parse step that turns the `payload` of a Deliver into an envelope or
into a result, in this order
[test: tests/client/test_envelope.py::test_payload_that_is_no_peer_message_is_bad_envelope]
[test: tests/client/test_envelope.py::test_other_version_is_read_before_any_other_rule]
[test: tests/client/test_envelope.py::test_field_that_breaks_its_length_is_bad_envelope]:

1. A payload that does not parse as a `PeerMessage` gets the result BAD_ENVELOPE.
2. `version` is read before any other rule is applied. When it is not 1, 0 included, the
   result is UNSUPPORTED_VERSION, whatever the other fields hold.
3. With `version` 1, the result is BAD_ENVELOPE when one of these holds:
   - `header` is not 40 bytes;
   - `ciphertext` is shorter than 284 bytes, or its length less 28 is not a multiple of
     256;
   - `initial_header` is present and its `identity_dh_key` is not 32 bytes, its
     `identity_dh_signature` is not 64 bytes or its `ephemeral_key` is not 32 bytes.

A field that the schema of the client does not have is ignored. As in section 7.3, a
payload that parses is not valid by that alone, and nothing depends on how the peer
serialized the message: the client reads `header` and `ciphertext` as the bytes of their
fields, and no serialized message is signed, hashed or compared.

A client that reads a `version` it does not implement decrypts nothing and changes
nothing: it reports that the contact uses a version of the end-to-end protocol that this
client does not implement, and acks the message (section 20.2). The `version` field is
not authenticated at this point; the first byte of the session associated data binds
every message that decrypts to version 1 (section 16.5).

### 19.5 Content

| Field  | No. | Type   | Length or value                                               |
|--------|-----|--------|---------------------------------------------------------------|
| `text` | 1   | string | UTF-8, 0 to MAX_TEXT_BYTES bytes when sent (section 19.7)     |
| `attachment` | 2 | Attachment | A file of part 3, with the checks of section 32.2   |
| `profile` | 3 | Profile | The profile of part 4, with the checks of section 35.3      |

After a message decrypted and its padding was removed (section 19.6), the client parses
the bytes as a `Content`
[test: tests/client/test_envelope.py::test_content_that_does_not_parse_or_is_not_utf8_is_bad_content]
[test: tests/client/test_envelope.py::test_content_without_a_known_member_is_unknown_content]:

- Bytes that do not parse, a `text` that is not UTF-8 included, give the result
  BAD_CONTENT.
- A `Content` in which no member that the client knows is set gives the result
  UNKNOWN_CONTENT. A client that does not implement part 3 knows one member, `text`; one
  that does knows `attachment` as well, and one that implements part 4 knows `profile`.
- The text is whatever the peer chose to send. The command-line client of this
  repository prints it with the C0, C1 and bidirectional control characters escaped
  [test: tests/client/test_cli.py::test_peer_text_is_printed_with_control_characters_escaped].

A message with the result BAD_CONTENT or UNKNOWN_CONTENT is a real message of the peer:
it decrypted. The client keeps the new ratchet state and the seen id and acks the
message, and it has no text to show (section 20.3)
[test: tests/client/test_session.py::test_message_without_a_text_saves_its_state_and_seen_id_and_logs_nothing].

### 19.6 Padding

The plaintext that is sealed is the serialized `Content`, then one byte `80`, then bytes
`00` up to the next multiple of PADDING_BLOCK, 256 bytes
[test: tests/client/test_envelope.py::test_padding_adds_the_mark_and_zero_bytes_up_to_the_next_block]
[test: tests/client/test_envelope.py::test_receiver_takes_the_content_in_front_of_the_mark_behind_any_zero_bytes]
[test: tests/client/test_envelope.py::test_plaintext_without_padding_is_bad_padding]:

```
P = Content || 80 || 00 ... 00
```

- For a `Content` of C bytes, P has 256 * (floor(C / 256) + 1) bytes. At least the byte
  `80` is always added: a `Content` of 255 bytes gives 256 bytes, one of 256 bytes gives
  512.
- A sender adds no more padding than that.
- To remove the padding, a receiver finds the last byte of P that is not `00`. It has to
  be `80`, and the `Content` is the bytes in front of it. A receiver accepts any number
  of `00` bytes behind the `80`.
- When P has no byte other than `00`, or its last byte other than `00` is not `80`, the
  plaintext has no padding. The result is BAD_PADDING, and the message is handled like
  one with BAD_CONTENT (section 19.5).

The padding is inside the sealed bytes. The relay sees the length of a message in steps
of 256 bytes.

### 19.7 The largest text

MAX_TEXT_BYTES is 65019: a text of more bytes in UTF-8 is not sent, and the client
refuses it with the result TEXT_TOO_LONG. The client checks the length before any other
step of L1 (section 20.2): a text that is refused fetches no bundle and starts no key
agreement
[test: tests/client/test_session.py::test_text_too_long_is_refused_before_any_bundle_or_key_agreement]
[test: tests/client/test_envelope.py::test_largest_text_fills_254_blocks_and_one_byte_more_is_refused].

The number follows from the payload limit of section 7.12, 65472 bytes, for the longest
envelope:

| Part                                                                       | Bytes  |
|----------------------------------------------------------------------------|--------|
| `Content`: tag 1, length 3, text 65019                                     | 65023  |
| P: the `Content` and one byte `80`, 254 blocks of 256                      | 65024  |
| `ciphertext`: P, nonce 12, tag 16                                          | 65052  |
| `ciphertext` as a field: tag 1, length 3                                   | 65056  |
| `header` as a field: tag 1, length 1, 40                                   | 42     |
| `version` as a field: tag 1, value 1                                       | 2      |
| `initial_header` as a field: tag 1, length 2, and at most 146 (keys 34 and 34, signature 66, two ids of at most 6 each) | 149 |
| The payload                                                                | 65249  |

One more block of 256 bytes makes 65505 and does not fit. The limit is one number for
every message, with or without an initial header, so that a text that was accepted for
sending fits whatever the state of the session. A receiver applies no limit of its own to
a text: the largest frame bounds it
[test: tests/client/test_session.py::test_largest_text_fits_a_payload_with_an_initial_header]
[test: tests/client/test_session.py::test_receiver_applies_no_limit_to_a_text].

## 20. Session rules

### 20.1 What a client keeps

For every contact:

- its identity key and, once the client has seen it, its pinned X25519 identity key
  (section 5.3);
- a list of at most MAX_SESSIONS, 3, sessions, in an order. The first session of the list
  is the sending session: the client encrypts on it and on no other.

A session enters the list at its head, whether the client made it as initiator or as
responder. A session on which a message decrypts moves to the head. When the list has more
than 3 sessions, the last one is deleted: the oldest, that is, the session whose last move
to the head lies furthest back
[test: tests/client/test_sessions.py::test_fourth_session_drops_the_oldest_and_reports_its_missing_messages].

For all contacts together:

- the seen ids: the pairs (sender, message id) of the messages it accepted
  (section 20.4);
- the records of the initial messages it accepted (section 20.4).

### 20.2 The table

Three states of an identity at a client:

- N: the identity is not a contact.
- C0: the identity is a contact without a session.
- C1: the identity is a contact with 1 to 3 sessions.

The events I1 to I10 are the kinds of a Deliver, by its `sender`. They are tried in this
order, and a Deliver is the first kind whose condition holds. L1 to L3 are local events.
Every cell names an action of section 20.3; "none" means that the event cannot occur in
that state. The client does what the table says
[test: tests/client/test_session.py::test_stranger_is_acked_before_a_byte_is_parsed]
[test: tests/client/test_session.py::test_envelope_delivered_twice_gives_one_text_and_two_acks]
[test: tests/client/test_session.py::test_other_version_is_acked_and_changes_nothing]
[test: tests/client/test_session.py::test_initial_header_that_fails_step_1_or_2_changes_nothing]
[test: tests/client/test_session.py::test_replayed_initial_message_gives_no_second_text]
[test: tests/client/test_session.py::test_later_message_finds_its_session_with_and_without_the_initial_header]
[test: tests/client/test_session.py::test_message_without_initial_header_from_a_contact_without_session_is_no_session]
[test: tests/client/test_session.py::test_arbitrary_payload_ends_in_a_named_result_and_an_unchanged_store]
[test: tests/client/test_hostile_relay.py::test_lying_relay_gives_no_text_and_leaves_the_store_unchanged]
[test: tests/client/test_hostile_relay.py::test_arbitrary_bytes_from_any_sender_end_in_a_named_result]
[test: tests/client/test_sessions.py::test_fourth_session_drops_the_oldest_and_reports_its_missing_messages].

| Event                                                                                              | N        | C0                                             | C1                                             |
|----------------------------------------------------------------------------------------------------|----------|------------------------------------------------|------------------------------------------------|
| I1. The pair of its `sender` and `message_id` is a seen id                                         | STRANGER | DUPLICATE                                      | DUPLICATE                                      |
| I2. Its payload is no envelope of version 1 (section 19.4)                                         | STRANGER | FAIL: UNSUPPORTED_VERSION or BAD_ENVELOPE      | FAIL: UNSUPPORTED_VERSION or BAD_ENVELOPE      |
| I3. It carries an initial header that fails step 1 or 2 of section 16.8                            | STRANGER | FAIL: BAD_INITIAL_HEADER or IDENTITY_KEY_MISMATCH | FAIL: BAD_INITIAL_HEADER or IDENTITY_KEY_MISMATCH |
| I4. It carries an initial header with a record whose session is in the list, and that session decrypts it | STRANGER | none                                    | ACCEPT                                         |
| I5. It carries an initial header with a record whose session is in the list, and that session does not decrypt it | STRANGER | none                            | FAIL: DECRYPT_FAILED                           |
| I6. It carries an initial header with a record whose session is gone                               | STRANGER | FAIL: REPLAYED_INITIAL                         | FAIL: REPLAYED_INITIAL                         |
| I7. It carries an initial header without a record, and steps 3 to 8 of section 16.8 pass           | STRANGER | ACCEPT-NEW                                     | ACCEPT-NEW                                     |
| I8. It carries an initial header without a record, and one of steps 3 to 8 of section 16.8 fails   | STRANGER | FAIL: the result of that step                  | FAIL: the result of that step                  |
| I9. It carries no initial header, and a session of the list decrypts it                            | STRANGER | none                                           | ACCEPT                                         |
| I10. It carries no initial header, and no session of the list decrypts it                          | STRANGER | FAIL: NO_SESSION                               | FAIL: DECRYPT_FAILED                           |
| L1. The user sends a text to the identity                                                          | REFUSE   | START, then SEND                               | SEND                                           |
| L2. The user resets the session with the identity                                                  | REFUSE   | START                                          | START                                          |
| L3. Skipped keys were removed that no message used: by the cap or the purge of section 17.8, or with a session that left the list | none | none                              | GAP                                            |

How the conditions are decided
[test: tests/client/test_session.py::test_later_message_finds_its_session_with_and_without_the_initial_header]
[test: tests/client/test_session.py::test_two_clients_exchange_texts_in_both_directions]
[test: tests/client/test_sessions.py::test_both_sides_starting_at_once_send_and_receive_in_both_directions]
[test: tests/client/test_hostile_relay.py::test_reordered_messages_give_each_text_once]:

- I4 to I8: a record is found by the `sender` and the bytes of `ephemeral_key`
  (section 20.4).
- I4 and I5: the message is decrypted on the session of the record and on no other
  (section 17.7).
- I9 and I10: the sessions of the list are tried in the order of the list, each by a
  decryption of section 17.7 on a copy of its state. The first session that decrypts
  takes the message.
- At this level every result of a decryption that is no plaintext counts as
  DECRYPT_FAILED, whatever the ratchet returned for a single session.

### 20.3 The actions

| Action     | What the client does                                                                                                   | What it saves                                                          | Ack                   |
|------------|------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|-----------------------|
| STRANGER   | Drops the Deliver. It parses no byte of the payload, touches no key and shows nothing. The result is NOT_A_CONTACT     | Nothing                                                                | Yes                   |
| DUPLICATE  | Drops the Deliver before it parses the payload and shows nothing. The result is DUPLICATE                              | Nothing                                                                | Yes                   |
| FAIL       | Shows the user that a message of this contact could not be read, with the result that the table names. It fetches no bundle, makes no session and sends nothing to the peer | Nothing: no seen id, no change of a session, no prekey deleted, no pin | Yes                   |
| ACCEPT     | Removes the padding and reads the `Content` (sections 19.5 and 19.6). It shows the text                                 | In one transaction (section 22.2): the new state of the session that decrypted, which moves to the head of the list and drops its initial header; the seen id; the text | Yes, after the commit |
| ACCEPT-NEW | As ACCEPT, for the session that step 8 of section 16.8 made                                                            | As ACCEPT, and in the same transaction what step 9 of section 16.8 lists. The new session enters the list at its head; a fourth session is deleted | Yes, after the commit |
| SEND       | Encrypts the text on the sending session (section 17.6), with the initial header while the session holds one, and sends the Send | In one transaction (section 22.2), before the Send leaves: the new state of the session, the outbox row and the text | No Deliver to ack     |
| START      | Sends a FetchBundle for the contact and runs section 16.6 with the Bundle. A failure is reported with its result: NOT_FOUND, BAD_BUNDLE, IDENTITY_KEY_MISMATCH or ZERO_DH | On success, in one transaction, the new session at the head of the list and, when the contact had none, the pin (section 16.6, step 8); a fourth session is deleted. On failure nothing: no session and no pin | No Deliver to ack     |
| REFUSE     | Does nothing and reports NOT_A_CONTACT. A client sends to a contact only                                               | Nothing                                                                | No Deliver to ack     |
| GAP        | Tells the user how many messages of the contact are missing: the number of skipped keys that were removed without use  | Nothing more                                                           | No Deliver to ack     |

Rules that hold for every row
[test: tests/client/test_session.py::test_arbitrary_payload_ends_in_a_named_result_and_an_unchanged_store]
[test: tests/client/test_session.py::test_substituted_one_time_prekey_ends_in_a_decrypt_failure_and_keeps_the_prekey]
[test: tests/client/test_session.py::test_message_without_a_text_saves_its_state_and_seen_id_and_logs_nothing]
[test: tests/client/test_session.py::test_replayed_initial_message_gives_no_second_text]
[test: tests/client/test_hostile_relay.py::test_lying_relay_gives_no_text_and_leaves_the_store_unchanged]
[test: tests/client/test_hostile_relay.py::test_arbitrary_bytes_from_any_sender_end_in_a_named_result]:

- Every Deliver is acked, whatever its action. A message that could not be read is gone
  for good: the relay deletes it on the Ack, and this protocol has no frame that asks a
  peer to send a message again.
- A failure never starts a key agreement. A client that answered a message it cannot
  read with a new session would let whoever controls the relay force key agreements and
  use up one-time prekeys. Only L1 in state C0 and L2 start one.
- A START that fails is followed by no SEND: the text is not sent, and the user is told
  why.
- A failure changes nothing in the store. In particular, of the actions of this table
  only ACCEPT-NEW deletes the private key of a one-time prekey, so a forged initial
  message uses none up. Sections 21.3 and 21.4 name the two deletions that no message
  causes.
- An ACCEPT whose plaintext gives BAD_PADDING, BAD_CONTENT or UNKNOWN_CONTENT saves the
  state and the seen id without a text. The first two are shown as a message that could
  not be read. The third is shown as nothing: a later member of `Content` need not be a
  message of the chat, as `profile` of part 4 is not (section 36.6)
  [test: tests/client/test_cli.py::test_unknown_content_prints_nothing].
- A bundle without a one-time prekey starts a session all the same: START never fails
  for the lack of one (section 16.6). A client that refused such a bundle could be cut
  off from a contact by anyone who empties the handout bucket of that contact
  (section 9.3).

### 20.4 Seen ids and records

Seen ids
[test: tests/client/test_session.py::test_envelope_delivered_twice_gives_one_text_and_two_acks]
[test: tests/client/test_session.py::test_stranger_is_acked_before_a_byte_is_parsed]
[test: tests/client/test_session.py::test_replayed_initial_message_gives_no_second_text]:

- ACCEPT and ACCEPT-NEW save the pair (sender, message id) of the message. No other
  action saves one. The id of a message that did not decrypt is not authentic
  (section 18.2): a saved id of that kind would let whoever controls the relay block a
  real message by delivering a forged one under its id first.
- The seen ids are checked before the payload is parsed and before any key is touched.
  The ratchet alone cannot tell a copy from a forgery: for both its answer is
  DECRYPT_FAILED.
- A seen id is kept for SEEN_ID_SECONDS, 3196800 seconds: MESSAGE_TTL_SECONDS and one
  week, 37 days. The client deletes it at the first login after that time, and until it
  is deleted it counts as seen
  [test: tests/client/test_lifecycle.py::test_seen_id_counts_until_it_is_forgotten_after_its_time].
- A copy that arrives after the deletion is no duplicate for the table. The ratchet
  refuses it, because its message key is used: the copy is shown as a message that could
  not be read and is never read a second time.

Records of accepted initial messages
[test: tests/client/test_lifecycle.py::test_replayed_initial_message_gives_no_text_after_its_session_left_and_after_a_restart]
[test: tests/client/test_hostile_relay.py::test_lying_relay_gives_no_text_and_leaves_the_store_unchanged]:

- ACCEPT-NEW saves a record: the pair (IKsig_A, EK_A), each as the 32 bytes received,
  the session it made, and the id of the signed prekey that the key agreement used.
- A later message with the same `sender` and the same bytes in `ephemeral_key` belongs
  to that session and is decrypted there (I4, I5). After steps 1 and 2 of section 16.8
  the two prekey ids of its initial header are not read.
- A record is kept while its session is in the list. The initiator sends the initial
  header until it decrypts a message of the responder (section 16.7), which can be
  longer than any signed prekey lives: for all that time the record is what leads its
  messages to their session.
- A record outlives its session. A record whose session is gone is kept until the
  client deletes the private key of its signed prekey, and is deleted in the same
  transaction (section 21.2). A session that leaves the list takes its record with it
  when that private key is already deleted. A message that matches a record whose
  session is gone is refused with REPLAYED_INITIAL (I6).
- This closes the replay of an initial message. Without a one-time prekey nothing in the
  key agreement is fresh on the side of the responder, so the same initial message would
  be accepted again, as a new session with the same SK, for as long as the responder
  holds the private key of the signed prekey. The record refuses it during that time,
  and after it step 3 of section 16.8 does, with UNKNOWN_SIGNED_PREKEY.
- A replay with other bytes in `ephemeral_key` that give the same Diffie-Hellman
  outputs (section 16.5) finds no record and derives the same SK. It fails all the
  same, with DECRYPT_FAILED: the bytes of `ephemeral_key` are part of the session
  associated data.
- A record survives a restart of the client.

### 20.5 Several sessions and simultaneous initiation

Two clients can each start a session with the other before either received the initial
message of the other. Both key agreements are valid, and each client then holds two
sessions for the peer: the one it made as initiator and the one it made as responder.

The rule of section 20.1 settles which one is used, without a comparison of keys or
clocks: a client sends on the session on which it last decrypted a message. This is the
session rule of Sesame in its smallest form. Every message decrypts, because both
sessions stay in the list
[test: tests/client/test_sessions.py::test_both_sides_starting_at_once_send_and_receive_in_both_directions]. While messages of the two clients cross on
the way, the two can send on different sessions. By the rule of section 20.1, once one
client sends a message while none of the other is on the way, and the other receives it
before it sends one, both send on the session of that message.

The limit of 3 bounds the session states, with their skipped keys, that a peer can make
a client store. It does not bound the records and the seen ids: every accepted initial
message with a new ephemeral key adds a record, kept by the rules of section 20.4, and
every accepted message adds a seen id for SEEN_ID_SECONDS. A session that leaves the
list takes its skipped keys with it, and a message that arrives for it later fails (I6,
I8 or I10).

### 20.6 Reset, gaps and removal

- A reset (L2) is the way out of a session that does not decrypt on one side: the client
  makes a new session as initiator. The older sessions stay in the list behind it, so
  that messages on the way still decrypt. The next text goes out on the new session with
  its initial header. Only a user starts a reset
  [test: tests/client/test_sessions.py::test_reset_keeps_the_older_sessions_and_sends_on_the_new_one]
  [test: tests/client/test_hostile_relay.py::test_lying_relay_gives_no_text_and_leaves_the_store_unchanged].
- A gap (L3) is the one notice of a lost message. A skipped key stands for a message
  whose number the peer used and which did not arrive. When the cap or the purge of
  section 17.8 removes such a key, or a session that holds some is deleted from the
  list, the message can never be read, and the client reports the number
  [test: tests/client/test_sessions.py::test_purged_skipped_keys_are_reported_as_missing]
  [test: tests/client/test_sessions.py::test_fourth_session_drops_the_oldest_and_reports_its_missing_messages]. Messages that were lost at the end of a conversation, with no later
  message behind them, leave no skipped key and no notice.
- A client that removes a contact deletes the sessions of that contact. It keeps the
  seen ids and the records until their own rules delete them: an initial message that
  was accepted before the removal would otherwise be accepted again once the id is a
  contact again
  [test: tests/client/test_lifecycle.py::test_removed_contact_added_again_gets_no_replayed_initial_message].

## 21. The prekey lifecycle

### 21.1 The clock and the prekey ids

- A client reads the time from one clock, in whole seconds. An implementation takes the
  clock as an argument, so that a test can set it
  [test: tests/client/test_lifecycle.py::test_initial_message_under_a_replaced_signed_prekey_decrypts_only_in_the_grace_period].
- A client that does not run does nothing. The rules of this section take effect after
  a LoggedIn; the deletion of step 1 of section 21.2 also takes effect when the client
  starts.
- A client keeps two counters per identity in its store, one for signed prekeys and one
  for one-time prekeys. The first key of a kind gets the id 1, every later key the id of
  the key before it plus 1. The counter is saved in the transaction that saves the key.
  An id is so never used for two keys of one kind, after a crash and after the deletion
  of a key included
  [test: tests/client/test_lifecycle.py::test_prekey_ids_are_never_reused_and_stop_at_the_last_id].
- An identity whose counter reached 2^32 - 1 makes no further key of that kind
  [test: tests/client/test_lifecycle.py::test_prekey_ids_are_never_reused_and_stop_at_the_last_id].
- These are rules for the owner of the keys. A receiver accepts any id from 0 to
  2^32 - 1 (section 5.2).

### 21.2 The signed prekey

The newest signed prekey of a client is the one it made last. After every LoggedIn the
client does this, in this order
[test: tests/client/test_lifecycle.py::test_rotation_follows_the_age_of_the_newest_signed_prekey]
[test: tests/client/test_lifecycle.py::test_initial_message_under_a_replaced_signed_prekey_decrypts_only_in_the_grace_period]:

1. Deletion. For every signed prekey whose grace period is over, it deletes the private
   key and, in the same transaction, every record of section 20.4 that names its id and
   whose session is gone from the list.
2. Rotation. When it holds no signed prekey, or it made the newest one
   SIGNED_PREKEY_ROTATION_SECONDS, 604800 seconds or 7 days, ago or longer, it makes a
   new one: a key pair from 32 random bytes, the next id, and a signature over the
   string of section 4.4. It saves the key, with the time of the clock, before it
   uploads it.
3. Upload. When the relay has not confirmed the newest signed prekey with a
   BundleStored, the client sends an UploadBundle that carries it (section 21.4)
   [test: tests/client/test_transport.py::test_steps_after_the_login_upload_once_then_send_the_outbox].

Step 1 needs no connection. The client also runs it every time it starts, before it
dials the relay [test: tests/client/test_transport.py::test_expired_signed_prekey_is_deleted_at_start_before_any_dial]. A client that stays on one connection SHOULD run the
three steps again when the newest signed prekey reaches the age of step 2 or a grace
period ends.

The grace period
[test: tests/client/test_lifecycle.py::test_initial_message_under_a_replaced_signed_prekey_decrypts_only_in_the_grace_period]:

- A signed prekey is replaced at the moment the client saves a newer one (step 2). The
  moment does not wait for the upload of the newer one or for its BundleStored.
- Its grace period runs from that moment for SIGNED_PREKEY_GRACE_SECONDS, 3196800
  seconds: MESSAGE_TTL_SECONDS and one week, 37 days. The relay hands out the replaced
  key until it stores the newer one, and an initial message that was made with it can
  wait in the queue for the whole MESSAGE_TTL_SECONDS. The week is for the clocks, for a
  sender that was slow to send and for an upload that was late. When the upload is later
  than that week and the client does not run in between, an initial message made with
  the replaced key can arrive after the grace period and fails.
- During the grace period the responder finds the key by its id (section 16.8, step 3).
  After it the key counts as not held, whether or not step 1 has deleted it yet: an
  initial message that names the id and matches no record gets UNKNOWN_SIGNED_PREKEY.
- With the defaults the private key of a signed prekey exists for about 44 days: 7 until
  it is replaced and 37 after. The 7 days are stretched by the time to the next
  LoggedIn, the 37 days by the time to the next start or LoggedIn of the client. A relay
  that withholds a BundleStored stretches neither. A relay that keeps a client from
  logging in keeps the newest signed prekey of that client in use for as long (threat
  model, "What the relay can do").
- The deletion of the private key is what bounds the records whose session is gone, and
  what ends the time in which the first messages of a session without a one-time prekey
  can be opened with keys taken from the responder (threat model).

### 21.3 One-time prekeys

- A one-time prekey is a key pair from 32 random bytes with the next id. It is not
  signed.
- Refill. After every LoggedIn the client reads `one_time_prekey_count`, c. When c is
  less than ONE_TIME_PREKEY_REFILL_BELOW, 50, it makes ONE_TIME_PREKEY_CAP - c new
  one-time prekeys, 100 - c with the default, and uploads them in the UploadBundle of
  this login (section 21.4). The first upload of an identity so carries 100
  [test: tests/client/test_transport.py::test_steps_after_the_login_upload_once_then_send_the_outbox].
- The relay sends no notice when the number falls (section 9.4). A client MAY refill
  during a connection as well, from the last count the relay reported less the number
  of initial messages it accepted since then that named a one-time prekey.
- The private key of a one-time prekey is deleted when the initial message that names
  it is accepted (section 16.8, step 9), and not when a message that names it fails
  [test: tests/client/test_session.py::test_stored_responder_session_holds_neither_the_secret_nor_the_signed_prekey]
  [test: tests/client/test_session.py::test_substituted_one_time_prekey_ends_in_a_decrypt_failure_and_keeps_the_prekey].
- A client holds at most ONE_TIME_PREKEY_HELD_MAX, 1000, private keys of one-time
  prekeys. Before it makes a batch that would go over, it deletes the ones with the
  lowest ids until the batch fits
  [test: tests/client/test_lifecycle.py::test_held_one_time_prekeys_are_bounded_by_deleting_the_lowest_ids]. The count is the word of the
  relay, and fetches by anyone lower it (section 9.3): without this bound a client would
  make keys without end. An initial message that names a key deleted in this way gets
  UNKNOWN_ONE_TIME_PREKEY.

### 21.4 The upload

- An UploadBundle carries the X25519 identity key with its signature, the newest signed
  prekey with its id and its signature, and the new one-time prekeys, if any
  (section 7.8).
- After a LoggedIn a client sends at most one UploadBundle for the steps of sections
  21.2 and 21.3, before any Send of that login (section 23.3) [test: tests/client/test_transport.py::test_steps_after_the_login_upload_once_then_send_the_outbox]. A
  rotation or a refill during the connection (sections 21.2 and 21.3) is a further
  UploadBundle.
- A one-time prekey is uploaded once (section 9.1). The client saves the one-time
  prekeys of an UploadBundle in its store before the frame leaves and puts each of them
  into that frame only: a later UploadBundle carries new keys. The keys of an
  UploadBundle that got no answer are kept and go into no later frame
  [test: tests/client/test_lifecycle.py::test_unanswered_upload_keeps_its_keys_and_a_refused_one_deletes_them].
- An UploadBundle that the relay refused with an Error whose action is Back off is sent
  again unchanged on the same connection (section 11.1): the same frame, not a new one
  with the same keys in it.
- An UploadBundle that waits in Back off, or that has no answer, when the connection
  ends is not sent again, and after the next LoggedIn the steps of sections 21.2 and
  21.3 build the UploadBundle of that login [test: tests/client/test_transport.py::test_upload_open_when_the_connection_ends_is_not_sent_again]. The one-time prekeys of
  a frame that has no answer are kept: the relay can hold them. The relay holds none
  of a frame that waits in Back off, because it refused the frame each time it was sent
  (section 11.2): the client deletes the private keys of the one-time prekeys of that
  frame
  [test: tests/client/test_lifecycle.py::test_unanswered_upload_keeps_its_keys_and_a_refused_one_deletes_them].
  Kept, they would count toward the bound of section 21.3, and while the relay refuses every upload a client would in the end delete the keys
  that the relay still hands out.
- The X25519 identity key and its signature are the same in every upload
  (section 5.3).

## 22. The client store

### 22.1 What it holds

A client keeps, for one identity
[test: tests/client/test_client_store.py::test_store_holds_what_section_22_1_lists]:

- the seed of the identity and the private key of its X25519 identity key;
- the private keys of its signed prekeys and of its one-time prekeys with their ids, the
  two counters of section 21.1 and the times that section 21.2 needs
  [test: tests/client/test_lifecycle.py::test_rotation_follows_the_age_of_the_newest_signed_prekey]
  [test: tests/client/test_lifecycle.py::test_replayed_initial_message_gives_no_text_after_its_session_left_and_after_a_restart];
- its contacts with their pinned X25519 identity keys;
- the sessions of every contact, in their order (sections 17.2 and 20.1);
- the seen ids and the records of accepted initial messages (section 20.4);
- the outbox: for every message that it encrypted and that the relay has not confirmed,
  the message id, the recipient and the bytes of the payload;
- the message log: the texts it sent and received.

Section 33.7 adds what part 3 keeps, and section 36.1 what part 4 keeps.

No frame and no payload carries the seed or a private key [test: tests/client/test_transport.py::test_steps_after_the_login_upload_once_then_send_the_outbox].

### 22.2 The two ordering rules

On receive
[test: tests/client/test_session.py::test_crash_between_decryption_and_commit_changes_nothing_and_the_message_decrypts_again]
[test: tests/client/test_session.py::test_envelope_delivered_twice_gives_one_text_and_two_acks]
[test: tests/client/test_transport.py::test_connection_cut_between_deliver_and_ack_gives_one_text]:

- The client sends the Ack for a message that it accepted only after one transaction
  committed everything the message changes: the new ratchet state of its session, the
  text and the seen id, and for an initial message what step 9 of section 16.8 lists.
- An Ack tells the relay to delete the only other copy (section 10.5). A client that
  stops between the commit and the Ack gets the message again after its next login and
  drops it as a duplicate. A client that stops before the commit gets it again and
  decrypts it: its state did not change.
- The Ack for a Deliver that is dropped or that failed (section 20.3) waits for nothing:
  the client saved nothing.

On send
[test: tests/client/test_session.py::test_outbox_bytes_sent_again_after_a_crash_give_one_text]
[test: tests/client/test_transport.py::test_client_killed_between_commit_and_stored_delivers_one_text]:

- One transaction commits the new ratchet state, with the sending chain moved on, and
  the outbox row with the message id and the bytes of the payload. Only after the commit
  does a Send with these bytes leave.
- A message is encrypted once. A repeated Send (section 10.3) carries the bytes of the
  row: the same message id, recipient and payload. A client never encrypts the text of
  an outbox row again.
- The row is removed when the relay answers its Send with Stored, or with an Error whose
  action is Stop, which the client reports.
- A client that stops between the commit and the Stored sends the row again after its
  next login. Without the row it would either lose the message or encrypt it a second
  time under the same message id, with a message key that was used.

### 22.3 Deletion

A key or a state that this text calls deleted is, after the commit of the transaction
that deletes it, in none of the files of the store
[test: tests/client/test_lifecycle.py::test_replaced_chain_keys_are_in_no_file_of_the_store]
[test: tests/client/test_lifecycle.py::test_initial_message_under_a_replaced_signed_prekey_decrypts_only_in_the_grace_period]. What lies below the
files, the blocks that a filesystem keeps of an overwritten or removed file, is out of
scope, as it is for the relay (section 13.3).

### 22.4 The store of the client of this repository

The rules above hold for every client. How a client keeps its store is its own matter;
the macOS client is free to keep keys in the keychain. The client of this repository does
this
[test: tests/client/test_client_store.py::test_directory_gets_mode_0700_and_the_file_0600]
[test: tests/client/test_client_store.py::test_start_is_refused_when_a_mode_gives_a_right_to_the_group_or_others]
[test: tests/client/test_client_store.py::test_store_uses_the_rollback_journal_with_secure_delete]:

- The store is one SQLite file per identity in a data directory. The directory has mode
  0700 and the file mode 0600, and both are set before the first byte is written.
- The client refuses to start when the directory or the file gives any right to the
  group or to others, that is, when its mode has one of the bits 077.
- The database uses the rollback journal and not a write-ahead log, with `secure_delete`
  on and one connection: no second file keeps older ratchet states.
- The seed is never taken from a command line argument and never printed [test: tests/client/test_cli.py::test_seed_is_neither_an_argument_nor_printed].

Nothing in the store is encrypted. Whoever can read the file holds the identity and
everything else in section 22.1; the threat model says what follows from that.

## 23. The client transport

### 23.1 The URL

A client is given the URL of its relay; no URL of a relay that serves other hosts is
built into it. The command-line client of this repository has a default, the loopback URL
`ws://127.0.0.1:8765/ws` of a relay on the same machine, and the option `--relay` for any
other [test: tests/client/test_transport.py::test_url_rules_of_sections_8_2_and_23_1] [test: tests/client/test_cli.py::test_ws_url_off_loopback_is_refused_without_insecure].

- The scheme is `wss` or `ws`. The client dials the URL as given and takes the server
  name from its host (section 8.2).
- A `wss` URL is dialed with TLS, and the certificate of the server is verified against
  the host of the URL with the trust store of the platform.
- A `ws` URL has no TLS: the login and every frame are readable and changeable on the
  path. A client dials a `ws` URL only when its host is a loopback host, unless the user
  gave an explicit override for this start of the client. In the command-line client of
  this repository the override is the option `--insecure`.
- A loopback host is, as the server name of section 8.2: the name `localhost`; an IPv4
  address of four decimal numbers from 0 to 255, each written without a leading zero,
  whose first is 127; or an IPv6 address that is the loopback address of RFC 4291
  section 2.5.3, in any text form of that address. A short form of an IPv4 address, such
  as the `127.1` of section 8.2, is not one, and neither is `0127.0.0.1`.

### 23.2 The connection

- The client sets the receive limit of its WebSocket library to MAX_FRAME_BYTES
  (section 6.3) [test: tests/client/test_transport.py::test_broken_server_frame_closes_with_its_code_and_the_client_reconnects].
- The client connects to the host of the URL itself. It takes no proxy from its
  environment [test: tests/client/test_transport.py::test_proxy_of_the_environment_is_not_used]: a proxy that the user did not ask for would see the
  address of the relay and, on a `ws` URL, every frame.
- The client answers pings and requires no subprotocol (sections 6.2 and 6.4).

### 23.3 After the login

After a LoggedIn the client does this, in this order [test: tests/client/test_transport.py::test_steps_after_the_login_upload_once_then_send_the_outbox]:

1. The steps of sections 21.2 and 21.3, and the one UploadBundle they ask for. Until the
   relay holds the bundle of an identity, the identity is not registered and nobody can
   send to it (section 8.6), a peer that answers included.
2. Every row of the outbox, oldest first, as a Send (section 22.2).
3. The deletion of the seen ids whose time is over (section 20.4).

A Deliver can arrive from the LoggedIn on, between any two of these steps. The steps only
send frames; the frames of the relay that arrive meanwhile wait and are handled in their
order once the steps are done (section 20.2).

### 23.4 The reconnect schedule

This is the wait of the action Retry of section 11.1 [test: tests/client/test_transport.py::test_waits_follow_the_schedules] [test: tests/client/test_transport.py::test_relay_restarted_in_the_middle_of_a_conversation_loses_nothing].

- n counts the attempts to connect since the last LoggedIn: the first attempt after a
  connection ended has n = 1, and every attempt that ends without a LoggedIn raises n
  by 1. A LoggedIn sets it back.
- Before attempt n the client waits w + j seconds: w is 2^(n-1), at most
  RETRY_MAX_SECONDS, 60; j is chosen evenly between 0 and w / 2.

| n            | 1   | 2 | 3 | 4  | 5  | 6  | 7 and more |
|--------------|-----|---|---|----|----|----|------------|
| w            | 1   | 2 | 4 | 8  | 16 | 32 | 60         |
| Longest wait | 1.5 | 3 | 6 | 12 | 24 | 48 | 90         |

- The jitter j keeps clients that lost one relay at one moment from returning at one
  moment. It needs no generator of the operating system.
- A client that the user stops, or that was closed with a code whose action is Stop
  (section 11.3), does not reconnect.

### 23.5 The Back off schedule

This is the wait of the action Back off of section 11.1 [test: tests/client/test_transport.py::test_waits_follow_the_schedules] [test: tests/client/test_transport.py::test_rate_limited_send_is_sent_again_after_the_back_off].

- k counts, for one frame, the times in a row that the relay refused it on this
  connection with an Error whose action is Back off.
- Before it sends the frame again, unchanged, the client waits w + j seconds: w is
  FRAME_REFILL_SECONDS * 2^(k-1), at most RETRY_MAX_SECONDS; j is chosen evenly between
  0 and w / 2. With the defaults these are the numbers of section 23.4, and the wait is
  never shorter than FRAME_REFILL_SECONDS.
- While a frame waits after RATE_LIMITED or STORAGE_FULL, the client SHOULD hold back
  its other Send, UploadBundle and FetchBundle frames: the frame bucket and the page
  ceiling are shared by all of them. An Ack is never held back.
- A frame that waits when the connection ends is sent again after the next login
  (section 11.1), with k at 1. An UploadBundle is the exception (section 21.4).

## 24. Constants, local results and test vectors

### 24.1 The constants of part 2

| Name                           | Value   | Unit     | Meaning                                                                    |
|--------------------------------|---------|----------|----------------------------------------------------------------------------|
| MAX_SKIP                       | 1000    | keys     | The most message keys one decryption skips in one chain (section 17.8)     |
| SKIPPED_KEYS_CAP               | 2000    | keys     | The most skipped keys one session stores (section 17.8)                    |
| SKIPPED_KEY_STEPS              | 5       | steps    | The DH ratchet steps after which the skipped keys of a chain are purged (section 17.8) |
| PADDING_BLOCK                  | 256     | bytes    | The block to which a plaintext is padded (section 19.6)                    |
| MAX_TEXT_BYTES                 | 65019   | bytes    | The longest text a client sends, in UTF-8 (section 19.7)                   |
| MAX_SESSIONS                   | 3       | sessions | The most sessions a client keeps for one contact (section 20.1)            |
| SEEN_ID_SECONDS                | 3196800 | seconds  | The time a seen id is kept, 37 days (section 20.4)                         |
| SIGNED_PREKEY_ROTATION_SECONDS | 604800  | seconds  | The age at which a signed prekey is replaced, 7 days (section 21.2)        |
| SIGNED_PREKEY_GRACE_SECONDS    | 3196800 | seconds  | The time a replaced signed prekey keeps its private key, 37 days (section 21.2) |
| ONE_TIME_PREKEY_REFILL_BELOW   | 50      | keys     | The count below which a client uploads one-time prekeys (section 21.3)     |
| ONE_TIME_PREKEY_HELD_MAX       | 1000    | keys     | The most one-time prekey private keys a client holds (section 21.3)        |
| RETRY_MAX_SECONDS              | 60      | seconds  | The cap of w in the two schedules (sections 23.4 and 23.5)                 |

- MAX_SKIP, SKIPPED_KEYS_CAP, SKIPPED_KEY_STEPS, PADDING_BLOCK and MAX_TEXT_BYTES are
  constants of end-to-end protocol version 1. Two clients that differ in one of them
  disagree on which messages decrypt or fit. The vectors and the tests of the ratchet
  hold the first three
  [test: tests/crypto/test_ratchet.py::test_constants_are_those_of_section_24_1]
  [test: tests/crypto/test_ratchet_recompute.py::test_document_and_vectors_agree_on_the_layouts].
  No vector of section 24.3 covers the other
  two, because the padded plaintext is an input of a ratchet vector: the tests of the
  session hold the padding and the largest text
  [test: tests/client/test_envelope.py::test_padding_adds_the_mark_and_zero_bytes_up_to_the_next_block]
  [test: tests/client/test_envelope.py::test_largest_text_fills_254_blocks_and_one_byte_more_is_refused]
  [test: tests/client/test_session.py::test_largest_text_fits_a_payload_with_an_initial_header].
- The other values are the defaults of a client. SEEN_ID_SECONDS and
  SIGNED_PREKEY_GRACE_SECONDS are built on the default of MESSAGE_TTL_SECONDS
  (section 12.1).

### 24.2 Local results

The checks of part 2 run inside a client and end in no frame. Like those of section 11.4
their results have names, which a negative test vector states as its `error`
(section 15.2).

| Name                    | Where                    | Meaning                                                                          |
|-------------------------|--------------------------|----------------------------------------------------------------------------------|
| ZERO_DH                 | Section 16.3             | A Diffie-Hellman output is 32 zero bytes                                         |
| BAD_INITIAL_HEADER      | Section 16.8, step 1     | The signature over the X25519 identity key of an initial header does not verify under the sender |
| IDENTITY_KEY_MISMATCH   | Section 16.8, step 2     | The initial header carries another X25519 identity key than the pinned one       |
| UNKNOWN_SIGNED_PREKEY   | Section 16.8, step 3     | The client holds no signed prekey private key with the id of the initial header  |
| UNKNOWN_ONE_TIME_PREKEY | Section 16.8, step 4     | The client holds no one-time prekey private key with the id of the initial header |
| DECRYPT_FAILED          | Section 17.7             | The message does not verify under the key of its header, or that key was used or purged |
| TOO_MANY_SKIPPED        | Section 17.7             | The header asks for more than MAX_SKIP skipped keys in one chain                 |
| CHAIN_EXHAUSTED         | Sections 17.6 and 17.9   | The message number 2^32 - 1: a sending chain at its end, or a header that names it |
| NO_SENDING_CHAIN        | Section 17.6             | An encryption on a state without a sending chain: a responder before its first decryption |
| UNSUPPORTED_VERSION     | Section 19.4             | The `version` of an envelope is not 1                                            |
| BAD_ENVELOPE            | Section 19.4             | The payload is not a `PeerMessage`, or a field breaks its length                 |
| BAD_PADDING             | Section 19.6             | A plaintext that decrypted has no padding                                        |
| BAD_CONTENT             | Section 19.5             | A plaintext that decrypted does not parse as a `Content`                         |
| UNKNOWN_CONTENT         | Section 19.5             | A `Content` has no member that the client knows                                  |
| TEXT_TOO_LONG           | Section 19.7             | A text to send is longer than MAX_TEXT_BYTES                                     |
| NOT_A_CONTACT           | Section 20.3             | The sender of a Deliver, or the identity of a local event, is not a contact      |
| DUPLICATE               | Section 20.3             | The pair of sender and message id of a Deliver is a seen id                      |
| REPLAYED_INITIAL        | Section 20.3             | An initial message matches a record whose session is gone                        |
| NO_SESSION              | Section 20.3             | A message without an initial header came from a contact without a session        |

IDENTITY_KEY_MISMATCH is the name of section 11.4 with the same meaning: another X25519
identity key than the pinned one, in a bundle there and in an initial header here.
Section 33.6 names the local results of part 3, and section 36.7 those of part 4.

### 24.3 What the test vectors record

Section 15 holds the schema, and every rule of it applies: every private key, ephemeral
key, nonce and message id is an input, and replaying a vector draws no random byte. The
names of the operations and the keys of their objects enter section 15 with the files.

A vector of the key agreement records
[test: tests/crypto/test_x3dh_vectors.py::test_vectors_use_the_operations_and_keys_of_the_document]
[test: tests/crypto/test_x3dh_recompute.py::test_every_recorded_value_recomputes_without_the_core]:

| Object          | Values                                                                                   |
|-----------------|------------------------------------------------------------------------------------------|
| `inputs`        | The identity keys of both sides. The private keys of IKdh_A and EK_A for an initiator; of IKdh_B, of the signed prekey and of the one-time prekey for a responder. The public keys, ids and signatures of the Bundle or of the initial header, as bytes to verify |
| `intermediates` | The strings of sections 4.3 and 4.4 that were verified; DH1, DH2, DH3 and, when computed, DH4; the input key material of section 16.4 |
| `outputs`       | SK and the session associated data of section 16.5                                       |

Its negative case is a public key of small order, with the `error` ZERO_DH. Further
cases are vectors of a responder with `outputs`, which differ from those of the
initiator:

- a one-time prekey that was replaced on the way: another SK;
- the unknown key share of section 16.5: the same SK and another session associated
  data;
- an `ephemeral_key` with other bytes that give the same Diffie-Hellman outputs
  (section 16.5), once with the most significant bit of its last byte set and once with
  the u-coordinate replaced by its inverse modulo 2^255 - 19: the same SK and another
  session associated data.

A vector of the ratchet is one step of a scripted conversation and records
[test: tests/crypto/test_ratchet_vectors.py::test_vectors_use_the_operations_and_keys_of_the_document]
[test: tests/crypto/test_ratchet_recompute.py::test_every_recorded_value_recomputes_without_the_core]:

| Object          | Values                                                                                   |
|-----------------|------------------------------------------------------------------------------------------|
| `inputs`        | SK and the session associated data; the key pair of the signed prekey; the 32 random bytes of the ratchet private key of every initialisation of an initiator and of every decryption that reaches sub-step 4 of step 5 of section 17.7, a decryption that then fails included; for every message the message id, the nonce and the padded plaintext; the order in which the messages are delivered |
| `intermediates` | For every DH ratchet step the Diffie-Hellman outputs and the root key and chain key of each KDF_RK; for every message the chain key before it, its message key, the 40 bytes of its header and the 217 bytes of its associated data; every skipped key that was stored or purged |
| `outputs`       | For an encryption the bytes of the `ciphertext` field; for a decryption the plaintext    |

The conversation covers messages in order and out of order, lost messages, several DH
ratchet steps and the negative cases of section 17.7.

Appendix A writes out one such run in full, in hex.

## 25. Deviations and what is missing

### 25.1 From X3DH Revision 1

| X3DH Revision 1                                                          | This protocol                                                              | Reason                                                                     |
|--------------------------------------------------------------------------|----------------------------------------------------------------------------|----------------------------------------------------------------------------|
| Signatures are XEdDSA, made with the X25519 identity key                 | Signatures are Ed25519 (RFC 8032), made with an Ed25519 identity key       | Neither the Python package cryptography nor CryptoKit has XEdDSA, and this project builds no cryptography of its own |
| One identity key, X25519, serves for Diffie-Hellman and for signatures   | Two: the Ed25519 identity key, which is the user id, and an X25519 identity key that it signs once (section 4.3) | Follows from the first. No key is used for both a signature and a Diffie-Hellman computation |
| The signed message is Encode(SPK)                                        | The signed strings of sections 4.3 and 4.4: a prefix, a zero byte, the key of the signer and the signed key | The same identity key signs the login. The prefix keeps a signature of one kind from being one of another kind |
| Encode(PK) is recommended as a byte for the curve and the u-coordinate   | A public key is its 32 bytes, with no byte in front                        | One curve. The version byte of the session associated data and the prefixes carry the context |
| AD is Encode(IK_A) \|\| Encode(IK_B); more can be appended (X3DH section 3.3) | The version byte and five keys: both Ed25519 keys, both X25519 identity keys and the bytes of the ephemeral key (section 16.5) | The Diffie-Hellman values authenticate the X25519 keys only; without the Ed25519 keys an unknown key share is possible (X3DH section 4.8). X25519 gives one output for more than one 32-byte string, so the ephemeral key is bound as bytes: the record of section 20.4 is found by them |
| The initial message carries IK_A                                         | It carries the X25519 identity key with its signature. The Ed25519 key is the `sender` of the Deliver | One source for the identity of the sender, and the associated data binds it |
| An all-zero Diffie-Hellman output is not mentioned                       | It ends the key agreement (section 16.3)                                   | The two libraries differ, and RFC 7748 allows the check                    |
| A replayed initial message without a one-time prekey is accepted; mitigations are left open (X3DH section 4.2) | The responder keeps a record of every accepted initial message while its session or the private key of its signed prekey exists (section 20.4) | Without it the same SK would be accepted again                |
| The lifetime of a signed prekey and of its private key is left open (X3DH section 3.2) | Replaced after 7 days, private key kept for 37 more (section 21.2)         | A value has to be written down                                             |
| One-time prekey private keys are deleted as messages that use them arrive (X3DH sections 3.2 and 3.4) | A client also deletes the ones with the lowest ids before it would hold more than 1000 (section 21.3), and those of an upload that the relay refused and that is not sent again (section 21.4) | The count of the relay decides how many keys a client makes, and anyone lowers it by fetching: without a bound a client would make keys without end. The keys of a refused upload never reached the relay |
| The initiator verifies one signature, over the signed prekey             | The four checks of section 5.4: the id, the signature over the X25519 identity key, the pinned key, the signature over the signed prekey | Follows from the second key. The first check is what keeps the relay from handing out keys of its own |
| The server provides a one-time prekey if one exists (X3DH section 3.3)   | The relay withholds one while the handout bucket of the target is empty (section 9.3) | X3DH section 4.7 asks the server to hinder the draining of one-time prekeys. The bucket spreads the stored keys over time, at the price of sessions without a one-time prekey while it is empty |
| No rule about who sends an initial message                               | A responder accepts one from a contact only (section 20.2)                 | Identities are free: this bounds what strangers can make a client compute and store |

Kept as written: the four Diffie-Hellman values and their order; DH4 left out without a
one-time prekey; the key derivation with F, a zero salt and an info string, here with
SHA-256 and X25519; one-time prekeys that are not signed; the deletion of the one-time
prekey private key when its initial message is accepted; the first message of the ratchet
as the initial ciphertext.

### 25.2 From the Double Ratchet, Revision 4

| Double Ratchet, Revision 4                                               | This protocol                                                              | Reason                                                                     |
|--------------------------------------------------------------------------|----------------------------------------------------------------------------|----------------------------------------------------------------------------|
| Double Ratchet sections 4, 5 and 6: header encryption, the Sparse Post-Quantum Ratchet and the Triple Ratchet | Double Ratchet sections 2 and 3 only | Each is a second protocol. The header is readable for the relay, and there is no post-quantum protection (section 25.4) |
| ENCRYPT is recommended as SIV or as CBC with HMAC (Double Ratchet section 7.2) | ChaCha20-Poly1305 with a random nonce that is sent, which Double Ratchet section 3.1 permits | CryptoKit has no SIV mode, and both libraries have this AEAD. The random nonce is the hedge against a key used twice |
| DH: "no need to check for invalid public keys" (Double Ratchet section 7.2) | An all-zero output fails the decryption (section 16.3)                  | The Python library raises on it and CryptoKit does not: one rule for both  |
| The associated data is the AD of the key agreement and the header        | The session associated data, the message id and the header (section 18.2)  | The message id is the key by which copies are dropped, so it has to be authentic |
| CONCAT can need a length in front of AD (Double Ratchet section 3.1)     | No length                                                                  | All three parts have fixed lengths                                         |
| The encoding of the header is left open                                  | 40 fixed bytes (section 17.5)                                              | It is authenticated as received, and protobuf serialization is not canonical |
| MAX_SKIP is checked chain by chain, the second check after keys of the first chain were derived | Both checks come before any key is derived (section 17.7) | A header that asks for too many keys costs the receiver no key derivation. The results are the same |
| A message whose number lies behind Nr fails at the AEAD, after a key was derived | It fails before a key is derived (section 17.7, step 3)            | The same result at less cost                                               |
| MKSKIPPED "raises an exception if too many elements are stored"; deletion after an interval is advised (Double Ratchet sections 3.2 and 8.4) | A cap of 2000 that removes the oldest key, and a purge after 5 DH ratchet steps (section 17.8) | A session that only failed at the cap could stay stuck. Deletion follows events, not a timer (Double Ratchet section 8.7) |
| The state has no counter of DH ratchet steps                             | DHSTEPS (section 17.2)                                                     | The purge needs it                                                         |
| The size of the counters is left open                                    | u32; a chain ends at 2^32 - 2 (section 17.9)                               | A width has to be written down                                             |
| Double Ratchet section 7.1 joins the ratchet to PQXDH                    | To the key agreement of section 16, in the same way: SK, the associated data, the signed prekey as the first ratchet key | Section 25.4                                                   |

Kept as written: the state variables and the initialisation of Double Ratchet sections
3.2 and 3.3; KDF_RK and KDF_CK as Double Ratchet section 7.2 recommends them; the order
of the steps of RatchetEncrypt and RatchetDecrypt; a new ratchet key pair made in the DH
ratchet step, not deferred (Double Ratchet section 8.5); the state discarded when a
decryption fails; the pattern of Double Ratchet section 7.1, the initial message of the
key agreement in front of every message of the initiator until the first message of the
responder decrypts.

### 25.3 From Sesame

This protocol takes one rule from Sesame, Revision 2: a list of sessions per peer in
which a session that receives becomes the sending session (section 20.1). It has no
devices and no user records, no stale records, no retry requests and no delivery
receipts, and no expiry of a session by time.

### 25.4 What Signal runs and this protocol lacks

The two specifications that this protocol follows are not what the Signal applications
run.

- Signal's key agreement is PQXDH: it adds a post-quantum key encapsulation to the
  Diffie-Hellman values. This protocol has X3DH Revision 1.
- Signal's ratchet is the Triple Ratchet: the Double Ratchet together with the Sparse
  Post-Quantum Ratchet, sections 5 and 6 of Revision 4. This protocol has the Double
  Ratchet alone.

This protocol has no post-quantum protection of any kind. Whoever records its traffic
and later has a quantum computer that breaks X25519 can open what was recorded; the
healing of the Double Ratchet does not help against that (Double Ratchet, section 8.11).
Nothing is reserved for a post-quantum step but the two version numbers.

### 25.5 Deniability

This protocol claims no deniability.

One fact is stated: no signature covers the content of a message. An identity key signs
the three strings of section 4 and nothing else, and a message is authenticated by the
AEAD under keys that both sides can compute.

That fact is not a claim that a user can deny a conversation. The login signature shows
the relay that the holder of an identity key was connected (section 8), the signatures of
a bundle show that the identity published those keys, and the relay sees who sends to
whom. The deniability that X3DH describes (X3DH, section 4.4) was not examined for the
changes of section 25.1.

### 25.6 From the age format

The blob cipher of section 29 is the payload of the age format, version 1, with these
differences:

| age, version 1                                                           | This protocol                                                              | Reason                                                                     |
|--------------------------------------------------------------------------|----------------------------------------------------------------------------|----------------------------------------------------------------------------|
| A header in front of the payload wraps the file key for each recipient, and a MAC covers the header | No header. A blob is the payload alone, and the file key travels in an `Attachment` inside a message of the ratchet (section 32) | The ratchet already carries a key to one recipient and authenticates it with the session. A header would wrap the same key a second time |
| The payload encrypts the file                                            | It encrypts the file followed by zero bytes up to the padded length of section 29.2 | The relay sees the length of every blob                         |
| A reader decrypts chunks until it reaches the final one                  | The reader knows the length of the blob from `size` and refuses another length before it opens a chunk. It also checks the SHA-256 of the whole blob and that the padding is zero bytes (section 29.7) | One verdict on the whole blob before any byte of it is shown, however the download was split and resumed |

Kept as written: a file key of 16 bytes from the random number generator, for one file
only; a nonce of 16 bytes at the start of the payload, new for each file; the payload key
from HKDF-SHA-256 with the nonce as salt and `payload` as info; chunks of 64 KiB; the
nonce of a chunk, an 11-byte big-endian counter from 0 and a last byte `01` for the final
chunk and `00` for the others; a final chunk of 64 KiB or less that is not empty;
ChaCha20-Poly1305, which the age text names by RFC 7539 and RFC 8439 obsoletes with the
same algorithm, with no associated data.

The padding is the Padmé function as Nikitin and others define it, applied to the size
or to 256, whichever is larger: the function is not defined for 0 and 1, and the lower
bound gives every small file one length.

## 26. Not part of this protocol

These are left out on purpose. Each is a second protocol, or needs a deployed
environment, or has no user before a later stage of the project.

- TLS inside the relay process, and the reverse proxy with the header that passes on the
  address of a client.
- Limits per address: connections per address and new identities per address.
- Expiry of identities.
- Proof of work.
- Hiding the sender from the relay, and encryption of the message header.
- Post-quantum key agreement and a post-quantum ratchet (section 25.4). Nothing is
  reserved for them beyond the two version numbers.
- Verification of keys by a safety number.
- Several devices per identity, groups and calls.
- Any claim of deniability (section 25.5).
- Encryption of the client store, and key storage in a keychain or in hardware.
- Moving an identity to another device, and a backup of it.
- Replacing or revoking an identity key.
- Delivery receipts, read receipts and requests to send a message again.
- Expiry of a session by time.
- Kinds of content other than a text and an attachment. The oneof of section 19.1 is
  their place.
- Of files: a blob for several recipients, the forwarding of a blob to another
  recipient, playback of a file before its download ends, previews that the relay makes,
  and the reuse of a blob for the same file.

## 27. References

- RFC 2104, HMAC: Keyed-Hashing for Message Authentication.
- RFC 3986, Uniform Resource Identifier (URI): Generic Syntax.
- RFC 4291, IP Version 6 Addressing Architecture.
- RFC 5869, HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
- RFC 5890, Internationalized Domain Names for Applications (IDNA): Definitions and
  Document Framework.
- RFC 6234, US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF).
- RFC 6455, The WebSocket Protocol.
- RFC 7748, Elliptic Curves for Security.
- RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA).
- RFC 6838, Media Type Specifications and Registration Procedures.
- RFC 7539, ChaCha20 and Poly1305 for IETF Protocols, obsoleted by RFC 8439.
- RFC 8439, ChaCha20 and Poly1305 for IETF Protocols.
- Protocol Buffers documentation, "Proto Serialization Is Not Canonical",
  https://protobuf.dev/programming-guides/serialization-not-canonical/
- K. Chalkias, F. Garillot, V. Nikolaenko, "Taming the many EdDSAs", IACR ePrint
  2020/1244, https://eprint.iacr.org/2020/1244
- M. Marlinspike, T. Perrin, "The X3DH Key Agreement Protocol", Revision 1,
  https://signal.org/docs/specifications/x3dh/
- T. Perrin, M. Marlinspike, R. Schmidt, "The Double Ratchet Algorithm", Revision 4,
  https://signal.org/docs/specifications/doubleratchet/
- M. Marlinspike, T. Perrin, "The Sesame Algorithm: Session Management for Asynchronous
  Message Encryption", Revision 2, https://signal.org/docs/specifications/sesame/
- E. Kret, R. Schmidt, "The PQXDH Key Agreement Protocol", Revision 3,
  https://signal.org/docs/specifications/pqxdh/
- IANA, WebSocket Close Code Number Registry,
  https://www.iana.org/assignments/websocket/websocket.xhtml
- C2SP, "age", the age-encryption.org/v1 file format, section "Payload",
  https://c2sp.org/age
- V. T. Hoang, R. Reyhanitabar, P. Rogaway, D. Vizár, "Online Authenticated-Encryption
  and its Nonce-Reuse Misuse-Resistance", CRYPTO 2015, IACR ePrint 2015/189,
  https://eprint.iacr.org/2015/189
- K. Nikitin, L. Barman, W. Lueks, M. Underwood, J.-P. Hubaux, B. Ford, "Reducing
  Metadata Leakage from Encrypted Files and Communication with PURBs", Proceedings on
  Privacy Enhancing Technologies 2019(4), https://arxiv.org/abs/1806.03160

## 28. Attachments

### 28.1 What part 3 is

Part 3 specifies how a client sends a file to a contact: a photo, a document, any byte
string of up to MAX_FILE_BYTES. It adds no key agreement and no key of an identity.

- The sender encrypts the file on its device under a new random key with the blob cipher
  of section 29. The result is a blob.
- It uploads the blob to the relay in pieces with the blob frames of section 30, and an
  upload that stopped goes on from the length that the relay stored. The relay keeps the
  blob for the one recipient that the upload names (section 31).
- When the relay holds the whole blob, the sender sends a message of the ratchet whose
  `Content` is an `Attachment` (section 32): the blob id, the key, the size of the file,
  the digest of the blob and what the recipient shows before it downloads the file: the
  media type, the file name, the size of an image, a thumbnail and a caption.
- The recipient fetches the blob by ranges, and a download that stopped goes on from the
  bytes it holds. It checks the blob, decrypts it and then deletes the blob at the relay.

The relay stores and passes on the blob and holds no key that opens it: the key travels
only inside a message of the ratchet (sections 17 and 18). Section 33 states what a client
does and when a file counts as sent, received or failed, and section 34 the test vectors
of the blob cipher.

### 28.2 Versions and the announcement

Part 3 changes neither version number of section 1.3.

- The relay protocol. A relay announces that it serves the blob frames with the field
  `blob_max_bytes` of LoggedIn (section 7.7): the length of the largest blob it accepts,
  BLOB_MAX_BYTES (section 31.7). A relay that does not serve them leaves the field at 0,
  and a client that reads 0 sends no blob frame (section 33.1). A client that does not
  implement part 3 ignores the field (section 7.3) and never receives a blob frame: the
  relay sends the frames of section 30 only as answers to blob frames. Section 14.1 counts
  a frame of this kind as no new version.
- The end-to-end protocol. `attachment` is a new member of the `Content` oneof. A client
  that does not implement part 3 reports such a message as UNKNOWN_CONTENT (section 19.5)
  and acks it; the blob stays at the relay until it expires (section 31.5).

### 28.3 Status of part 3

The relay of this repository serves the blob frames (sections 30 and 31), and its
command-line client implements the blob cipher, the attachment and the rules of a client
(sections 29 and 32 to 34). Every rule of part 3 carries a citation like the rules of
parts 1 and 2 (section 1.2).

### 28.4 Terms

- A file: the bytes that a user sends, 0 to MAX_FILE_BYTES of them.
- A blob: a file encrypted by section 29, as the relay stores it.
- The uploader of a blob: the identity of the connection that sent its StartBlob. The
  recipient of a blob: the identity that the StartBlob names.
- The blob id: 16 random bytes that the uploader chooses. Like a message id it is unique
  per uploader only: a blob is named by the pair (uploader, blob id).
- The length of a blob: its number of bytes, B. The stored length: how many of its first
  bytes the relay holds.
- A complete blob: a blob whose stored length is its length.

## 29. The blob cipher

### 29.1 What it is

The blob cipher is the payload of the age format, version 1, as the section "Payload" of
the age specification defines it (section 27): the STREAM construction with
ChaCha20-Poly1305 in chunks of 64 KiB. A blob is an age payload byte for byte and has no
age header. The file is padded before it is encrypted (section 29.2). Section 25.6 lists
every difference from the age format with its reason.

An encryption takes the file, a file key of 16 random bytes and a nonce of 16 random
bytes [test: tests/crypto/test_blob_vectors.py::test_positive_vectors_replay_byte_for_byte]. A client makes a new file key
and a new nonce for every blob. It MUST NOT use a file key or a nonce for a second blob,
the same file sent again included
[test: tests/client/test_files.py::test_same_file_sent_twice_gets_a_new_blob_id_key_and_nonce].

### 29.2 Padding

The padded length P of a file of `size` bytes is the Padmé function of Nikitin and others
(section 27) applied to the size or to FILE_PADDING_MIN, 256 bytes, whichever is larger:

```
L = max(size, 256)
E = floor(log2(L))
S = floor(log2(E)) + 1
z = E - S
m = 2^z - 1
P = (L + m) AND NOT m
```

The plaintext M of the cipher is the file followed by P - size bytes `00`
[test: tests/crypto/test_blob_vectors.py::test_positive_vectors_replay_byte_for_byte]
[test: tests/crypto/test_blob.py::test_padded_lengths_are_the_table_of_section_29_2].

| `size`    | P         |
|-----------|-----------|
| 0         | 256       |
| 255       | 256       |
| 257       | 272       |
| 1000      | 1024      |
| 65537     | 67584     |
| 1000000   | 1015808   |
| 104857600 | 104857600 |
| 104857601 | 106954752 |

- P is at least 256 and never less than `size`. For a file of 256 bytes or more, P - size
  is less than size / 16: the last z bits of P are zero, and z is less than E by S, which
  is at least 4 [test: tests/crypto/test_blob.py::test_padding_is_at_least_the_minimum_and_below_a_sixteenth].
- Between 2^E and 2^(E+1) lie 2^S padded lengths: 16 for E from 8 to 15, 32 for E from
  16 to 26. The relay learns which of them a file has and nothing finer.
- MAX_FILE_BYTES, 104857600, is its own padded length, and the next size gives 106954752:
  a file of more than MAX_FILE_BYTES is not sent (section 33.1)
  [test: tests/crypto/test_blob.py::test_file_above_the_largest_is_not_encrypted].

### 29.3 The payload key

The payload key is one call of HKDF (RFC 5869)
[test: tests/crypto/test_blob_vectors.py::test_intermediates_are_the_values_of_the_core]:

| Parameter          | Value                                              |
|--------------------|----------------------------------------------------|
| Hash               | SHA-256                                            |
| Salt               | The 16-byte nonce                                  |
| Input key material | The 16-byte file key                               |
| Info               | ASCII `payload`, 7 bytes, hex `7061796c6f6164`     |
| Output length      | 32 bytes                                           |

The calls are `HKDF(algorithm=hashes.SHA256(), length=32, salt=nonce, info=b"payload")`
with `derive(file_key)` in the Python package cryptography and
`HKDF<SHA256>.deriveKey(inputKeyMaterial:salt:info:outputByteCount:)` in CryptoKit.

### 29.4 Chunks

M is cut into chunks of STREAM_CHUNK_BYTES, 65536 bytes. Chunk i, counted from 0, is the
bytes 65536 * i to 65536 * (i + 1) - 1 of M. There are n = ceil(P / 65536) chunks, and the
last one, number n - 1, holds what is left: 1 to 65536 bytes. M has at least 256 bytes,
so no chunk is empty [test: tests/crypto/test_blob_vectors.py::test_intermediates_are_the_values_of_the_core]
[test: tests/crypto/test_blob_vectors.py::test_positive_vectors_replay_byte_for_byte].

Chunk i is sealed with ChaCha20-Poly1305 (RFC 8439 section 2.8) under the payload key,
with no associated data, and with this nonce of 12 bytes:

| Offset | Length | Field   | Value                                              |
|--------|--------|---------|----------------------------------------------------|
| 0      | 11     | counter | i, big-endian                                      |
| 11     | 1      | last    | `01` for chunk n - 1, `00` for every other chunk   |

The sealed chunk is the ciphertext, as long as the chunk, followed by a tag of 16 bytes.
The calls are `ChaCha20Poly1305(payload_key).encrypt(nonce, chunk, None)` in the Python
package cryptography and `ChaChaPoly.seal(_:using:nonce:)` in CryptoKit, whose
`ciphertext` and `tag` are taken in this order.

### 29.5 The blob

| Offset              | Length            | Field                                       |
|---------------------|-------------------|---------------------------------------------|
| 0                   | 16                | The nonce of section 29.1                   |
| 16                  | 65552             | Sealed chunk 0                              |
| 16 + 65552 * i      | 65552             | Sealed chunk i, for every chunk but the last |
| 16 + 65552 * (n - 1) | 16 + the length of the last chunk | Sealed chunk n - 1        |

The length of the blob is B = 16 + P + 16 * n
[test: tests/crypto/test_blob.py::test_blob_lengths_are_the_table_of_section_29_5].

| `size`    | P         | n    | B         |
|-----------|-----------|------|-----------|
| 0         | 256       | 1    | 288       |
| 65536     | 65536     | 1    | 65568     |
| 65537     | 67584     | 2    | 67632     |
| 104857600 | 104857600 | 1600 | 104883216 |

### 29.6 The digest

The digest of a blob is SHA-256 (RFC 6234) of its B bytes, 32 bytes. The calls are
`hashlib.sha256` of the Python standard library and `SHA256.hash(data:)` in CryptoKit.
The digest travels in the attachment, inside a message of the ratchet (section 32)
[test: tests/crypto/test_blob_vectors.py::test_positive_vectors_replay_byte_for_byte].

### 29.7 Opening a blob

A client opens a blob from the bytes it fetched and the `key`, `size` and `digest` of the
attachment. The opening succeeds when all six steps hold. When one fails, the result is
BAD_BLOB, whichever step a client runs first
[test: tests/crypto/test_blob_vectors.py::test_negative_vectors_raise_their_named_error]
[test: tests/crypto/test_blob_vectors.py::test_negative_vector_at_the_chunks_has_its_length_and_its_own_digest]:

1. The number of bytes is B for the P of `size` (sections 29.2 and 29.5).
2. SHA-256 of the bytes is `digest`.
3. The payload key is derived from `key` and the first 16 bytes (section 29.3).
4. The rest is cut into sealed chunks of 65552 bytes, the last one shorter or equal. Each
   is opened in order, with the nonce of its number and the byte `01` for the last chunk
   only. A chunk that does not verify fails the step.
5. The bytes of M from `size` on are all `00`.
6. The file is the first `size` bytes of M.

A client MAY open chunks as they arrive, as the age format allows, but it shows and saves
no byte as the file before all six steps passed. A blob that fails leaves nothing
[test: tests/client/test_files.py::test_altered_or_truncated_blob_could_not_be_received_and_writes_nothing]
[test: tests/client/test_files.py::test_blob_whose_chunk_does_not_open_under_its_digest_writes_nothing].

What the steps catch. The relay holds no key, so it cannot make a chunk that opens. A
chunk that is dropped, repeated, moved or cut fails at its nonce and its tag, and a blob
that ends after a whole chunk fails at step 1 or at the last flag. The digest checks the
whole blob in one step before any chunk is opened, however the download was split and
resumed; it does not replace the tag of a chunk. Step 5 makes the plaintext of a blob a
function of the file alone, so that two implementations accept the same blobs.

## 30. The blob frames

### 30.1 The frames

Section 7.1 lists the blob frames with the other frames of the relay protocol.

| Frame                                 | Sent by | Valid                                   | Answer                |
|---------------------------------------|---------|-----------------------------------------|-----------------------|
| StartBlob                             | client  | After the Login of the connection       | BlobStored or Error   |
| PutBlob                               | client  | After the Login of the connection       | BlobStored or Error   |
| FetchBlob                             | client  | After the Login of the connection       | BlobData or Error     |
| DeleteBlob                            | client  | After the Login of the connection       | none                  |
| BlobStored, BlobData                  | relay   | As answers only                         | none                  |

- A client sends a blob frame only to a relay that announced a `blob_max_bytes` other
  than 0 in the LoggedIn of the connection (section 28.2). A relay without the blob
  frames treats one as a malformed frame and closes with 1008 (section 7.3).
- The rules of state of section 7.4 hold for the blob frames: a blob frame before the
  login closes with 1008 [test: tests/test_blobs.py::test_blob_frame_before_the_login_closes_with_1008]; the
  relay handles the frames of a connection one at a time and answers each before it
  handles the next; every StartBlob, PutBlob and FetchBlob gets exactly one answer
  [test: tests/test_blobs.py::test_blob_uploaded_in_pieces_is_fetched_byte_for_byte_by_its_recipient].
- A client MAY send several PutBlob or FetchBlob frames before their answers arrive. The
  answers come in the order of the frames
  [test: tests/test_blobs.py::test_blob_uploaded_in_pieces_is_fetched_byte_for_byte_by_its_recipient].
- The field numbers follow section 7.2: `blob_id` is field 1 of every blob frame, and
  FetchBlob, BlobData and DeleteBlob share their first two fields, the pair (blob id,
  uploader), as a MessageRef shares them with a Deliver.

### 30.2 StartBlob

| Field       | No. | Type   | Length or value                                    |
|-------------|-----|--------|----------------------------------------------------|
| `blob_id`   | 1   | bytes  | 16, random, chosen by the uploader                 |
| `recipient` | 2   | bytes  | 32, the identity key of the recipient              |
| `length`    | 3   | uint32 | 1 to 2^32 - 1, the length B of the blob            |

- Sent by a logged-in client to start an upload, and again to learn how far an upload
  got (section 33.4).
- Valid answers: BlobStored; or Error with RATE_LIMITED, BLOB_TOO_LARGE,
  UNKNOWN_RECIPIENT, QUOTA_FULL or STORAGE_FULL, with `blob_id` set to the `blob_id` of
  the request (section 30.8).
- Violations: a malformed StartBlob closes with 1008, a `length` of 0 included
  [test: tests/test_frames.py::test_blob_frame_that_breaks_its_table_is_malformed]. Section 31.1 has the full rules.

### 30.3 PutBlob

| Field     | No. | Type   | Length or value                                       |
|-----------|-----|--------|-------------------------------------------------------|
| `blob_id` | 1   | bytes  | 16, the `blob_id` of a StartBlob of the same uploader |
| `offset`  | 2   | uint32 | The position of `data` in the blob                    |
| `data`    | 3   | bytes  | 1 to BLOB_CHUNK_BYTES, that is 65408 bytes             |

- Sent by a logged-in client: bytes of a blob that it uploads.
- Valid answers: BlobStored; or Error with NOT_FOUND, BLOB_TOO_LARGE or STORAGE_FULL,
  with `blob_id` set.
- Violations: a malformed PutBlob closes with 1008, an empty `data` included
  [test: tests/test_frames.py::test_blob_frame_that_breaks_its_table_is_malformed]. Section 31.2 has the full rules.

### 30.4 BlobStored

| Field           | No. | Type   | Length or value                                      |
|-----------------|-----|--------|------------------------------------------------------|
| `blob_id`       | 1   | bytes  | 16, the `blob_id` of the request                     |
| `stored_length` | 2   | uint32 | The stored length of the blob after the request      |

- Sent by the relay as the answer to a StartBlob or a PutBlob, after the commit of what
  the request stored.
- No answer.
- Violations, seen by the client: a `blob_id` that is not 16 bytes is a malformed frame.

### 30.5 FetchBlob

| Field      | No. | Type   | Length or value                                              |
|------------|-----|--------|--------------------------------------------------------------|
| `blob_id`  | 1   | bytes  | 16, the `blob_id` of an attachment                           |
| `uploader` | 2   | bytes  | 32, the `sender` of the Deliver that carried the attachment  |
| `offset`   | 3   | uint32 | The first byte asked for                                     |
| `length`   | 4   | uint32 | 1 to BLOB_CHUNK_BYTES, the number of bytes asked for          |

- Sent by a logged-in client: a range of a blob of which it is the recipient.
- Valid answers: BlobData; or Error with NOT_FOUND, with `blob_id` set to the `blob_id`
  and `identity` to the `uploader` of the request.
- Violations: a malformed FetchBlob closes with 1008
  [test: tests/test_frames.py::test_blob_frame_that_breaks_its_table_is_malformed]. Section 31.3 has the full rules.

### 30.6 BlobData

| Field      | No. | Type   | Length or value                                                          |
|------------|-----|--------|--------------------------------------------------------------------------|
| `blob_id`  | 1   | bytes  | 16, the `blob_id` of the request                                         |
| `uploader` | 2   | bytes  | 32, the `uploader` of the request                                        |
| `offset`   | 3   | uint32 | The `offset` of the request                                              |
| `data`     | 4   | bytes  | 0 to BLOB_CHUNK_BYTES: the bytes of the blob from `offset` on, `length` of them, or fewer at the end of the blob |

- Sent by the relay as the answer to a FetchBlob.
- No answer.
- Violations, seen by the client: a `blob_id` that is not 16 bytes, an `uploader` that is
  not 32 bytes and a `data` above BLOB_CHUNK_BYTES are malformed frames.

### 30.7 DeleteBlob

| Field      | No. | Type  | Length or value                                                    |
|------------|-----|-------|--------------------------------------------------------------------|
| `blob_id`  | 1   | bytes | 16                                                                 |
| `uploader` | 2   | bytes | 32, the uploader of the blob: the client's own identity key for a blob it uploads |

- Sent by a logged-in client: the uploader gives up a blob, or the recipient is done with
  one.
- No answer and no Error, whatever the frame names (section 31.4).
- Violations: a malformed DeleteBlob closes with 1008
  [test: tests/test_frames.py::test_blob_frame_that_breaks_its_table_is_malformed].

### 30.8 The Error of a blob frame

The `blob_id` of an Error (section 7.16) is 16 bytes when the refused frame is a
StartBlob, a PutBlob or a FetchBlob, and is its `blob_id`; otherwise it is empty. The key
fields tell a client which frame was refused:

| Key fields set              | Refused frame                  |
|-----------------------------|--------------------------------|
| `blob_id` alone             | StartBlob or PutBlob           |
| `blob_id` and `identity`    | FetchBlob; `identity` is its `uploader` |

A StartBlob and a PutBlob of one blob have one key; the order of the answers tells them
apart (section 7.4). A client treats an Error as a malformed frame when its `blob_id` is
neither empty nor 16 bytes, or when `blob_id` and `message_id` are both set.

## 31. The relay and blobs

### 31.1 StartBlob

The relay handles a well-formed StartBlob of a logged-in connection in this order. The
uploader is the identity of the connection. Steps 2 to 6 are one transaction.

1. It takes a token from the frame bucket of the uploader (section 12.2). Without a token
   the answer is Error RATE_LIMITED
   [test: tests/test_blobs.py::test_start_takes_a_token_and_put_fetch_and_delete_take_none].
2. When the relay holds a blob with this uploader and this `blob_id`, the answer is
   BlobStored with its stored length and nothing else happens. The `recipient` and the
   `length` of the request are not looked at
   [test: tests/test_blobs.py::test_repeated_start_answers_the_stored_length_and_looks_at_nothing_else].
3. When `length` is more than BLOB_MAX_BYTES, the answer is Error BLOB_TOO_LARGE
   [test: tests/test_blobs.py::test_start_longer_than_the_largest_blob_is_blob_too_large].
4. When `recipient` is not registered, the answer is Error UNKNOWN_RECIPIENT
   [test: tests/test_blobs.py::test_start_to_an_unregistered_recipient_is_unknown_recipient].
5. When the lengths of the blobs that the relay holds for this uploader, complete or not,
   together with `length` are more than BLOB_QUOTA_BYTES, the answer is Error
   QUOTA_FULL [test: tests/test_blobs.py::test_start_over_the_quota_is_quota_full_and_a_deletion_makes_room].
6. It stores the uploader, the recipient, the blob id, the length, no byte of the blob
   and the time in whole seconds, and commits. When the transaction fails because the
   database is at its page ceiling, it is rolled back and the answer is Error
   STORAGE_FULL
   [test: tests/test_blobs.py::test_start_and_put_into_a_full_database_answer_storage_full_and_the_relay_serves_on].
7. The answer is BlobStored with `stored_length` 0
   [test: tests/test_blobs.py::test_blob_uploaded_in_pieces_is_fetched_byte_for_byte_by_its_recipient].

Step 2 is what makes a StartBlob safe to repeat: it is the question "how far did this
upload get" after a connection ended (section 33.4).

### 31.2 PutBlob

The relay handles a well-formed PutBlob of a logged-in connection in this order. The
uploader is the identity of the connection. Steps 1 to 4 are one transaction.

1. When the relay holds no blob with this uploader and this `blob_id`, the answer is
   Error NOT_FOUND
   [test: tests/test_blobs.py::test_put_of_an_unknown_blob_or_of_another_uploader_is_not_found].
2. When `offset` is not the stored length of the blob, the answer is BlobStored with the
   stored length and nothing is stored. This covers a PutBlob that is repeated after a
   lost answer and one that a client sent behind a PutBlob that failed
   [test: tests/test_blobs.py::test_put_at_another_offset_than_the_stored_length_stores_nothing]
   [test: tests/test_blobs.py::test_upload_cut_with_its_connection_goes_on_from_the_stored_length].
3. When `offset` and the length of `data` together are more than the length of the blob,
   the answer is Error BLOB_TOO_LARGE and nothing is stored
   [test: tests/test_blobs.py::test_piece_that_ends_past_the_length_is_blob_too_large_and_stores_nothing].
4. It appends `data` to the blob, sets the time of the blob to the time in whole seconds,
   and commits. When the transaction fails because the database is at its page ceiling,
   it is rolled back and the answer is Error STORAGE_FULL
   [test: tests/test_blobs.py::test_start_and_put_into_a_full_database_answer_storage_full_and_the_relay_serves_on]
   [test: tests/test_blobs.py::test_blob_expires_its_ttl_after_its_last_write_complete_or_not].
5. The answer is BlobStored with the new stored length
   [test: tests/test_blobs.py::test_blob_uploaded_in_pieces_is_fetched_byte_for_byte_by_its_recipient].

A blob is complete when its stored length reaches its length; no frame finishes it
[test: tests/test_blobs.py::test_fetch_of_a_blob_that_is_not_a_complete_one_of_the_recipient_is_not_found].

A PutBlob, a FetchBlob and a DeleteBlob take no token from the frame bucket
[test: tests/test_blobs.py::test_start_takes_a_token_and_put_fetch_and_delete_take_none]. A token for
each would hold the largest blob, 1604 frames of BLOB_CHUNK_BYTES, to one frame a second
once the bucket is empty: more than 25 minutes. The relay handles the frames of a
connection one at a time, so a connection moves blob bytes no faster than the relay
writes and reads them; BLOB_QUOTA_BYTES and the page ceiling bound what is stored.

### 31.3 FetchBlob

The relay handles a well-formed FetchBlob of a logged-in connection in this order:

1. When the relay holds no complete blob with this `uploader` and this `blob_id` whose
   recipient is the identity of the connection, the answer is Error NOT_FOUND. The answer
   is the same for a blob that does not exist, one that is not complete and one with
   another recipient
   [test: tests/test_blobs.py::test_fetch_of_a_blob_that_is_not_a_complete_one_of_the_recipient_is_not_found].
2. The answer is BlobData with the bytes of the blob from `offset` on: `length` of them,
   or as many as the blob has from `offset` on, when that is fewer. When `offset` is the
   length of the blob or more, `data` is empty
   [test: tests/test_blobs.py::test_blob_uploaded_in_pieces_is_fetched_byte_for_byte_by_its_recipient].

A fetch changes nothing: the blob, its time and its bytes stay as they were
[test: tests/test_blobs.py::test_blob_uploaded_in_pieces_is_fetched_byte_for_byte_by_its_recipient]
[test: tests/test_blobs.py::test_download_cut_with_its_connection_goes_on_from_the_bytes_it_holds]. Only the
recipient of a blob receives its bytes; the uploader cannot fetch its own blob
[test: tests/test_blobs.py::test_fetch_of_a_blob_that_is_not_a_complete_one_of_the_recipient_is_not_found].

### 31.4 DeleteBlob

- The relay deletes the blob with this `uploader` and this `blob_id` when the identity of
  the connection is its uploader, whether the blob is complete or not, or is its
  recipient and the blob is complete. Otherwise it does nothing
  [test: tests/test_blobs.py::test_uploader_deletes_its_blob_complete_or_not]
  [test: tests/test_blobs.py::test_recipient_deletes_only_a_complete_blob_and_a_start_after_it_is_a_new_blob].
- A DeleteBlob has no answer and no Error, and is safe to repeat
  [test: tests/test_blobs.py::test_recipient_deletes_only_a_complete_blob_and_a_start_after_it_is_a_new_blob].
- A deleted blob does not count toward the quota of its uploader
  [test: tests/test_blobs.py::test_start_over_the_quota_is_quota_full_and_a_deletion_makes_room].
- The relay keeps no record of a deleted blob. A StartBlob with the same blob id after
  the deletion makes a new blob (section 31.1)
  [test: tests/test_blobs.py::test_recipient_deletes_only_a_complete_blob_and_a_start_after_it_is_a_new_blob].

### 31.5 Expiry

The relay deletes a blob BLOB_TTL_SECONDS after its last write, the StartBlob that made
it or the last PutBlob that appended to it, at the first sweep after that moment
(section 13), whether it is complete or not. Nobody gets a notice
[test: tests/test_blobs.py::test_blob_expires_its_ttl_after_its_last_write_complete_or_not].

A sender sends the message of a file after the last write of its blob (section 33.2),
and the relay keeps a message for MESSAGE_TTL_SECONDS at most. With the defaults a blob so
outlives the message that names it by a week, less the time from the last write of the
blob to the moment the relay stored the message; for a client that stays connected that
time is short. A recipient has about that week to download a file that reached it on the
last day of its message.

### 31.6 The errors of the blob frames

The codes are those of section 11.2 and two more, QUOTA_FULL and BLOB_TOO_LARGE.

| Code              | No. | Refuses            | Sent when                                                                  | Client                       |
|-------------------|-----|--------------------|----------------------------------------------------------------------------|------------------------------|
| UNKNOWN_RECIPIENT | 1   | StartBlob          | The recipient is not registered at this relay                              | Stop                         |
| STORAGE_FULL      | 3   | StartBlob, PutBlob | The database is at its page ceiling                                        | Back off                     |
| RATE_LIMITED      | 4   | StartBlob          | The frame bucket of the identity is empty                                  | Back off                     |
| NOT_FOUND         | 5   | PutBlob            | The relay holds no blob of the uploader with this id                       | StartBlob again (section 33.2) |
| NOT_FOUND         | 5   | FetchBlob          | The relay holds no complete blob with this uploader and id for this recipient | Stop: BLOB_GONE (section 33.3) |
| QUOTA_FULL        | 8   | StartBlob          | The blob would take the blobs of the uploader over BLOB_QUOTA_BYTES        | Stop                         |
| BLOB_TOO_LARGE    | 9   | StartBlob, PutBlob | `length` is more than BLOB_MAX_BYTES, or `data` would end past the length  | Stop                         |

A refused blob frame stores nothing and deletes nothing
[test: tests/test_blobs.py::test_piece_that_ends_past_the_length_is_blob_too_large_and_stores_nothing]
[test: tests/test_blobs.py::test_start_to_an_unregistered_recipient_is_unknown_recipient]
[test: tests/test_blobs.py::test_start_longer_than_the_largest_blob_is_blob_too_large]
[test: tests/test_blobs.py::test_start_takes_a_token_and_put_fetch_and_delete_take_none]
[test: tests/test_blobs.py::test_start_and_put_into_a_full_database_answer_storage_full_and_the_relay_serves_on].
The actions are those of section 11.1.

### 31.7 Limits

| Name             | Default   | Unit    | Meaning                                                                      |
|------------------|-----------|---------|------------------------------------------------------------------------------|
| BLOB_CHUNK_BYTES | 65408     | bytes   | The largest `data` of a PutBlob and of a BlobData, and the largest `length` of a FetchBlob: MAX_FRAME_BYTES - 128 |

BLOB_MAX_BYTES, BLOB_QUOTA_BYTES and BLOB_TTL_SECONDS are settings: their rows are in the
table of section 12.1, and the relay reads them from the environment as that section says
[test: tests/test_docs.py::test_limits_table_is_the_settings_of_the_relay]. A test compares
the table above with the code [test: tests/test_docs.py::test_blob_limits_table_is_the_constant_of_the_relay].

- BLOB_CHUNK_BYTES is a constant of relay protocol version 1, like MAX_FRAME_BYTES. The
  128 bytes bound what the envelope and the other fields add to `data`: 32 bytes in the
  longest PutBlob and 66 in the longest BlobData
  [test: tests/test_frames.py::test_largest_put_blob_and_blob_data_fit_the_largest_frame].
- An operator MAY lower BLOB_MAX_BYTES: a client takes the value from the LoggedIn
  (section 33.1). A larger value gains nothing, since no client sends a file of more than
  MAX_FILE_BYTES.
- A blob counts toward the quota of its uploader until it is deleted. A blob that its
  recipient never downloads, because the user does not ask for it or the client of the
  recipient does not implement part 3, holds its room for BLOB_TTL_SECONDS.
- Blobs count toward MAX_PAGES (section 12.3). Its default, 8 GiB, holds about eighty
  blobs of the largest length, or the full quotas of 32 uploaders. The reason: with the
  1 GiB that parts 1 and 2 had, three users who each send a long video fill the relay,
  and every Send and upload after that gets STORAGE_FULL. 8 GiB still fits the disk of a
  small host with room for the write-ahead log, which the ceiling does not bound
  (section 13.2). The ceiling is a guard against a full disk, not a sizing: an operator
  whose disk is smaller lowers it, one who serves more files raises it.

### 31.8 Storage, erasure and metrics

- The relay of this repository keeps a blob, with its bytes, in its database file, the
  one file of its state. It stores the `data` of each PutBlob as a piece of its own, so
  that a PutBlob writes its own bytes and not the blob again
  [test: tests/test_process.py::test_blob_stored_length_survives_a_kill_of_the_relay].
  It sends BlobStored only after the commit of what the request stored
  [test: tests/test_blobs.py::test_blob_stored_is_sent_after_the_commit_of_the_piece], so that a stored length
  it reported survives a kill of the relay process
  [test: tests/test_process.py::test_blob_stored_length_survives_a_kill_of_the_relay]
  and a restart [test: tests/test_blobs.py::test_upload_goes_on_from_the_stored_length_after_a_restart_of_the_relay].
- A blob is deleted by a DeleteBlob (section 31.4) or by expiry in a sweep
  (section 31.5). "Deleted" means what section 13.2 says:
  after the first sweep that follows the deletion, the bytes of the blob and its blob id
  are in none of the files of the database
  [test: tests/test_blobs.py::test_deleted_blob_is_in_no_file_of_the_database_after_the_sweep]. Section 13.3
  holds for blobs as well.
- The metrics of the blob frames carry no label that names an identity, as the other
  metrics [test: tests/test_metrics.py::test_metrics_count_the_blob_frames_without_an_identity]:

| Name                             | Kind    | Counts                                                      |
|----------------------------------|---------|-------------------------------------------------------------|
| `sotto_blobs_started_total`      | counter | StartBlob frames that made a blob                           |
| `sotto_blobs_completed_total`    | counter | Blobs whose last byte was stored                            |
| `sotto_blobs_deleted_total`      | counter | Blobs deleted by a DeleteBlob, with the label `by`, `uploader` or `recipient` |
| `sotto_blobs_expired_total`      | counter | Blobs deleted by expiry                                     |
| `sotto_blob_bytes_stored_total`  | counter | Bytes appended by PutBlob frames                            |
| `sotto_blob_bytes_fetched_total` | counter | Bytes sent in BlobData frames                               |
| `sotto_blob_bytes`               | gauge   | The stored lengths of all blobs the relay holds, added up   |

  A QUOTA_FULL counts in `sotto_limit_refusals_total` with the `kind` `blob_quota`, and the
  blob frames count in `sotto_frames_total` like every other frame.

## 32. The attachment

### 32.1 The fields

The `Attachment` message is listed in section 19.1. It is the `attachment` member of a
`Content` and travels as a message of the ratchet like a text.

| Field        | No. | Type   | Length or value                                                          |
|--------------|-----|--------|--------------------------------------------------------------------------|
| `blob_id`    | 1   | bytes  | 16, the `blob_id` of the StartBlob                                       |
| `key`        | 2   | bytes  | 16, the file key of section 29.1                                         |
| `size`       | 3   | uint32 | 0 to MAX_FILE_BYTES, the length of the file                              |
| `digest`     | 4   | bytes  | 32, the digest of the blob (section 29.6)                                |
| `media_type` | 5   | string | 0 to MAX_MEDIA_TYPE_BYTES, 127, bytes when sent: a media type as RFC 6838 names it, such as `image/jpeg`, or empty |
| `file_name`  | 6   | string | 0 to MAX_FILE_NAME_BYTES, 255, bytes when sent: the name of the file without any folder, or empty |
| `width`      | 7   | uint32 | The width of an image in pixels, 0 for a file that is not an image       |
| `height`     | 8   | uint32 | The height of an image in pixels, 0 for a file that is not an image      |
| `thumbnail`  | 9   | bytes  | 0 to MAX_THUMBNAIL_BYTES, 16384, bytes when sent: a JPEG image that shows the file small, or empty |
| `caption`    | 10  | string | 0 to MAX_CAPTION_BYTES, 4096, bytes of UTF-8 when sent                  |

- The uploader of the blob is the `sender` of the Deliver that carries the attachment,
  and no field names it, for the reason of section 16.7. A client fetches the blob with
  that `sender` as `uploader`
  [test: tests/client/test_files.py::test_file_of_four_pieces_is_received_byte_for_byte_and_its_blob_is_deleted].
- The key of a blob travels only in this message. A client sends no field beyond its
  limit [test: tests/client/test_envelope.py::test_attachment_beyond_a_limit_of_section_32_1_is_not_encoded].

### 32.2 The receiver's checks

After a message decrypted and its plaintext parsed as a `Content` with an `attachment`
(section 19.5), the result is BAD_CONTENT when `blob_id` is not 16 bytes, `key` is not 16
bytes, `digest` is not 32 bytes or `size` is more than MAX_FILE_BYTES
[test: tests/client/test_envelope.py::test_received_attachment_that_breaks_section_32_2_is_bad_content]. The strings and the
thumbnail have no limit of the receiver's own: the largest frame bounds them, as it bounds
a text (section 19.7).

Every value of an attachment is what the sender chose, and nothing binds the media type,
the name, the size of the image, the thumbnail or the caption to the file:

- A client MUST NOT use `file_name` as a path. It writes a received file only into a
  folder that it chose, under a name of at most MAX_FILE_NAME_BYTES bytes that holds no
  `/`, no `\`, no byte `00`, no C0 or C1 control character and no bidirectional control
  character (the characters that section 19.5 escapes) and that is neither empty nor `.`
  nor `..`. A name that breaks this is replaced by a name of the client's own
  [test: tests/client/test_received_files.py::test_name_that_breaks_section_32_2_is_replaced]
  [test: tests/client/test_received_files.py::test_name_within_section_32_2_is_kept]
  [test: tests/client/test_files.py::test_received_name_never_picks_a_folder_or_overwrites_a_file].
- A client never writes a received file over a file that is already there. When the
  name is taken, it writes the file under another name
  [test: tests/client/test_received_files.py::test_saved_file_takes_a_free_name_and_never_follows_a_link]
  [test: tests/client/test_files.py::test_received_name_never_picks_a_folder_or_overwrites_a_file].
- A client does not open or run a received file by itself, whatever its media type or
  name. It opens a file only when the user asks.
- The thumbnail can show another picture than the file. A thumbnail that does not decode
  as a JPEG image is not shown.
- `file_name`, `media_type` and `caption` are texts of the peer (section 19.5). The
  command-line client escapes their control characters as it does for a text
  [test: tests/client/test_cli.py::test_peer_file_name_and_caption_are_printed_with_control_characters_escaped].

### 32.3 Lengths

The longest attachment within the limits of section 32.1 makes a `Content` of 20965
bytes [test: tests/client/test_envelope.py::test_longest_attachment_is_the_content_of_section_32_3_and_decodes], far below the 65023 bytes of the longest text (section 19.7). It so fits a message
whatever the state of the session.

| Part                                                          | Bytes |
|---------------------------------------------------------------|-------|
| `blob_id` and `key`: each tag 1, length 1, 16                 | 36    |
| `size`: tag 1, value 4                                        | 5     |
| `digest`: tag 1, length 1, 32                                 | 34    |
| `media_type`: tag 1, length 1, 127                            | 129   |
| `file_name`: tag 1, length 2, 255                             | 258   |
| `width` and `height`: each tag 1, value at most 5             | 12    |
| `thumbnail`: tag 1, length 3, 16384                           | 16388 |
| `caption`: tag 1, length 2, 4096                              | 4099  |
| The `Attachment`                                              | 20961 |
| The `Content`: tag 1, length 3 and the `Attachment`           | 20965 |

## 33. The client and files

### 33.1 Before a file is sent

A client runs these checks before it makes a key or a blob. The first that fails ends
the sending with its result, and nothing else is done
[test: tests/client/test_files.py::test_checks_before_a_file_run_in_the_order_of_section_33_1]
[test: tests/client/test_files.py::test_file_too_large_is_not_sent_and_sends_no_blob_frame]
[test: tests/client/test_files.py::test_relay_that_announces_no_blobs_gets_no_blob_frame]:

1. The identity is a contact. Otherwise the result is NOT_A_CONTACT, as for a text
   (section 20.2, L1).
2. The relay announced the blob frames: the `blob_max_bytes` of the last LoggedIn the
   client received is not 0. Otherwise the result is FILES_UNSUPPORTED.
3. `size` is MAX_FILE_BYTES or less, and the B of the file (section 29.5) is that
   `blob_max_bytes` or less. Otherwise the result is FILE_TOO_LARGE.

The client fills `media_type`, `file_name`, `thumbnail` and `caption` within the limits of
section 32.1.

### 33.2 Sending

1. The checks of section 33.1.
2. The client reads the file once and makes the blob: a random blob id, file key and
   nonce, 16 bytes each, the blob of section 29 and its digest. In one transaction it
   saves an upload: the blob id, the contact, the bytes of the blob and the fields of the
   attachment. From then on it sends those bytes. It never reads the file again and never
   encrypts it a second time, so a file that changes or goes away does not change the
   upload [test: tests/client/test_files.py::test_client_restarted_in_the_middle_of_an_upload_and_of_a_download].
3. It sends StartBlob with the blob id, the contact and B. The BlobStored gives the
   stored length s.
4. While s is less than B, it sends PutBlob with `offset` s and the next bytes of the
   blob, BLOB_CHUNK_BYTES or fewer, and takes the `stored_length` of each BlobStored as
   the new s. A BlobStored with a smaller length than the client expected means that a
   PutBlob stored nothing, and the client goes on from that length
   [test: tests/client/test_files.py::test_upload_cut_in_the_middle_goes_on_from_the_stored_length].
5. When a BlobStored says that s is B, the client sends the message: the action SEND of
   section 20.3 with a `Content` whose `attachment` holds the fields of the upload, after
   START when the contact has no session (section 20.2, L1). The transaction of SEND also
   deletes the upload with its bytes [test: tests/client/test_files.py::test_file_of_four_pieces_is_received_byte_for_byte_and_its_blob_is_deleted].
6. The file counts as sent when the relay answers the Send of the message with Stored
   (section 22.2) [test: tests/client/test_files.py::test_file_of_four_pieces_is_received_byte_for_byte_and_its_blob_is_deleted].

The answers to the blob frames:

- RATE_LIMITED and STORAGE_FULL: the client sends the frame again after the wait of Back
  off (section 23.5).
- NOT_FOUND to a PutBlob: the blob expired or was lost at the relay. The client goes back
  to step 3, and the upload starts again from 0 with the same bytes and the same blob id
  [test: tests/client/test_files.py::test_put_answered_not_found_starts_the_upload_again]
  [test: tests/client/test_files.py::test_upload_whose_blob_expired_starts_again_from_0_with_the_same_blob].
- UNKNOWN_RECIPIENT, QUOTA_FULL, BLOB_TOO_LARGE or a code the client does not know, and a
  START that fails: the file is not sent. The client deletes the upload, sends DeleteBlob
  for the blob and reports the result. No message is sent
  [test: tests/client/test_files.py::test_refused_upload_is_not_sent_and_its_blob_is_deleted].
- A user who cancels the sending before step 5 ends it in the same way, without a result.
- When the Send of the message of a file ends with an Error whose action is Stop
  (section 22.2), the client sends DeleteBlob for its blob
  [test: tests/client/test_files.py::test_refused_message_of_a_file_deletes_its_blob].
- While a frame waits after RATE_LIMITED or STORAGE_FULL, the client SHOULD hold back its
  StartBlob and PutBlob frames as well, as section 23.5 says for the other frames.
- After an Error whose action is Back off, the BlobStored answers to the PutBlob frames
  that the client sent behind the refused one say that they stored nothing. The client
  sends nothing for them: after the wait it sends the refused frame again and goes on
  from its answer.
- A BlobStored whose `stored_length` is more than B ends the upload as not sent with the
  result BAD_BLOB, and the client sends DeleteBlob
  [test: tests/client/test_files.py::test_stored_length_above_the_blob_ends_the_upload_as_bad_blob].

A client saves every DeleteBlob that it has to send and sends it again after every login
until the relay answered a frame that the client sent after it on one connection: the
relay handles the frames of a connection in order (section 7.4), and a DeleteBlob has no
answer of its own
[test: tests/client/test_files.py::test_delete_blob_is_sent_again_after_a_login_until_a_later_frame_is_answered].

### 33.3 Receiving

1. A Deliver whose `Content` holds an `attachment` is an ACCEPT or an ACCEPT-NEW of
   section 20.3: the client saves the attachment with the message in the transaction of
   section 22.2 and acks after the commit. It shows the attachment at once: the
   thumbnail, the name, the size and the caption [test: tests/client/test_files.py::test_file_of_four_pieces_is_received_byte_for_byte_and_its_blob_is_deleted]
   [test: tests/client/test_cli.py::test_file_sent_by_one_process_is_saved_by_the_chat_of_the_other].
2. The client downloads the blob by itself or when the user asks; which is its own
   choice. A download holds the bytes of the blob received so far, h of them. The client
   sends FetchBlob with the `sender` of the Deliver as `uploader`, the `blob_id`, `offset`
   h and a `length` of BLOB_CHUNK_BYTES or fewer. Several FetchBlob frames on the way ask
   for ranges that follow each other without a gap. The client writes the `data` of each
   BlobData at h and saves the new h together with those bytes; it counts no byte that
   it has not saved [test: tests/client/test_files.py::test_download_cut_in_the_middle_goes_on_from_the_bytes_it_holds].
3. A BlobData ends the download with BAD_BLOB when its `blob_id`, `uploader` or `offset`
   is not that of the FetchBlob it answers (section 7.4), when its `offset` is not h,
   when its `data` is longer than the `length` asked for or would end past B, and when
   its `data` is shorter than asked for although it ends before B
   [test: tests/client/test_files.py::test_altered_or_truncated_blob_could_not_be_received_and_writes_nothing].
4. When h is B, the client opens the blob (section 29.7). When the opening succeeds, it
   saves the file and deletes the downloaded bytes in one transaction, and then sends
   DeleteBlob. The file counts as received [test: tests/client/test_files.py::test_file_of_four_pieces_is_received_byte_for_byte_and_its_blob_is_deleted].
5. With BAD_BLOB the client deletes the downloaded bytes, reports that the file could not
   be received and sends DeleteBlob
   [test: tests/client/test_files.py::test_altered_or_truncated_blob_could_not_be_received_and_writes_nothing].
6. With NOT_FOUND the result is BLOB_GONE: the blob expired, was deleted or was never
   complete. The client deletes the downloaded bytes and reports that the file is not
   available [test: tests/client/test_files.py::test_expired_blob_is_not_available_and_its_message_stays].

An attachment whose file fails is still a message: its thumbnail and caption stay
[test: tests/client/test_files.py::test_expired_blob_is_not_available_and_its_message_stays].

The client of this repository writes the file before the transaction of step 4. A client
that stops between the two opens the blob again at its next start and writes it a second
time under a free name: the file is never lost, and it can be there twice. A file that
cannot be written, into a full disk or a folder it may not write, leaves no part of it
behind and keeps the downloaded bytes, and the next login opens the blob again
[test: tests/client/test_files.py::test_file_that_cannot_be_written_keeps_its_bytes_for_the_next_login].

### 33.4 Resume

An upload and a download go on from where they stopped. Neither starts again from 0
while the relay holds the blob
[test: tests/client/test_files.py::test_upload_cut_in_the_middle_goes_on_from_the_stored_length]
[test: tests/client/test_files.py::test_download_cut_in_the_middle_goes_on_from_the_bytes_it_holds]
[test: tests/client/test_files.py::test_relay_restarted_in_the_middle_of_an_upload_and_of_a_download]
[test: tests/client/test_files.py::test_client_restarted_in_the_middle_of_an_upload_and_of_a_download]
[test: tests/client/test_files.py::test_file_half_uploaded_before_the_restart_is_sent_and_received_whole].

| What happened                         | Upload                                                               | Download                                   |
|---------------------------------------|----------------------------------------------------------------------|--------------------------------------------|
| The connection ended                  | After the next LoggedIn and the steps of section 23.3: StartBlob for every upload, then PutBlob from the stored length of its answer | After the next LoggedIn: FetchBlob from h for every download |
| The relay restarted                   | As above. The relay keeps every byte that a BlobStored reported      | As above                                   |
| The client restarted                  | As above: the uploads are in the store                               | As above: the downloads are in the store   |
| The blob expired or was lost         | NOT_FOUND to PutBlob, or a StartBlob answered with 0: the upload starts from 0 with the same bytes | NOT_FOUND: BLOB_GONE |
| A Back off code                       | The same frame after the wait (section 23.5)                         | No such code for a FetchBlob               |
| A LoggedIn with a `blob_max_bytes` of 0, or below B | Not sent: FILES_UNSUPPORTED or FILE_TOO_LARGE. The client deletes the upload | Ends with FILES_UNSUPPORTED; the downloaded bytes are deleted |

A LoggedIn with a `blob_max_bytes` of 0 ends the transfers as the last row says
[test: tests/client/test_files.py::test_transfers_end_when_a_later_login_announces_no_blobs]. A download ends with
FILES_UNSUPPORTED only on a `blob_max_bytes` of 0: a lower one bounds the blobs that the
relay takes, not those it holds.

An upload ends with the file sent or not sent with a result, and a download with the
file received, BAD_BLOB, BLOB_GONE or FILES_UNSUPPORTED. While the client has no
connection, a transfer waits and has not failed.

### 33.5 What the user sees

| State                  | Shown                                                                          |
|------------------------|--------------------------------------------------------------------------------|
| Sending                | The progress: the `stored_length` of the last BlobStored out of B              |
| Sent                   | The file, once the message got Stored                                          |
| Not sent               | The result: FILES_UNSUPPORTED, FILE_TOO_LARGE, a code of section 31.6 or the result of a START that failed; or that the user cancelled. The user can send the file again: that is a new blob with a new blob id, file key and nonce |
| Offered                | The attachment without the file                                                |
| Receiving              | The progress: h out of B                                                       |
| Received               | The file                                                                       |
| Could not be received  | BAD_BLOB                                                                       |
| Not available          | BLOB_GONE                                                                      |

### 33.6 Constants and local results

| Name                  | Value     | Unit  | Meaning                                                           |
|-----------------------|-----------|-------|-------------------------------------------------------------------|
| MAX_FILE_BYTES        | 104857600 | bytes | The largest file, 100 MiB (section 29.2)                          |
| FILE_PADDING_MIN      | 256       | bytes | The smallest padded length (section 29.2)                         |
| STREAM_CHUNK_BYTES    | 65536     | bytes | The plaintext of one chunk of the blob cipher (section 29.4)      |
| MAX_MEDIA_TYPE_BYTES  | 127       | bytes | The longest `media_type` a client sends                           |
| MAX_FILE_NAME_BYTES   | 255       | bytes | The longest `file_name` a client sends                            |
| MAX_THUMBNAIL_BYTES   | 16384     | bytes | The longest `thumbnail` a client sends                            |
| MAX_CAPTION_BYTES     | 4096      | bytes | The longest `caption` a client sends                              |

MAX_FILE_BYTES, FILE_PADDING_MIN and STREAM_CHUNK_BYTES are constants of end-to-end
protocol version 1: two clients that differ in one of them disagree on which blobs open.
The other four bound what a client sends.

| Name              | Where                    | Meaning                                                                  |
|-------------------|--------------------------|--------------------------------------------------------------------------|
| FILES_UNSUPPORTED | Section 33.1             | The relay announced no blob frames                                       |
| FILE_TOO_LARGE    | Section 33.1             | The file is longer than MAX_FILE_BYTES, or its blob is longer than the relay accepts |
| BAD_BLOB          | Sections 29.7, 33.2 and 33.3 | The fetched bytes are not the blob of the attachment, or the relay reported a stored length above the length of the blob |
| BLOB_GONE         | Section 33.3             | The relay holds no complete blob of the attachment for the client        |

### 33.7 The store

A client that implements part 3 keeps, besides what section 22.1 lists, its uploads with
the bytes of their blobs until their message is committed or they are given up, its
downloads with the bytes received so far, the attachments of the message log and the
files it received [test: tests/client/test_client_store.py::test_store_holds_what_section_22_1_lists]. Section 22.3 holds for what this part deletes. A received file is kept
in readable form, like the message log (threat model, "A thief of the device or of the
data directory").

## 34. The test vectors of the blob cipher

The vectors of part 3 are the file `vectors/blob.json`, in the schema of section 15.2,
written by `scripts/generate_vectors.py` with the code of part 3
[test: tests/crypto/test_blob_vectors.py::test_vector_file_follows_the_schema]
[test: tests/crypto/test_blob_vectors.py::test_vectors_use_the_operations_and_keys_of_the_document]. `size`, `padded_length`
and `blob_length` are numbers, `chunk_nonces` is an array of hex strings, and every other
value is a hex string.

| Operation      | Rule             | `inputs`                                | `intermediates`                            | `outputs`                        | `error`  |
|----------------|------------------|-----------------------------------------|--------------------------------------------|----------------------------------|----------|
| `blob-length`  | 29.2, 29.5       | `size`                                  |                                            | `padded_length`, `blob_length`   |          |
| `blob-encrypt` | 29.1 to 29.6     | `file`, `file_key`, `nonce`             | `padded_length`, `payload_key`, `chunk_nonces` | `blob`, `digest`             |          |
| `blob-open`    | 29.7             | `blob`, `file_key`, `size`, `digest`    | `payload_key`                              | `file`                           | BAD_BLOB |

- `blob-length`: P and B of a size. The sizes include 0, 255, 256, 257, 65536, 65537,
  2^E + 1 for every E from 8 to 26, MAX_FILE_BYTES and MAX_FILE_BYTES + 1.
- `blob-encrypt`: `chunk_nonces` are the 12-byte nonces of section 29.4 in the order of
  the chunks. The files include an empty file, a file of one chunk, a file whose padded
  length is exactly 65536 bytes and a file of two chunks.
- `blob-open`: a positive vector opens the blob of the `blob-encrypt` vector with the same
  name after the operation, and its `file` is the `file` of that vector
  [test: tests/crypto/test_blob_vectors.py::test_each_positive_open_opens_the_blob_of_its_encryption].
- A negative vector of `blob-open` records no intermediate. The negative cases: one byte
  changed in the nonce, in a ciphertext and in a tag; two chunks swapped; the last chunk
  left out; a blob of two chunks whose first chunk was sealed as the last; a padding
  byte that is not `00`, sealed under its key so that every tag verifies. Each of these
  carries the digest of its own bytes, so that the failure comes from step 4 or 5 of
  section 29.7 and not from the digest. Three more fail earlier: one byte appended, the
  digest of another blob, and a `size` with another padded length
  [test: tests/crypto/test_blob_vectors.py::test_vectors_cover_the_sizes_files_and_cases_of_section_34]
  [test: tests/crypto/test_blob_vectors.py::test_negative_vector_at_the_chunks_has_its_length_and_its_own_digest].

## 35. The profile

### 35.1 What part 4 is

Part 4 specifies the profile of an identity: a display name and an avatar, a picture,
that a client sends to its contacts so that they can show them. It adds one member to
the `Content` oneof, `profile`, and no key, no frame and no rule of the relay.

- A profile travels as a message of the ratchet, like a text (sections 17 and 18). The
  relay sees a message of the usual length and nothing of the profile.
- The avatar is an `Attachment` of part 3: the picture goes as a blob to each contact,
  and the message carries its key (sections 28 to 33).
- The receiver keeps the latest profile of each contact and nothing older. A profile is
  no message of the chat (section 36.3).
- The name a contact sends is that contact's own choice. The name the user gave a
  contact wins wherever the client shows one (section 36.4).

Part 4 changes neither version number of section 1.3: `profile` is a new member of the
`Content` oneof, which a client of version 1 that does not implement part 4 reports as
UNKNOWN_CONTENT (sections 14.2 and 36.6).

The command-line client of this repository implements part 4. Every rule of part 4
carries a citation like the rules of parts 1 to 3 (section 1.2).

### 35.2 The fields

The `Profile` message is listed in section 19.1. It is the `profile` member of a
`Content`.

| Field    | No. | Type       | Length or value                                                          |
|----------|-----|------------|--------------------------------------------------------------------------|
| `name`   | 1   | string     | 0 to MAX_PROFILE_NAME_BYTES, 256, bytes of UTF-8 without a control character, or empty |
| `avatar` | 2   | Attachment | Present or absent: the picture, a file of part 3 with the limits below   |

The control characters are those that the command-line client escapes in a text
(section 19.5): U+0000 to U+001F, U+007F to U+009F, U+061C, U+200E, U+200F, U+202A to
U+202E, U+2066 to U+2069, U+2028 and U+2029.

The fields of `avatar` follow section 32.1, with these limits of their own:

| Field        | Value when sent                                                                  |
|--------------|----------------------------------------------------------------------------------|
| `size`       | 0 to MAX_AVATAR_BYTES, 1048576                                                   |
| `media_type` | `image/jpeg` or `image/png`, the type of the bytes of the picture, spelled so    |
| `file_name`  | Empty                                                                            |
| `caption`    | Empty                                                                            |
| `width`, `height` | The size of the picture in pixels, or 0 when the client does not know it   |
| `thumbnail`  | A small JPEG of the picture, 0 to MAX_THUMBNAIL_BYTES bytes; SHOULD be present   |

- The media type is read from the first bytes of the picture, not from a file name: a
  JPEG starts with `ff d8 ff` and a PNG with `89 50 4e 47 0d 0a 1a 0a`
  [test: tests/client/test_envelope.py::test_avatar_media_type_is_read_from_the_first_bytes]. A
  picture of another kind is not sent: the result is NOT_AN_IMAGE. A picture of more than
  MAX_AVATAR_BYTES is not sent: the result is AVATAR_TOO_LARGE. A name that breaks the
  rule of the table is not sent: the result is BAD_PROFILE_NAME
  [test: tests/client/test_envelope.py::test_profile_beyond_a_limit_of_section_35_2_is_not_encoded]
  [test: tests/client/test_cli.py::test_profile_set_refuses_an_avatar_too_large_or_not_an_image].
- The thumbnail travels inside the message, so it outlives the blob; it is what a client
  shows of the avatar until the picture is downloaded, and when it never is
  (section 36.5).
- A `Profile` without `avatar` has no avatar, and one with an empty `name` has no name.
  A `Profile` with neither is the empty profile: it clears the profile at the receiver
  (section 36.3). A `Content` whose `profile` is the empty `Profile` is the two bytes
  `1a 00` before padding [test: tests/client/test_envelope.py::test_profile_encodes_and_decodes_with_and_without_an_avatar].

### 35.3 The receiver's checks

After a message decrypted and its plaintext parsed as a `Content` with a `profile`
(section 19.5), the result is BAD_CONTENT when
[test: tests/client/test_envelope.py::test_received_profile_that_breaks_section_35_3_is_bad_content]:

- `name` is longer than MAX_PROFILE_NAME_BYTES bytes or holds a control character of
  section 35.2;
- `avatar` is present and breaks a check of section 32.2, or its `size` is more than
  MAX_AVATAR_BYTES, or its `media_type` is neither `image/jpeg` nor `image/png`.

A profile with BAD_CONTENT changes nothing that the client keeps of the contact's
profile. The other fields of `avatar` are not checked, and a client never shows its
`file_name` or `caption`. A field of `Profile` that the client does not know is ignored,
as everywhere in this protocol (section 19.4)
[test: tests/client/test_envelope.py::test_profile_encodes_and_decodes_with_and_without_an_avatar].

### 35.4 Lengths

The longest profile within the limits of section 35.2 makes a `Content` of 16753 bytes
[test: tests/client/test_envelope.py::test_longest_profile_is_the_content_of_section_35_4_and_decodes],
below the 65023 bytes of the longest text (section 19.7), so it fits a message whatever
the state of the session.

| Part                                                              | Bytes |
|-------------------------------------------------------------------|-------|
| `name`: tag 1, length 2, 256                                      | 259   |
| `avatar`: `blob_id` and `key` 36, `size` 4, `digest` 34, `media_type` 12, `width` and `height` 12, `thumbnail` 16388 | 16486 |
| `avatar` as a field: tag 1, length 3                              | 16490 |
| The `Profile`                                                     | 16749 |
| The `Content`: tag 1, length 3 and the `Profile`                  | 16753 |

## 36. The client and the profile

### 36.1 What a client keeps

A client that implements part 4 keeps, besides what sections 22.1 and 33.7 list
[test: tests/client/test_client_store.py::test_store_holds_what_section_22_1_lists]:

- its own profile: the name, the picture and its media type;
- for every contact the latest profile it accepted: the name, the avatar attachment and,
  once downloaded, the picture;
- the contacts it owes its profile (section 36.2), and the upload of the avatar of each.

The avatar of a received profile is no attachment of the message log. A contact that is
removed takes its profile with it (section 20.6).

### 36.2 Sending

A client owes its profile to a contact, and saves that in the transaction that causes it
[test: tests/client/test_profiles.py::test_profile_change_is_owed_to_every_contact_with_a_session]
[test: tests/client/test_profiles.py::test_new_session_gets_the_profile_once_in_both_directions]
[test: tests/client/test_profiles.py::test_empty_profile_is_not_sent_into_a_new_session]:

- When the user changes or clears the profile: to every contact with a session. A
  contact without a session gets the profile with its first session.
- When a session enters the list of a contact (sections 20.1 and 20.3): START, as
  initiator, and ACCEPT-NEW, as responder. So both sides of a new session send their
  profiles once, and a reset by either side (section 20.6) sends both again. A client
  whose profile is empty sends none into a new session.

A client sends what it owes as soon as it is logged in, and its last profile only:

1. Without an avatar, it sends at once a message whose `Content` is the `profile`: the
   action SEND of section 20.3, whose transaction also clears the debt.
2. With an avatar, it uploads the picture to the contact as a new blob by section 33.2,
   steps 2 to 4: a new blob id, file key and nonce for every contact, since a blob is
   kept for one recipient (section 31.1). When the blob is complete, the message carries
   the `profile` with the name that is current at that moment and the avatar of the
   upload; its transaction deletes the upload and clears the debt
   [test: tests/client/test_profiles.py::test_avatar_reaches_the_contact_whole_and_its_blob_is_deleted].
3. A relay that announces no blob frames, or whose `blob_max_bytes` is below the blob of
   the picture, gets the profile without the avatar
   [test: tests/client/test_profiles.py::test_relay_without_blobs_gets_the_profile_without_the_avatar].
4. A change while an avatar upload is on its way gives the upload up: the client deletes
   it and sends DeleteBlob for its blob (section 33.2), then owes the new profile
   [test: tests/client/test_profiles.py::test_profile_change_is_owed_to_every_contact_with_a_session].
5. An upload refused with an Error whose action is Stop, or a START that fails, ends the
   debt without a message, as a file that is not sent (section 33.2). The next change or
   the next new session sends the profile again.

### 36.3 Receiving

A Deliver whose `Content` holds a `profile` that passes section 35.3 is an ACCEPT or an
ACCEPT-NEW of section 20.3. In its transaction (section 22.2) the client
[test: tests/client/test_profiles.py::test_received_profile_replaces_the_earlier_one_and_is_no_message]
[test: tests/client/test_profiles.py::test_cleared_profile_leaves_nothing_of_the_contact]:

1. deletes the earlier profile of the contact with its avatar and picture. When the
   earlier avatar was not downloaded yet, it saves the DeleteBlob of its blob, and a
   download of it that is on its way ends without a result
   [test: tests/client/test_profiles.py::test_newer_profile_takes_the_place_of_an_avatar_on_its_way];
2. keeps the new profile, unless it is the empty profile, which leaves nothing;
3. logs no message: a profile is not shown as a message of the chat, never counts as an
   unread message and does not move the chat in a list of chats.

The client downloads the avatar by itself by section 33.3, steps 2 to 6, without the
user's request: it is at most MAX_AVATAR_BYTES. It writes no file: the picture stays in
the store. When the opened picture does not start with the bytes of its media type
(section 35.2), the avatar could not be received with the result NOT_AN_IMAGE, and the
client sends DeleteBlob for its blob
[test: tests/client/test_profiles.py::test_avatar_reaches_the_contact_whole_and_its_blob_is_deleted]
[test: tests/client/test_profiles.py::test_avatar_that_is_no_image_of_its_media_type_is_not_kept].

"The latest" is the profile of the last message accepted, in the order the client
accepted them.

### 36.4 What the user sees

- Where the user gave a contact a name, that name is the name of the contact: in the
  list of contacts, the list of chats, the chat and a notification. The name the contact
  sent MAY be shown next to it, marked as the contact's own
  [test: tests/client/test_cli.py::test_contacts_show_the_name_a_contact_sent_next_to_the_local_one].
- A client MAY show the sent name of a contact that has no local name, marked the same
  way. A sent name proves nothing: any contact can send any name, the name of another
  contact included.
- The name is a text of the peer. The command-line client prints it through the escape
  of section 19.5 [test: tests/client/test_cli.py::test_peer_profile_name_is_printed_with_control_characters_escaped].
- The avatar is shown when its picture decodes as an image of its media type, else the
  thumbnail when it decodes as a JPEG image, else none. An empty profile, or a profile
  without an avatar, shows the client's own drawing for a contact without a picture.
- A client MAY tell the user once that a contact changed its profile. The command-line
  client prints one line in the chat when a profile arrives
  [test: tests/client/test_cli.py::test_chat_prints_one_line_when_the_contact_profile_changes].

### 36.5 A lost avatar

The blob of an avatar lives as long as the blob of any file, BLOB_TTL_SECONDS after its
last write, and outlives the message that names it by about a week (section 31.5).
When the download ends with BLOB_GONE, the profile stays with its name and its
thumbnail, and its avatar is not available
[test: tests/client/test_profiles.py::test_avatar_whose_blob_is_gone_is_not_available_and_the_name_stays].
The picture comes again with the next change of the contact's profile or the next new
session with the contact, which a reset by either side makes. No message asks a contact
for its profile.

### 36.6 An older client

A client of version 1 that does not implement part 4 parses a profile as a `Content`
without a member it knows: the result is UNKNOWN_CONTENT (section 19.5). It keeps the
new ratchet state and the seen id, acks the message and shows nothing
[test: tests/client/test_envelope.py::test_profile_is_unknown_content_to_a_client_without_part_4]
[test: tests/client/test_cli.py::test_unknown_content_prints_nothing]. The blob of the
avatar stays at the relay until it expires (section 31.5).

### 36.7 Constants and local results

| Name                   | Value   | Unit  | Meaning                                                 |
|------------------------|---------|-------|---------------------------------------------------------|
| MAX_PROFILE_NAME_BYTES | 256     | bytes | The longest name, in UTF-8: 64 characters of 4 bytes    |
| MAX_AVATAR_BYTES       | 1048576 | bytes | The largest picture of an avatar, 1 MiB                 |

Both bound what a client sends and what a receiver accepts (section 35.3).

| Name             | Where        | Meaning                                                                  |
|------------------|--------------|--------------------------------------------------------------------------|
| BAD_PROFILE_NAME | Section 35.2 | A name to send is longer than MAX_PROFILE_NAME_BYTES or holds a control character |
| AVATAR_TOO_LARGE | Section 35.2 | A picture to send is longer than MAX_AVATAR_BYTES                        |
| NOT_AN_IMAGE     | Sections 35.2 and 36.3 | The bytes are neither a JPEG nor a PNG picture, or not one of the media type of the avatar |

## 37. The test vectors of the profile

The vectors of part 4 are the file `vectors/profile.json`, in the schema of section 15.2,
written by `scripts/generate_vectors.py` with the code of part 4
[test: tests/crypto/test_profile_vectors.py::test_vector_file_follows_the_schema]
[test: tests/crypto/test_profile_vectors.py::test_vectors_use_the_operations_and_keys_of_the_document]
[test: tests/crypto/test_profile_vectors.py::test_positive_vectors_replay_byte_for_byte]
[test: tests/crypto/test_profile_vectors.py::test_negative_vectors_raise_their_named_error].
`name` and `media_type` are JSON strings, `size`, `width` and `height` are numbers,
`avatar` is an object of the fields of an `Attachment` that are set, and every other
value is a hex string.

| Operation           | Rule       | `inputs`             | `intermediates` | `outputs`             | `error`                    |
|---------------------|------------|----------------------|-----------------|-----------------------|----------------------------|
| `profile-encode`    | 35.2, 19.6 | `name`, `avatar`     | `content`       | `plaintext`           | BAD_PROFILE_NAME, AVATAR_TOO_LARGE, NOT_AN_IMAGE |
| `profile-decode`    | 35.3, 19.6 | `plaintext`          | `content`       | `name`, `avatar`      | BAD_CONTENT                |
| `avatar-media-type` | 35.2       | `image`              |                 | `media_type`          | NOT_AN_IMAGE               |

- `profile-encode`: `avatar` is absent for a profile without one. `content` is the
  serialized `Content` and `plaintext` the padded plaintext of section 19.6. The cases:
  a name alone, a name with a JPEG avatar and its thumbnail, a PNG avatar without a name
  or a thumbnail, the empty profile, a name of MAX_PROFILE_NAME_BYTES bytes, and the
  longest profile of section 35.4. The negative cases: a name of
  MAX_PROFILE_NAME_BYTES + 1 bytes, a name with U+202E, an avatar of MAX_AVATAR_BYTES + 1
  bytes and an avatar of the media type `image/gif`.
- `profile-decode`: `content` is the bytes in front of the padding, and `outputs` hold
  `avatar` only when it is present. The positive cases are the plaintexts of the
  `profile-encode` vectors of the same name after the operation, and a profile with a
  field that the client does not know. The negative cases: a name of
  MAX_PROFILE_NAME_BYTES + 1 bytes; a name that is not UTF-8; a name with each kind of
  control character of section 35.2 (U+0000, U+007F, U+0085, U+202E, U+2028); an avatar
  whose `blob_id`, `key` or `digest` breaks its length; an avatar of MAX_AVATAR_BYTES + 1 bytes; and avatars of
  the media types `image/gif`, `IMAGE/JPEG`, `image/jpeg; q=1` and the empty one
  [test: tests/crypto/test_profile_vectors.py::test_vectors_cover_the_cases_of_section_37].
- `avatar-media-type`: the first bytes of a picture. The cases: a JPEG, a PNG, a GIF,
  no bytes, and the first two bytes of a JPEG.
- A negative vector records no intermediate.

## Appendix A. One key agreement and two messages in hex

This appendix holds one run of the protocol written out in hex, every value in the order
in which sections 16 to 19 compute it. The values are taken from the vector files of
sections 15.6 and 15.7, so that the text and the vectors cannot differ
[test: tests/crypto/test_ratchet_vectors.py::test_appendix_a_is_taken_from_the_vector_files].
Each value is named by its vector, its object and its key; a long value is broken into
lines of 32 bytes, and the two prekey ids are numbers.

The key agreement between the initiator A and the responder B with a one-time prekey
(section 16): the keys of A, the keys of B with the signatures of its bundle, the two
signed strings, DH1 to DH4, the input key material, SK and the 161 bytes of the session
associated data.

```
x3dh-initiate-with-a-one-time-prekey inputs.identity_key
  ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1
x3dh-initiate-with-a-one-time-prekey inputs.identity_dh_private_key
  3131313131313131313131313131313131313131313131313131313131313131
x3dh-respond-with-a-one-time-prekey inputs.identity_dh_key
  04f5f29162c31a8defa18e6e742224ee806fc1718a278be859ba5620402b8f3a
x3dh-initiate-with-a-one-time-prekey inputs.ephemeral_private_key
  3232323232323232323232323232323232323232323232323232323232323232
x3dh-respond-with-a-one-time-prekey inputs.ephemeral_key
  59d9225473451efffe6b36dbcaefdbf7b1895de62084509a7f5b58bf01d06418
x3dh-respond-with-a-one-time-prekey inputs.identity_key
  8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
x3dh-respond-with-a-one-time-prekey inputs.identity_dh_private_key
  1111111111111111111111111111111111111111111111111111111111111111
x3dh-initiate-with-a-one-time-prekey inputs.identity_dh_key
  7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13
x3dh-initiate-with-a-one-time-prekey inputs.identity_dh_signature
  75544e6d894bec2c438c747fd0305e6193611aa4c118baecde09ee521f8bb7c8
  3a2d4f61513cc382ac7a16c862d0d9520157a1f56179b18bd3481f50ea6e510e
x3dh-respond-with-a-one-time-prekey inputs.signed_prekey_private_key
  1212121212121212121212121212121212121212121212121212121212121212
x3dh-initiate-with-a-one-time-prekey inputs.signed_prekey_key
  052a50773ac8d91773f2dc9662e12f0defe915e415b8a1c8e20a5a3d6ab2b843
x3dh-initiate-with-a-one-time-prekey inputs.signed_prekey_signature
  7ac73331f4eb7c8377c639f83fa454d1661d106263622b96ae6901091b42bb41
  376ad531dce6d2295b1c350bbb42a4031a046e4b29a8ba64270233e97a91e907
x3dh-respond-with-a-one-time-prekey inputs.one_time_prekey_private_key
  1313131313131313131313131313131313131313131313131313131313131313
x3dh-initiate-with-a-one-time-prekey inputs.one_time_prekey_key
  197fc2c567dc03ee2aadf0ed86681dac24daa76e83ca555875dd3be7376e5306
x3dh-initiate-with-a-one-time-prekey intermediates.identity_dh_string
  736f74746f2f31206964656e746974792d6468008a88e3dd7409f195fd52db2d
  3cba5d72ca6709bf1d94121bf3748801b40f6f5c7b4e909bbe7ffe44c465a220
  037d608ee35897d31ef972f07f74892cb0f73f13
x3dh-initiate-with-a-one-time-prekey intermediates.signed_prekey_string
  736f74746f2f31207369676e65642d7072656b6579008a88e3dd7409f195fd52
  db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c052a50773ac8d91773f2
  dc9662e12f0defe915e415b8a1c8e20a5a3d6ab2b843
x3dh-initiate-with-a-one-time-prekey intermediates.dh1
  d61c769f51f4ef4d2ccd152d0bebf2b146baf820e2332a7399848906b5d87a49
x3dh-initiate-with-a-one-time-prekey intermediates.dh2
  2d57023133fd4411f3c2663f1a4ac1f36d5a2e97861023606d09aa7a431af676
x3dh-initiate-with-a-one-time-prekey intermediates.dh3
  bb7fe367bd6607a50eedf8c32c1accd4f8a5800dc7bdc431fe35f2e3caab9e42
x3dh-initiate-with-a-one-time-prekey intermediates.dh4
  12b8310a65a694bf345962dfd28ba47be3fee735d0a57c63fb506da80cd88001
x3dh-initiate-with-a-one-time-prekey intermediates.input_key_material
  ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  d61c769f51f4ef4d2ccd152d0bebf2b146baf820e2332a7399848906b5d87a49
  2d57023133fd4411f3c2663f1a4ac1f36d5a2e97861023606d09aa7a431af676
  bb7fe367bd6607a50eedf8c32c1accd4f8a5800dc7bdc431fe35f2e3caab9e42
  12b8310a65a694bf345962dfd28ba47be3fee735d0a57c63fb506da80cd88001
x3dh-initiate-with-a-one-time-prekey outputs.sk
  44df5354681736f7e0f3e7b1236263c07e0b4458ee6d5acf8b209a33fcd613ad
x3dh-initiate-with-a-one-time-prekey outputs.session_associated_data
  01ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737
  d104f5f29162c31a8defa18e6e742224ee806fc1718a278be859ba5620402b8f
  3a8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f
  5c7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f
  1359d9225473451efffe6b36dbcaefdbf7b1895de62084509a7f5b58bf01d064
  18
```

The first message of the initiator (sections 17.3, 17.6 and 18): its ratchet key pair, the
Diffie-Hellman output, the root key and the chain key, the message key, the 40 bytes of
the header, the message id, the nonce, the padded plaintext, the 217 bytes of the
associated data and the bytes of the `ciphertext` field, then the fields of its initial
header (section 16.7). The chain key of the message is the chain key of the
initialisation.

```
ratchet-init-initiator-with-a-one-time-prekey inputs.ratchet_private_key
  5050505050505050505050505050505050505050505050505050505050505050
ratchet-init-initiator-with-a-one-time-prekey intermediates.ratchet_key
  ef38b4abd14b0a919cbe6839f6185b97d32607bee359c6c53c12cc7597867d59
ratchet-init-initiator-with-a-one-time-prekey intermediates.dh
  1292b40f5316616960cfa35969655da0e3f02ec4c9b6018e316e678dfb106b18
ratchet-init-initiator-with-a-one-time-prekey intermediates.root_key
  75fed0c88f85961cba32ec90c683343a431ccb89f3acd158df6a09f73f1dd5f5
ratchet-init-initiator-with-a-one-time-prekey intermediates.chain_key
  74fbfa0a0b6865361f7e3976c705044463bc8e8a91a91bdd01ab64827b2fd3b7
ratchet-encrypt-i0 intermediates.message_key
  07552617906c9a3ecb017f635e5c44e579f714c66a5f6763cb2311cc5f56167d
ratchet-encrypt-i0 intermediates.header
  ef38b4abd14b0a919cbe6839f6185b97d32607bee359c6c53c12cc7597867d59
  0000000000000000
ratchet-encrypt-i0 inputs.message_id
  41414141414141414141414141414141
ratchet-encrypt-i0 inputs.nonce
  818181818181818181818181
ratchet-encrypt-i0 inputs.padded_plaintext
  0a0a6d6573736167652069308000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
ratchet-encrypt-i0 intermediates.associated_data
  01ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737
  d104f5f29162c31a8defa18e6e742224ee806fc1718a278be859ba5620402b8f
  3a8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f
  5c7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f
  1359d9225473451efffe6b36dbcaefdbf7b1895de62084509a7f5b58bf01d064
  1841414141414141414141414141414141ef38b4abd14b0a919cbe6839f6185b
  97d32607bee359c6c53c12cc7597867d590000000000000000
ratchet-encrypt-i0 outputs.ciphertext
  8181818181818181818181813fd253b39f0190934e2ae4347e1b90651a299b67
  a738fb370af6992d39c4b15aceb6434cdf1720ca87f0631225a9c41dc379ff24
  fa40f9274f208a042e0f6f7563258c8c0fc1e63a784bd5928f8154f575a930eb
  229888efb6a3701e40a5a3bc868db9efc959ea5a3a4f28db878d5cb7723aa784
  ad6c26f0ed8985a953d0b4b698080f70ee4e82249b4b518ed948d488413e659a
  052a53e024fd8abf0adfa93fa2c38dfaecd17f66bc3e3de1ffc9c42d1630941e
  8cf238feebab69c93f0d6a393dfad82c95b52b1fed4192fa5e1d807aa05429c4
  48337f27118152bc3dc45bc7989fc9a0a13a38847b812f6ef67fa038bd1f8a8f
  b618f0f4c5efc227f2e3ef5c774b5a5a0d67a52ddfcd65a73a2fe764
x3dh-respond-with-a-one-time-prekey inputs.identity_dh_key
  04f5f29162c31a8defa18e6e742224ee806fc1718a278be859ba5620402b8f3a
x3dh-respond-with-a-one-time-prekey inputs.identity_dh_signature
  2df31e115b6bd119f507d1fc769325cd171ec5f1b897ba1064eb53403556c56a
  3d675e46dfe313e0dd8e98d0f67cbd27e95c0f6e1ccba3fc7101cc4b89456d08
x3dh-respond-with-a-one-time-prekey inputs.ephemeral_key
  59d9225473451efffe6b36dbcaefdbf7b1895de62084509a7f5b58bf01d06418
x3dh-respond-with-a-one-time-prekey inputs.signed_prekey_id
  7
x3dh-respond-with-a-one-time-prekey inputs.one_time_prekey_id
  41
```

The first message of the responder in answer: the DH ratchet step that the responder
takes when it decrypts the first message of the initiator (section 17.7, step 5), with
the 32 random bytes of its new ratchet key, then the same values for its own message.
The chain key of that message is the chain key of the second KDF_RK of the step. It
carries no initial header.

```
ratchet-decrypt-i0-first-message inputs.ratchet_private_key
  5252525252525252525252525252525252525252525252525252525252525252
ratchet-decrypt-i0-first-message intermediates.dh_receiving
  1292b40f5316616960cfa35969655da0e3f02ec4c9b6018e316e678dfb106b18
ratchet-decrypt-i0-first-message intermediates.root_key_receiving
  75fed0c88f85961cba32ec90c683343a431ccb89f3acd158df6a09f73f1dd5f5
ratchet-decrypt-i0-first-message intermediates.chain_key_receiving
  74fbfa0a0b6865361f7e3976c705044463bc8e8a91a91bdd01ab64827b2fd3b7
ratchet-decrypt-i0-first-message intermediates.ratchet_key
  f68b05ba03f7185e1ba88878682f8dd0b15158f6050889c9481d79c2d7d2fa07
ratchet-decrypt-i0-first-message intermediates.dh_sending
  731a0e9015f7835416d6e020e07af563075bacb78ad13d8013a16f644b3c7806
ratchet-decrypt-i0-first-message intermediates.root_key_sending
  80589a645dd6847e1382b7a6803e1be1a8b8dad011a49b61314083886c296827
ratchet-decrypt-i0-first-message intermediates.chain_key_sending
  fe7dd7d9a266e3fa8b81d2ce18101119d37636f53ac74717d16509918895abba
ratchet-encrypt-r0 intermediates.message_key
  44a3dae0d4309fc78d0e33d492f4271440912767a6d2b68588a38eac21720fec
ratchet-encrypt-r0 intermediates.header
  f68b05ba03f7185e1ba88878682f8dd0b15158f6050889c9481d79c2d7d2fa07
  0000000000000000
ratchet-encrypt-r0 inputs.message_id
  46464646464646464646464646464646
ratchet-encrypt-r0 inputs.nonce
  868686868686868686868686
ratchet-encrypt-r0 inputs.padded_plaintext
  0a0a6d6573736167652072308000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
  0000000000000000000000000000000000000000000000000000000000000000
ratchet-encrypt-r0 intermediates.associated_data
  01ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737
  d104f5f29162c31a8defa18e6e742224ee806fc1718a278be859ba5620402b8f
  3a8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f
  5c7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f
  1359d9225473451efffe6b36dbcaefdbf7b1895de62084509a7f5b58bf01d064
  1846464646464646464646464646464646f68b05ba03f7185e1ba88878682f8d
  d0b15158f6050889c9481d79c2d7d2fa070000000000000000
ratchet-encrypt-r0 outputs.ciphertext
  86868686868686868686868637b065eb53fa3d6a41596033c93d1e78b0a4a52b
  405c73c2a7f749830e30d6cbec9a3da5c4e5657f84ac538a3e5e1cc631ff9ac6
  14853a91f5b956990979bb2eae81952e2f1601446b36ca701e46400e27498620
  9e7a6e904120789100be211d1eceb436b5ef60a9a8d529e6dc1927f0039e7a31
  d6a2f35dacf9bb869973b244ecf4c2b2b28e7c0e1fd6c5ce62e8fb1f36be5bd8
  3d02852549fb184512d6585f37805943bfa3c6fa5a776cb994a3970aebbc91c4
  708002a5758b1a9581f8e5932af8d075fd85aeff023421093287f361c7076223
  57d7f1b291a27e916e4d81ea5a4c0d0849e4aec5c0c7f02687493b5543ff7dd5
  06c1ba4b6168acc68c50e2287297a72caec342f3e4f05e93ecb9efbf
```
