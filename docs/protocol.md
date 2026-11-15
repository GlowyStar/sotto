# sotto protocol, part 1

Identity, the prekey bundle and the relay protocol.

## 1. Status and scope

### 1.1 What this document is

sotto is an end-to-end encrypted one-to-one messenger. Clients exchange ciphertext through
a relay that holds no key that opens a message [pending: task 9]. This document is the
contract between the implementations: the relay and the command-line client of this
repository, and a macOS client in a repository of its own. It is written at the level of
bytes. Where an implementation and this text disagree, the implementation is wrong.

Part 1 specifies:

- the identity of a user and its text form, the user id (section 3);
- the three byte strings an identity key signs (section 4);
- the prekey bundle (section 5);
- the protocol between a client and the relay: transport, frames, login, bundles,
  messages, errors, limits and erasure (sections 6 to 13);
- versioning and the format of the shared test vectors (sections 14 and 15).

### 1.2 Status

- No security audit. Nobody has reviewed this protocol or its implementations for
  security. Do not rely on it to protect anything that matters.
- Every guarantee in this document carries a citation (section 2.6). A guarantee whose
  citation names a task instead of a test is held by no test in this repository, and the
  code behind it can be missing as well.
- Field numbers and signed byte layouts are frozen from the moment they are merged
  (sections 4.1 and 7.2).

### 1.3 Two version numbers

| Version                     | Value | Covers                                                    |
|-----------------------------|-------|-----------------------------------------------------------|
| Relay protocol version      | 1     | Sections 6 to 13 and the login string of section 4.2      |
| End-to-end protocol version | 1     | Sections 3 and 5, the key statements of sections 4.3 and 4.4, and part 2 |

The two numbers change independently. Section 14 says where each appears on the wire and
what a client does with a relay protocol version it does not know.

### 1.4 Specified in part 2

The items of this list are specified in part 2 [pending: task 9]. Part 1 states about them
only what the relay protocol depends on, each time with a citation.

- Key agreement between two identities from a prekey bundle, including the handling of an
  all-zero Diffie-Hellman output.
- The Double Ratchet: key derivation, the message header, skipped message keys.
- Message encryption: the cipher, the nonce, the associated data and the wire layout.
- The peer envelope and the plaintext format with its padding, that is, the content of the
  `payload` field of sections 7.12 and 7.14.
- Session rules: several sessions per peer, duplicates, messages from an id that is not a
  contact, decryption failures.
- The prekey lifecycle: rotation of the signed prekey, allocation of prekey ids, refill of
  one-time prekeys.
- The client store and the client transport: the reconnect and back-off schedules and the
  refusal of an unencrypted connection to a host that is not the loopback.

## 2. Conventions

### 2.1 Bytes and hex

A byte is 8 bits. A byte string is written in lowercase hex, two digits per byte, first
byte first, without separators: `736f74746f` is the five bytes of the ASCII text `sotto`.
One byte is also written as `0x00`. Text inside a byte layout is ASCII, one byte per
character, with no terminator unless the layout shows one.

`A || B` is the bytes of A followed by the bytes of B. `X[i]` is byte i of X, counted
from 0.

### 2.2 Integers

- `u8` and `u32` are unsigned integers of 1 and 4 bytes.
- In a byte layout an integer wider than one byte is big-endian, most significant byte
  first. Part 1 has one integer in a byte layout, the 1-byte name length of section 4.2.
- In a frame an integer is a protobuf `uint32`, and protobuf decides its encoding.
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

A citation is written on one line and has one of two forms, shown here by a real example
of each:

- `[test: tests/test_routing.py::test_healthz_answers_200]` names the test function that
  holds the statement: the path of the test file from the root of the repository, two
  colons, the name of the function. A parametrized test is cited by its function name.
- `[pending: task 4]` says that what the statement rests on is not in this revision and
  gives the number, 3 to 14, of the task of the project plan that brings it. For a
  guarantee of part 1 that is a test, and the pull request of the task replaces the
  citation with the first form. For a statement that part 2 specifies it is task 9, which
  writes part 2 and brings no test: its pull request replaces the citation with the number
  of the section that states the rule and with the citation of the test, or of the task,
  behind that rule.

The two forms are checked by machine, here and in the other documents of `docs/` and in
the README. A citation of the first form has to name a test function that exists
[test: tests/test_docs.py::test_cited_tests_exist]. Four marks appear only inside a
citation: an opening square bracket followed by a word and a colon, the word that opens
the second form, a path into the test folder and a pair of colons. Text that carries one
of the marks and is not a citation of one of the two forms fails the check
[test: tests/test_docs.py::test_citations_are_well_formed]. The check sees the form of a
citation, not whether a guarantee has one.

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
[pending: task 5] [pending: task 6].

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
  session carry [pending: task 9].

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
these keys, for rotating the signed prekey and for choosing prekey ids are in part 2
[pending: task 9].

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
  start, not a session with someone else [pending: task 9].

### 5.3 The X25519 identity key is written once

A signature over an X25519 identity key has no expiry, so the key it covers does not
change for the life of the identity.

- The relay keeps the X25519 identity key of the first accepted upload of an identity and
  refuses every later upload that carries another one with IDENTITY_KEY_MISMATCH. It
  compares the 32 bytes of the key, not the signature (section 4.1, rule 5), and keeps the
  signature of the first upload [pending: task 5].
- A client pins the X25519 identity key of a contact the first time a bundle of that
  contact passes the checks of section 5.4 [pending: task 12] and refuses every later
  bundle of that contact that carries another one
  [test: tests/crypto/test_identity.py::test_pinned_x25519_identity_key_refuses_another_one].

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

- When all four pass and the client has no pin for the contact, it pins `identity_dh_key`.
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
does not depend on the request, on a client or on the database [pending: task 5]. The
WebSocket port serves no metrics [pending: task 8].

### 6.2 Binary frames only

One frame is one WebSocket binary message that holds one serialized envelope message
(section 7.1). A receiver that gets a WebSocket text message closes the connection with
close code 1003, in every state of the connection, before login and after it
[pending: task 4].

A client MUST answer a WebSocket ping with a pong (RFC 6455 section 5.5.2). The relay MAY
end a connection that leaves its pings unanswered.

### 6.3 The largest frame

A frame is at most MAX_FRAME_BYTES long, 65536 bytes (section 12.1). The length is that of
the whole WebSocket message, after fragments are joined. A receiver that gets a longer
message closes the connection with close code 1009; the WebSocket library sends that code
before any frame is parsed [pending: task 4]. A client MUST set the receive limit of its
WebSocket library to the same value. The relay sends no frame above the limit
[pending: task 6].

### 6.4 No compression, no extension, no subprotocol

The relay negotiates no WebSocket extension: its handshake answer carries no
`Sec-WebSocket-Extensions` header, so no message is compressed
[test: tests/test_routing.py::test_websocket_opens_on_ws]. Ciphertext does not compress.
The relay selects no subprotocol [pending: task 4], and a client MUST NOT require one.

### 6.5 TLS

The relay process speaks WebSocket without TLS
[test: tests/test_routing.py::test_websocket_opens_on_ws]. In a deployment a reverse proxy
in front of it ends TLS and forwards the path `/ws`. The protocol makes no use of the TLS
session: the login is not bound to it (section 8.7). What a client refuses to dial without
TLS is specified in part 2 [pending: task 9].

## 7. Frames

### 7.1 The schema

The frames are protobuf messages, proto3 syntax. The schema lives in `proto/sotto.proto`,
which is normative for the names, numbers and types of the fields; this section lists its
content for the relay protocol and adds the rules that a schema cannot express. A message
enters the file with the pull request that implements its handler, the login frames first
[pending: task 4].

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
}

message Error {
  ErrorCode code = 1;
  bytes message_id = 2;
  bytes identity = 3;
}
```

No client frame names its own sender. After the login the relay takes the identity of a
frame from the connection that carried it, never from a field: Send has a recipient only,
UploadBundle has no identity field, and the `sender` of a MessageRef is the sender of the
acked message, not of the Ack [pending: task 6]. The identity key of a Login is not an
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

A field that the receiver's schema does not have is ignored [pending: task 4]. A frame that
parses is not valid by that alone: proto3 has no required fields and reads an absent field
as empty, so rule 3 is what makes a frame complete.

The receiver of a malformed frame closes the connection with close code 1008. For the
relay this holds for every malformed frame, before login and after it
[pending: task 4]. A client that closed for this reason retries (section 11.1).

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

Rules of state for the relay [pending: task 4]:

- A first client frame that is not a Login closes the connection with 1008. This is the
  case of a frame before login.
- A Login that is not the first client frame closes the connection with 1008.
- A client MAY send further frames right after its Login without waiting for LoggedIn. The
  relay handles them only after it accepted the Login; when it refuses the Login it closes
  the connection and handles none of them.
- The relay handles the frames of one connection one at a time, in the order it received
  them, and sends the answer to a frame before it handles the next frame of that
  connection. A Deliver is not an answer and can arrive between any two other frames that
  follow the LoggedIn.
- Every UploadBundle and FetchBundle gets exactly one answer [pending: task 5], and so
  does every Send [pending: task 6].

Rules of state for a client [pending: task 14]:

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

- Sent by the relay as the first frame of every connection [pending: task 4].
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
- Violations [pending: task 4]: a malformed Login closes with 1008; an `identity_key` that
  fails step 3 or 4 of section 3.3 closes with 3000; a signature that does not verify
  closes with 3000; no Login within LOGIN_DEADLINE_SECONDS closes with 3008; a second Login
  on the connection closes with 1008. Section 8 has the full rules.

### 7.7 LoggedIn

| Field                   | No. | Type   | Length or value                                         |
|-------------------------|-----|--------|---------------------------------------------------------|
| `one_time_prekey_count` | 1   | uint32 | The number of one-time prekeys the relay holds for the identity, 0 for an identity that is not registered |

- Sent by the relay once, when it accepted the Login [pending: task 4]. The count is that
  of section 9.4 [pending: task 5].
- No answer.
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
- Violations [pending: task 5]: a malformed UploadBundle closes with 1008, a wrong length
  of a key or a signature included; an UploadBundle before login closes with 1008.
  Section 9.1 has the full rules.

### 7.9 BundleStored

| Field                   | No. | Type   | Length or value                                              |
|-------------------------|-----|--------|--------------------------------------------------------------|
| `one_time_prekey_count` | 1   | uint32 | The number of one-time prekeys the relay holds for the identity after the upload |

- Sent by the relay as the answer to an accepted UploadBundle [pending: task 5].
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
- Violations [pending: task 5]: a malformed FetchBundle closes with 1008; a FetchBundle
  before login closes with 1008. Section 9.2 has the full rules.

### 7.11 Bundle

| Field                     | No. | Type          | Length or value                                |
|---------------------------|-----|---------------|------------------------------------------------|
| `identity`                | 1   | bytes         | 32, the `identity` of the FetchBundle          |
| `identity_dh_key`         | 2   | bytes         | 32                                             |
| `identity_dh_signature`   | 3   | bytes         | 64                                             |
| `signed_prekey`           | 4   | SignedPrekey  | present; `key` 32, `signature` 64              |
| `one_time_prekey`         | 5   | OneTimePrekey | present or absent; `key` 32 when present       |

- Sent by the relay as the answer to a FetchBundle for a registered identity
  [pending: task 5].
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
- Violations [pending: task 6]: a malformed Send closes with 1008, an empty payload and a
  payload above the limit included; a Send before login closes with 1008. Section 10.2 has
  the full rules.

The payload is opaque to the relay: the relay stores and forwards its bytes and parses
none of them [pending: task 6]. The 64 bytes are a bound on what the envelope and the
other fields add to a payload in a Send or a Deliver (60 bytes in the shortest encoding),
so that every stored payload fits into a Deliver.

### 7.13 Stored

| Field        | No. | Type  | Length or value                        |
|--------------|-----|-------|----------------------------------------|
| `message_id` | 1   | bytes | 16, the `message_id` of the Send       |

- Sent by the relay as the answer to a Send, after the message is committed
  (section 10.2) [pending: task 6].
- No answer.
- Violations, seen by the client: a `message_id` that is not 16 bytes is a malformed
  frame.

### 7.14 Deliver

| Field        | No. | Type  | Length or value                                            |
|--------------|-----|-------|------------------------------------------------------------|
| `message_id` | 1   | bytes | 16, as the sender chose it                                 |
| `sender`     | 2   | bytes | 32, the identity key of the connection that sent the Send  |
| `payload`    | 3   | bytes | 1 to MAX_FRAME_BYTES - 64, the bytes of the Send           |

- Sent by the relay to the logged-in recipient (section 10.4) [pending: task 6].
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
- Violations [pending: task 6]: a malformed Ack closes with 1008, an Ack without a pair
  included; an Ack before login closes with 1008.

### 7.16 Error

| Field        | No. | Type      | Length or value                                              |
|--------------|-----|-----------|--------------------------------------------------------------|
| `code`       | 1   | ErrorCode | One of the codes of section 11.2                             |
| `message_id` | 2   | bytes     | 16 when the refused frame is a Send, its `message_id`; otherwise empty |
| `identity`   | 3   | bytes     | 32 when the refused frame is a FetchBundle, its `identity`; otherwise empty |

- Sent by the relay as the answer to a Send, an UploadBundle or a FetchBundle that it
  refuses. The connection stays open [pending: task 5].
- The key fields tell the client which frame was refused: `message_id` set means a Send,
  `identity` set means a FetchBundle, neither set means an UploadBundle
  [pending: task 5] [pending: task 6]. Answers arrive in the order of their requests
  (section 7.4), which tells two requests with one key apart.
- No answer.
- Violations, seen by the client: a `message_id` that is neither empty nor 16 bytes, an
  `identity` that is neither empty nor 32 bytes and an Error with both set are malformed
  frames. A `code` that the client does not know, 0 included, is not: the client treats
  the request as refused and stops repeating it (section 11.1).

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
relay uses for this connection only [pending: task 4]. The client answers with its
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
   result [pending: task 14].

| URL as given                      | Server name                                           |
|-----------------------------------|-------------------------------------------------------|
| `wss://Relay.Example.org:8443/ws` | `relay.example.org`, 17 bytes                         |
| `ws://127.1:8765/ws`              | `127.1`: the short form of an address is kept         |
| `wss://%72elay.example.org/ws`    | none: `%` breaks rule 4, and the URL is not dialed    |

A host name with characters outside ASCII breaks rule 4 as well, percent-encoded or not.
Such a name is given to the client in its ASCII form, the A-label of RFC 5890 (`xn--` and
what follows), and RELAY_NAME holds the same form.

The relay takes the name from its setting RELAY_NAME, default `127.0.0.1`, and does not
start with a value that breaks rule 4 [pending: task 4]. The operator sets it to the host
that clients dial, in the form that steps 1 to 3 give.

No frame carries the name, so the relay compares it with RELAY_NAME through the signature:
it builds the login string with RELAY_NAME, and a signature that a client made for another
name does not verify. The login is refused with 3000 [pending: task 4]. This is the case
of a login answer replayed to another server: a relay that received a login cannot use it
to log in at a relay with another server name. Relays that clients dial under one host, on
different ports, have one server name, and the login does not tell them apart: either of
them can pass a login it receives on to the other. It is for the operator to give a relay
a host that no relay of another party shares. A recorded login is of no use on another
connection of the same relay either, because every connection has its own nonce
[pending: task 4].

### 8.3 The relay's checks

For every connection, in this order [pending: task 4]:

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
relay sends no second Hello and accepts no second Login (section 7.4) [pending: task 4].

### 8.5 One live connection per identity

The relay keeps at most one logged-in connection per identity. When a login succeeds for
an identity that has a live connection, the relay closes the older connection with close
code 4001 and serves the newer one. From that login on, the relay handles no further frame
of the older connection and sends it nothing but the close [pending: task 4].

A client that is closed with 4001 stops: it does not reconnect by itself
[pending: task 14]. Two copies of one identity would otherwise replace each other without
end. This is the case of a second login of one identity.

### 8.6 Registration

There is no registration frame and no account. An identity is registered at a relay from
the first UploadBundle that the relay accepts for it (section 9.1): registration is the
first login plus a bundle upload.

- An identity that is logged in and not registered can send every frame. It can receive
  nothing, because a Send to it is refused with UNKNOWN_RECIPIENT (section 10.2) and a
  FetchBundle for it with NOT_FOUND (section 9.2).
- The relay keeps a registered identity and its bundle without an expiry, and no frame
  removes either [pending: task 7].

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
[pending: task 5]:

1. It takes a token from the frame bucket of the identity (section 12.2). Without a token
   the answer is Error RATE_LIMITED [pending: task 8].
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
      stored for the identity is skipped. One is stored while the identity has fewer than
      ONE_TIME_PREKEY_CAP stored. The rest are dropped.
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
[pending: task 5]. A client therefore MUST NOT upload a one-time prekey a second time,
unless the relay refused the frame that carried it with an Error: after an UploadBundle
that got no answer, the client counts the one-time prekeys of that frame as uploaded
[pending: task 13]. The other fields of an UploadBundle are safe to repeat.

### 9.2 Fetch

The relay handles a well-formed FetchBundle of a logged-in connection in this order
[pending: task 5]:

1. It takes a token from the frame bucket of the requesting identity. Without a token the
   answer is Error RATE_LIMITED [pending: task 8].
2. When the identity of the request is not registered, the answer is Error NOT_FOUND.
3. It decides the handout of a one-time prekey (section 9.3).
4. The answer is Bundle: the identity of the request, its X25519 identity key and
   signature, its stored signed prekey with id and signature, and the one-time prekey of
   step 3 when there is one.

Any logged-in identity can fetch the bundle of any registered identity, its own included.
The relay returns the stored bytes of every key and signature unchanged
[pending: task 5].

### 9.3 The handout of a one-time prekey

A fetched bundle carries at most one one-time prekey, and a one-time prekey is handed out
at most once [pending: task 5].

1. When the handout bucket of the target identity (section 12.2) has no token, the bundle
   goes out without a one-time prekey and the stored ones stay untouched
   [pending: task 8].
2. Otherwise the relay takes the one-time prekey of the target that was stored first and
   deletes it in the same transaction that reads it. The bundle is sent after the commit
   [pending: task 5].
3. When step 2 handed out a key, one token is taken from the handout bucket of the target.
   When the target has no one-time prekey stored, the bundle goes out without one and no
   token is taken [pending: task 8].

A fetch never fails for lack of a one-time prekey: a registered identity always gets a
Bundle [pending: task 5]. A bundle without a one-time prekey still starts a session
[pending: task 9].

### 9.4 The count of one-time prekeys

LoggedIn and BundleStored carry the number of one-time prekeys that the relay holds for
the identity at that moment [pending: task 5]. A client uses it to decide when to upload
more [pending: task 9]. The relay sends no other notice when the number falls
[pending: task 5].

## 10. Messages

### 10.1 The message id

The sender chooses the id of a message: 16 random bytes. The relay assigns no id of its
own: no frame carries an id, a counter or a position that the relay gave to a message
[pending: task 6].

- A client uses one id for one message and repeats a message with the id, the recipient
  and the payload unchanged.
- A client MUST NOT use the id of one message for another message.
- An id is unique per sender only. The key of a message at the relay and at the recipient
  is the pair (sender, message id) (sections 10.3 and 10.5).

### 10.2 Send and Stored

The relay handles a well-formed Send of a logged-in connection in this order
[pending: task 6]. The sender is the identity of the connection. Steps 2 to 5 are one
transaction.

1. It takes a token from the frame bucket of the sender (section 12.2). Without a token
   the answer is Error RATE_LIMITED [pending: task 8].
2. When the relay holds a message with this sender and this `message_id`, the answer is
   Stored and nothing else happens (section 10.3).
3. When `recipient` is not registered, the answer is Error UNKNOWN_RECIPIENT.
4. When the queue of the recipient holds QUEUE_MAX_MESSAGES messages, or the payloads in
   it together with this payload are more than QUEUE_MAX_BYTES, the answer is Error
   QUEUE_FULL and nothing is stored [pending: task 8].
5. The relay stores the sender, the recipient, the message id, the payload and the time
   in whole seconds, and commits. When the transaction fails because the database is at
   its page ceiling, it is rolled back, the answer is Error STORAGE_FULL and nothing is
   stored.
6. The answer is Stored with the `message_id` of the Send.

Stored means: the message is committed. The relay sends Stored only after the commit, and
a committed message survives a kill of the relay process [pending: task 6]. Whether it
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
  [pending: task 6].
- When the relay does not hold the message, because the recipient acked it or it expired,
  the relay cannot know the repeat. It stores the message again and delivers it again
  [pending: task 6]. The recipient's client discards the second copy by the pair (sender,
  message id) and acks it [pending: task 9].

This is the case of a Send repeated after a lost Stored.

The two cases look different to a sender that repeats a message id with another recipient.
While the relay holds the first message, the repeat is answered with Stored and nothing is
stored for the other recipient. Once the first message is acked or expired, the repeat is
a new message: it is refused with UNKNOWN_RECIPIENT when the other recipient is not
registered, and stored and delivered when it is [pending: task 6]. A sender learns in this
way when the recipient of the first message acked it (threat model, "Not protected").

### 10.4 Deliver, order and redelivery

- The relay sends the messages of a queue to the logged-in connection of the recipient,
  each as one Deliver with the sender, the message id and the payload as stored
  [pending: task 6].
- Order: the messages of one queue go out in the order in which the relay committed them,
  across all senders [pending: task 6].
- After a login the relay first sends LoggedIn and then every message of the queue, oldest
  first, the ones that an earlier connection received and did not ack included. Messages
  committed during the connection follow as they are committed [pending: task 6].
- On one connection a message is sent once. The relay does not wait for the Ack of a
  message before it sends the next one, and it does not send a message a second time on
  that connection, however long the Ack takes [pending: task 6].
- A message that is not acked stays in the queue and is delivered again after the next
  login of the recipient, until it is acked or expires [pending: task 6].
- The relay delivers a message to its recipient only, and the handling of one sender's
  Send never waits for a recipient to read [pending: task 6].

Delivery is at least once. A client receives a message more than once after a lost Ack, a
replaced connection or a repeated Send, and discards the copies by the pair (sender,
message id) [pending: task 9].

### 10.5 Ack

An Ack names messages by the pair (sender, message id), as the Deliver carried them.

- For every pair the relay deletes the message that has this sender, this message id and
  the identity of the acking connection as its recipient [pending: task 6].
- A pair that matches no such message is ignored. This covers a message that is already
  deleted and a message that is queued for another identity: an Ack never deletes a
  message of another recipient's queue, and the acking client learns nothing about it
  [pending: task 6]. This is the case of an Ack for a message queued for someone else.
- An Ack is safe to repeat [pending: task 6].
- An Ack has no answer, and the relay sends no Error for it [pending: task 6]. It takes no
  token from the frame bucket (section 12.2).
- An Ack for a message of an earlier connection is valid: the pair is the whole key
  [pending: task 6].

A client acks a message only after it saved everything it needs from it; the exact rule is
in part 2 [pending: task 9]. An Ack tells the relay to delete the only other copy.

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
no notice [pending: task 7].

## 11. Errors and close codes

### 11.1 What the client does next

Three actions are named in the tables below.

- Retry: the connection is gone. The client opens a new connection, logs in and repeats
  every Send that has no Stored and no Error whose action is Stop. It waits before each
  attempt and lengthens the wait while attempts fail; the schedule is specified in part 2
  [pending: task 9].
- Stop: the client does not reconnect and does not repeat the frame by itself. It reports
  the condition, and the next step is taken by a person.
- Back off: the connection stays open. The client waits before it sends the refused frame
  again, unchanged. The wait is FRAME_REFILL_SECONDS or longer and grows while the same
  frame keeps being refused; the schedule is specified in part 2 [pending: task 9]. A
  frame that waits in Back off when the connection ends is sent again after the next
  login.

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
  [pending: task 5] [pending: task 6].
- Stop applies to the refused frame only: the connection and the other frames go on.
- BAD_BUNDLE and IDENTITY_KEY_MISMATCH are also results of the client's own checks of a
  fetched bundle (sections 5.4 and 11.4).
- A code that a client does not know is handled as Stop for the refused frame.

The relay sends each code under the stated condition and no other
[pending: task 5] [pending: task 6] [pending: task 8].

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
  [pending: task 14]. 1003, 1008 and 1009 from the relay mean that the client broke the
  protocol, and a new connection would break it again.
- A client that closes because the relay sent a text message, a malformed frame or a
  message above the limit uses the same codes and then retries.
- Any other close code, and a connection that ends without a close, is handled as Retry.
- Close code 1000 is not a violation. A client that ends a connection for a reason of its
  own closes with it, the unknown version of section 14.1 included.
- The relay sends each code under the stated condition [pending: task 4]. On an orderly
  shutdown it closes every open connection with 1001 [pending: task 4] and exits with
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
bundle [pending: task 12]. Part 2 adds the local results of the end-to-end protocol
[pending: task 9].

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
| MAX_PAGES               | 262144   | pages    | The page ceiling of the database, 1 GiB at pages of 4096 bytes        |
| SWEEP_INTERVAL_SECONDS  | 60       | seconds  | The time between two sweeps (section 13)                              |

The values are the defaults of the relay's settings. The relay reads each from the
environment variable of the same name with the prefix `RELAY_`, and a test compares this
table with the settings, constant by constant [pending: task 8].

No frame carries a limit, so a client uses the defaults of the three it needs:
MAX_FRAME_BYTES, ONE_TIME_PREKEY_CAP and FRAME_REFILL_SECONDS.

- MAX_FRAME_BYTES is a constant of relay protocol version 1. A relay that serves clients
  MUST NOT run with another value: with a larger one it stores a message that no client
  can receive, with a smaller one it closes on a frame that this protocol allows.
- A relay with another ONE_TIME_PREKEY_CAP or FRAME_REFILL_SECONDS still works with a
  client that assumes the defaults (sections 9.1 and 11.1). These and the other settings
  of the table are the operator's to change.

### 12.2 Token buckets

A bucket holds at most its size in tokens and is full when it is made. Tokens return at
the rate of one per refill time, up to the size. Buckets live in the memory of the relay
process: a restart of the relay fills them, a new login does not. A bucket that is full
again is the same as a new one, and the relay MAY forget it [pending: task 8].

- The frame bucket belongs to an identity. Every Send, UploadBundle and FetchBundle of the
  identity takes one token before anything else is done with the frame, whatever the
  answer turns out to be. A frame that finds no token is refused with RATE_LIMITED and
  changes nothing. A Login and an Ack take no token [pending: task 8]. A Login comes
  before the identity is known. An Ack has no answer that could refuse it, and an Ack that
  is dropped keeps a message on the relay. Acks are therefore not limited: one identity
  can send them without bound, and each makes the relay look up every pair it names.
- The handout bucket belongs to a target identity. Handing out one of its one-time prekeys
  takes one token, whoever asks. A fetch that finds no token gets the bundle without a
  one-time prekey and no Error (section 9.3) [pending: task 8].

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
  answers STORAGE_FULL and stays up [pending: task 5].

## 13. Erasure on the relay

### 13.1 What is deleted, and when

The relay deletes a message in two cases:

- its recipient acked it (section 10.5): the deletion is part of the handling of the Ack;
- MESSAGE_TTL_SECONDS passed since it was stored (section 10.7): the deletion is part of a
  sweep.

The relay delivers no message that it deleted [pending: task 6] [pending: task 7]. A Send
that is repeated after the deletion is a new message for the relay (section 10.3).

### 13.2 What "deleted" means

"Deleted after the ack" means: after the first sweep that follows the deletion, the
payload of the message and its message id are in none of the files of the database: the
database file, its write-ahead log and the index of that log, the files that end in `-wal`
and `-shm` [pending: task 7].

How the relay gets there [pending: task 7]:

- The database runs with `secure_delete` on, so the deletion overwrites the bytes of the
  row with zeros instead of leaving them in a free page.
- The database runs in write-ahead mode, so until a checkpoint the old pages of the row
  remain in the write-ahead log file. A sweep ends with a checkpoint that moves the log
  into the database file and truncates the log to zero length.
- A sweep runs every SWEEP_INTERVAL_SECONDS while the relay runs. Between the deletion
  and the next sweep the bytes can be read from the log file.
- On an orderly shutdown the relay closes the database, which runs a last checkpoint and
  removes the log file [pending: task 5].
- A relay that is killed runs no sweep. What was deleted after its last sweep stays in the
  log file until the relay runs again and sweeps.

### 13.3 Out of scope

- What lies below the files: blocks that the filesystem or the storage device keeps after
  an overwrite or a truncation, snapshots and backups of the host.
- A relay that does not run this code. The rules of this section describe the relay of
  this repository; whoever runs a relay can keep a copy of every frame (threat model,
  "What the relay can do").

## 14. Versioning

### 14.1 The relay protocol version

The relay protocol version is 1. It appears in one place on the wire: the `version` field
of Hello, the first frame of every connection.

- In every version of the relay protocol the first frame of the relay is a ServerFrame
  with field 1, `hello`, set, and `version` is field 1 of that Hello.
- A client reads `version` before it applies any other rule to the Hello. A client that
  reads a `version` other than 1, 0 included, sends no Login, closes the connection with
  close code 1000, reports that the relay speaks a version it does not implement, and
  stops (section 11.1) [pending: task 14].
- A client states no version. A client that stays on the connection speaks the version of
  the Hello.
- A change that an implementation of version 1 would refuse or misread is a new version:
  a new frame, a new meaning of a field, a new layout of the login string. A new field
  that a receiver of version 1 can ignore is not.

### 14.2 The end-to-end protocol version

The end-to-end protocol version is 1. It appears inside the payload, in the peer envelope
that part 2 specifies [pending: task 9]. The relay does not read it and has no rule about
it (section 7.12).

- What a client does with an envelope that names a version it does not implement is a rule
  of part 2 [pending: task 9].
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
[test: tests/crypto/test_identity_vectors.py::test_negative_vectors_raise_their_named_error].
The first file is `vectors/identity.json`; section 15.5 names its operations and the keys
of their objects
[test: tests/crypto/test_identity_vectors.py::test_vectors_use_the_operations_and_keys_of_the_document].

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
| `error`         | string | negative case only       | The expected failure: one name of section 11                   |

Rules:

- A vector has `outputs` or `error`, never both and never neither.
- Bytes are hex strings as in section 2.1. Text is a JSON string. A count or an id is a
  JSON number. A value that is absent in the operation is absent in the object.
- Every private key, ephemeral key, nonce and message id that an operation uses is in
  `inputs`: replaying a vector draws no random byte.
- `intermediates` holds each value an implementation needs to find where it went wrong,
  the signed strings of section 4 among them.
- `error` is an Error code of section 11.2, the name of a close code of section 11.3 or a
  local result of section 11.4, spelled as there.
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

## 16. Not part of this protocol

These are left out on purpose. Each is a second protocol, or needs a deployed
environment, or has no user before a later stage of the project.

- TLS inside the relay process, and the reverse proxy with the header that passes on the
  address of a client.
- Limits per address: connections per address and new identities per address.
- Expiry of identities.
- Proof of work.
- Hiding the sender from the relay, and encryption of the message header.
- Post-quantum key agreement. Nothing is reserved for it beyond the two version numbers.
- Verification of keys by a safety number.
- Several devices per identity, groups, attachments and calls.
- Any claim of deniability.

## 17. References

- RFC 3986, Uniform Resource Identifier (URI): Generic Syntax.
- RFC 5890, Internationalized Domain Names for Applications (IDNA): Definitions and
  Document Framework.
- RFC 6455, The WebSocket Protocol.
- RFC 7748, Elliptic Curves for Security.
- RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA).
- Protocol Buffers documentation, "Proto Serialization Is Not Canonical",
  https://protobuf.dev/programming-guides/serialization-not-canonical/
- K. Chalkias, F. Garillot, V. Nikolaenko, "Taming the many EdDSAs", IACR ePrint
  2020/1244, https://eprint.iacr.org/2020/1244
- M. Marlinspike, T. Perrin, "The X3DH Key Agreement Protocol", Revision 1,
  https://signal.org/docs/specifications/x3dh/
- IANA, WebSocket Close Code Number Registry,
  https://www.iana.org/assignments/websocket/websocket.xhtml
