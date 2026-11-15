# sotto protocol

Part 1, sections 1 to 15: identity, the prekey bundle and the relay protocol. Part 2,
sections 16 to 25: the end-to-end protocol between two clients. Sections 26 and 27 close
both parts, and Appendix A follows section 27.

## 1. Status and scope

### 1.1 What this document is

sotto is an end-to-end encrypted one-to-one messenger. Clients exchange ciphertext through
a relay that holds no key that opens a message (sections 16 to 18) [pending: task 14].
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
| End-to-end protocol version | 1     | Sections 3 and 5, the key statements of sections 4.3 and 4.4, and sections 16 to 25 |

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

A citation is written on one line and has one of two forms, shown here by a real example
of each:

- `[test: tests/test_routing.py::test_healthz_answers_200]` names the test function that
  holds the statement: the path of the test file from the root of the repository, two
  colons, the name of the function. A parametrized test is cited by its function name.
- `[pending: task 4]` says that what the statement rests on is not in this revision and
  gives the number, 3 to 8 or 10 to 14, of the task of the project plan that brings it.
  The pull request of that task replaces the citation with the first form. No citation
  names task 9: that task is part 2 of this text and brings no test. A statement of
  part 1 that rests on a rule of part 2 names the section of that rule and carries the
  citation of the test, or of the task, behind it.

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
[pending: task 3].

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
implementation accepts the same strings [pending: task 3].

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
  2020/1244, tables 1 and 2.

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
   another; it harms only the identity that made it.
2. Every signed string is `prefix || 0x00 || fields`. The prefix is ASCII text and holds no
   0x00 byte, so the first 0x00 byte of a signed string ends its prefix. The three
   prefixes differ, so a signed string of one kind is never a signed string of another
   kind, whatever its fields hold [pending: task 3]. Without the prefixes the relay could
   choose a login nonce that makes the login string a valid prekey statement.
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
  session carry (section 16.8) [pending: task 12].

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
these keys are in section 16 [pending: task 10]; those for rotating the signed prekey and
for choosing prekey ids are in section 21 [pending: task 13].

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
  (section 16.9) [pending: task 10] [pending: task 12].

### 5.3 The X25519 identity key is written once

A signature over an X25519 identity key has no expiry, so the key it covers does not
change for the life of the identity.

- The relay keeps the X25519 identity key of the first accepted upload of an identity and
  refuses every later upload that carries another one with IDENTITY_KEY_MISMATCH. It
  compares the 32 bytes of the key, not the signature (section 4.1, rule 5), and keeps the
  signature of the first upload [pending: task 5].
- A client pins the X25519 identity key of a contact in the transaction that stores its
  first session with that contact: the key of a bundle that passed the checks of
  section 5.4, when the client made the session (section 16.6), or the key of the initial
  header, when it accepted the first initial message of the contact (section 16.8)
  [pending: task 12]. It refuses every later bundle of that contact that carries another
  key [pending: task 3] and every later initial header that does (section 16.8)
  [pending: task 12].

### 5.4 The client's checks

A client that received a Bundle for a contact runs these checks in this order and stops at
the first that fails [pending: task 3]. The lengths of the fields were checked before, when
the frame was parsed (section 7.3).

| No. | Check                                                                                         | Result on failure     |
|-----|-----------------------------------------------------------------------------------------------|-----------------------|
| 1   | `identity` equals the 32 bytes that the id of the contact decodes to                          | BAD_BUNDLE            |
| 2   | `identity_dh_signature` verifies under `identity` over the string of section 4.3, built from `identity` and `identity_dh_key` | BAD_BUNDLE |
| 3   | If the client has a pinned X25519 identity key for the contact: `identity_dh_key` equals it   | IDENTITY_KEY_MISMATCH |
| 4   | `signed_prekey.signature` verifies under `identity` over the string of section 4.4, built from `identity` and `signed_prekey.key` | BAD_BUNDLE |

- When all four pass and the client has no pin for the contact, it pins `identity_dh_key`
  in the transaction that stores the session made from the bundle (section 16.6, step 8)
  [pending: task 12]. A key agreement that fails after the checks pins nothing.
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
TLS is specified in section 23.1 [pending: task 14].

## 7. Frames

### 7.1 The schema

The frames are protobuf messages, proto3 syntax. The schema lives in `proto/sotto.proto`,
which is normative for the names, numbers and types of the fields; this section lists its
content for the relay protocol and adds the rules that a schema cannot express. A message
enters the file with the pull request that implements its handler, the login frames first
[pending: task 4]. The messages of the end-to-end protocol are in the same file and are
listed in section 19.1.

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
(section 16.6) [pending: task 10].

### 9.4 The count of one-time prekeys

LoggedIn and BundleStored carry the number of one-time prekeys that the relay holds for
the identity at that moment [pending: task 5]. A client uses it to decide when to upload
more (section 21.3) [pending: task 14]. The relay sends no other notice when the number
falls [pending: task 5].

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
  message id) and acks it (section 20.2) [pending: task 12].

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
message id) (section 20.2) [pending: task 12].

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
in section 22.2 [pending: task 14]. An Ack tells the relay to delete the only other copy.

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
  attempt and lengthens the wait while attempts fail; the schedule is specified in
  section 23.4 [pending: task 14].
- Stop: the client does not reconnect and does not repeat the frame by itself. It reports
  the condition, and the next step is taken by a person.
- Back off: the connection stays open. The client waits before it sends the refused frame
  again, unchanged. The wait is FRAME_REFILL_SECONDS or longer and grows while the same
  frame keeps being refused; the schedule is specified in section 23.5
  [pending: task 14]. A frame that waits in Back off when the connection ends is sent
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

A client that gets one of the first three reports it and uses neither the id nor the
bundle [pending: task 3]. Section 24.2 names the local results of the end-to-end protocol.

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

No frame carries a limit, so a client uses the defaults of the four it needs:
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

The end-to-end protocol version is 1. It appears in one place on the wire, inside the
payload: the `version` field of the peer envelope (section 19.2). It is also the first
byte of the session associated data, which is not sent and which every message of a
session authenticates (section 16.5) [pending: task 12]. The relay does not read it and
has no rule about it (section 7.12).

- In every version of the end-to-end protocol the payload is a `PeerMessage` whose field 1
  is `version`.
- A client reads `version` before it applies any other rule to the envelope. A client that
  reads a `version` other than 1, 0 included, decrypts nothing and changes nothing in its
  store: it reports that the contact uses a version it does not implement and acks the
  message (section 19.4) [pending: task 12].
- A change that a client of version 1 would refuse or misread is a new version: another
  layout of the header, of the associated data or of the padding, another cipher or key
  derivation. A new member of the `Content` oneof is not: a client of version 1 reports
  such a message as UNKNOWN_CONTENT (section 19.5).
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
[pending: task 3]. No vector file exists in this revision; the names of the operations and
the keys of their objects are added to this section together with the first file
[pending: task 3]. Section 24.3 says what the vectors of the key agreement and of the
ratchet record.

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
| `error`         | string | negative case only       | The expected failure: one name of section 11 or of section 24.2 |

Rules:

- A vector has `outputs` or `error`, never both and never neither.
- Bytes are hex strings as in section 2.1. Text is a JSON string. A count or an id is a
  JSON number. A value that is absent in the operation is absent in the object.
- Every private key, ephemeral key, nonce and message id that an operation uses is in
  `inputs`: replaying a vector draws no random byte.
- `intermediates` holds each value an implementation needs to find where it went wrong,
  the signed strings of section 4 among them.
- `error` is an Error code of section 11.2, the name of a close code of section 11.3 or a
  local result of section 11.4 or of section 24.2, spelled as there.
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
  never a contact: a client refuses to add it [pending: task 12].
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
  carries a private key as these 32 bytes [pending: task 10].
- A public key is stored, compared and put into a byte layout as the 32 bytes that were
  generated or received. No implementation decodes a public key and encodes it again
  [pending: task 10] [pending: task 11].
- An identity makes the key pair of IKdh together with its Ed25519 key pair and signs the
  string of section 4.3 for it. Any signature that verifies serves: the initial header and
  the bundle of one identity can carry different signature bytes (section 4.1, rule 5).

### 16.3 The Diffie-Hellman function

DH(k, P) is the X25519 function of RFC 7748 section 5 for the private key k and the public
key P. Its output is 32 bytes. The calls are `X25519PrivateKey.exchange` in the Python
package cryptography and `sharedSecretFromKeyAgreement(with:)` in CryptoKit, whose result
is read as its raw bytes.

An output of 32 zero bytes is refused: the operation that computed it ends with the result
ZERO_DH and uses the output for nothing [pending: task 10].

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

SK is one call of HKDF (RFC 5869) [pending: task 10]:

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

Both sides build the same 161 bytes, the keys of the initiator first [pending: task 10]:

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
[pending: task 10] [pending: task 13].

The ephemeral key stands in the associated data as bytes, because the Diffie-Hellman
values do not fix its bytes. The X25519 function gives one output for more than one
32-byte string: it ignores the most significant bit of the last byte (RFC 7748
section 5), and for a clamped private key a point and its sum with a point of small
order, which is another public key, give one output. Other bytes of either kind in
`ephemeral_key` therefore give the responder the same SK. They give another session
associated data, so no message decrypts under it [pending: task 10] [pending: task 13].
The record of an accepted initial message is found by these bytes and rests on that
(section 20.4).

### 16.6 The initiator

The initiator runs these steps in this order, for a contact and with a Bundle that it
fetched for this key agreement [pending: task 10]. One Bundle starts at most one session.

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
   derivation.
8. It initialises the ratchet as initiator with SK, SPK_B and 32 random bytes
   (section 17.3) and deletes SK. In one transaction it stores the session with its
   initial header (section 16.7) and, when the contact has no pinned X25519 identity
   key, `identity_dh_key` of the Bundle as its pin.

A key agreement that ends in a failure stores nothing, a pin included, and the client
reports the result (section 20.3). A session without a one-time prekey is a session like
any other for every later step; the threat model states what its first messages lose.

### 16.7 The initial header

The initial header is what the responder needs to run the same key agreement. It is the
`InitialHeader` message of section 19.3, with these values [pending: task 12]:

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

When the initiator sends it, and when it stops [pending: task 12]:

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
[pending: task 12]. Steps 1 and 2 run for every such message. Steps 3 to 9 run only when
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
message that decrypts to another plaintext [pending: task 10] [pending: task 12]:

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
message [pending: task 12] [pending: task 13]:

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
state [pending: task 11]. The same code can so be driven by a test, by a vector and by the
client.

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
(section 16.6, step 8) [pending: task 11]:

```
DHs       = a new X25519 key pair from the 32 random bytes
DHr       = SPK_B, the 32 bytes of the Bundle
RK, CKs   = KDF_RK(SK, DH(private key of DHs, DHr))
CKr       = empty
Ns, Nr, PN, DHSTEPS = 0
MKSKIPPED = no entry
```

The responder, from SK and the key pair of SPK_B (section 16.8, step 8)
[pending: task 11]:

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
key of the signed prekey [pending: task 12].

### 17.4 The two key derivations

KDF_RK(rk, dh) is one call of HKDF (RFC 5869). It returns a root key and a chain key
[pending: task 11]:

| Parameter          | Value                                                                    |
|--------------------|--------------------------------------------------------------------------|
| Hash               | SHA-256                                                                  |
| Salt               | rk, the 32 bytes of the root key                                         |
| Input key material | dh, the 32 bytes of one Diffie-Hellman output (section 16.3)             |
| Info               | ASCII `sotto/1 ratchet`, 15 bytes, hex `736f74746f2f312072617463686574`  |
| Output length      | 64 bytes                                                                 |
| Split              | Bytes 0 to 31 are the new root key. Bytes 32 to 63 are the chain key     |

KDF_CK(ck) is two calls of HMAC (RFC 2104) with SHA-256 under the same key. It returns a
message key and the next chain key [pending: task 11]:

| Output         | Key              | Data             | Length                                  |
|----------------|------------------|------------------|-----------------------------------------|
| Message key    | ck, 32 bytes     | The one byte `01` | 32 bytes, the whole HMAC value         |
| Next chain key | ck, 32 bytes     | The one byte `02` | 32 bytes, the whole HMAC value         |

KDF_CK has no salt, no info and no split. The calls are the `hmac` module of the Python
standard library and `HMAC<SHA256>` in CryptoKit.

This protocol calls HKDF in two places, sections 16.4 and 17.4, and their info strings
differ: `sotto/1 x3dh` and `sotto/1 ratchet` [pending: task 11].

### 17.5 The message header

The header of a message is 40 bytes [pending: task 11]:

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
steps, in this order [pending: task 11]:

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
[pending: task 11]:

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
before, and so are the skipped keys [pending: task 11]. A forged header can therefore not
move a chain, replace a ratchet key or remove a stored key. The client keeps the new state
only by the transaction of section 22.2.

Steps 3 and 4 make every check of a count before step 5, 6 or 7 derives a key: a header
that asks for more than MAX_SKIP keys costs the receiver no key derivation
[pending: task 11].

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
is removed before the new one is added [pending: task 11].

The rules [pending: task 11]:

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
that Ns, Nr and PN, which count the messages of a chain, fit a u32 [pending: task 11].

- A client whose Ns is 2^32 - 1 cannot encrypt on that sending chain: the result is
  CHAIN_EXHAUSTED. The next DH ratchet step, taken when a message of the peer with a new
  ratchet key decrypts, begins a new sending chain. Until then the user can reset the
  session (section 20.2).
- A received header with N = 2^32 - 1 gets the result CHAIN_EXHAUSTED before any key is
  derived.

## 18. Message encryption

### 18.1 The cipher

A message is sealed with ChaCha20-Poly1305, the AEAD of RFC 8439 section 2.8
[pending: task 11]:

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

Total length: 217 bytes [pending: task 11].

- The sender takes the message id that it puts into the Send. The receiver takes the
  `message_id` of the Deliver and the `header` field exactly as it received them. It
  never builds the header again from numbers [pending: task 11] [pending: task 12].
- The three parts have fixed lengths, so the 217 bytes split in one way only and no
  length is written in front of a part.
- The message id is the key by which a receiver discards copies (section 20.4). In the
  associated data it is authentic: a message whose id was changed on the way does not
  decrypt [pending: task 13].
- The caller of the ratchet passes the first 177 bytes with every call, and the ratchet
  adds the header [pending: task 11].

### 18.3 The wire layout

The `ciphertext` field of the envelope (section 19.2) holds, for a padded plaintext of L
bytes [pending: task 11]:

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
[pending: task 12].

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
  }
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
- `Content` is a oneof with one member. A kind of message that is added later is a new
  member of the oneof with the next number, and travels as a message of the ratchet like
  a text.

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
into a result, in this order [pending: task 12]:

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

After a message decrypted and its padding was removed (section 19.6), the client parses
the bytes as a `Content` [pending: task 12]:

- Bytes that do not parse, a `text` that is not UTF-8 included, give the result
  BAD_CONTENT.
- A `Content` in which no member that the client knows is set gives the result
  UNKNOWN_CONTENT. A client of version 1 knows one member, `text`.
- The text is whatever the peer chose to send. The command-line client of this
  repository prints it with the C0, C1 and bidirectional control characters escaped
  [pending: task 14].

A message with the result BAD_CONTENT or UNKNOWN_CONTENT is a real message of the peer:
it decrypted. The client keeps the new ratchet state and the seen id and acks the
message, and it has no text to show (section 20.3).

### 19.6 Padding

The plaintext that is sealed is the serialized `Content`, then one byte `80`, then bytes
`00` up to the next multiple of PADDING_BLOCK, 256 bytes [pending: task 12]:

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
agreement [pending: task 12].

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
a text: the largest frame bounds it [pending: task 12].

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
to the head lies furthest back [pending: task 13].

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
that state. The client does what the table says [pending: task 12] [pending: task 13].

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

How the conditions are decided [pending: task 12] [pending: task 13]:

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

Rules that hold for every row [pending: task 12] [pending: task 13]:

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
  not be read. A client MAY show the third as a message of a kind it does not know.
- A bundle without a one-time prekey starts a session all the same: START never fails
  for the lack of one (section 16.6). A client that refused such a bundle could be cut
  off from a contact by anyone who empties the handout bucket of that contact
  (section 9.3).

### 20.4 Seen ids and records

Seen ids [pending: task 12]:

- ACCEPT and ACCEPT-NEW save the pair (sender, message id) of the message. No other
  action saves one. The id of a message that did not decrypt is not authentic
  (section 18.2): a saved id of that kind would let whoever controls the relay block a
  real message by delivering a forged one under its id first.
- The seen ids are checked before the payload is parsed and before any key is touched.
  The ratchet alone cannot tell a copy from a forgery: for both its answer is
  DECRYPT_FAILED.
- A seen id is kept for SEEN_ID_SECONDS, 3196800 seconds: MESSAGE_TTL_SECONDS and one
  week, 37 days. The client deletes it at the first login after that time, and until it
  is deleted it counts as seen.
- A copy that arrives after the deletion is no duplicate for the table. The ratchet
  refuses it, because its message key is used: the copy is shown as a message that could
  not be read and is never read a second time.

Records of accepted initial messages [pending: task 13]:

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
sessions stay in the list [pending: task 13]. While messages of the two clients cross on
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
  its initial header. Only a user starts a reset [pending: task 13].
- A gap (L3) is the one notice of a lost message. A skipped key stands for a message
  whose number the peer used and which did not arrive. When the cap or the purge of
  section 17.8 removes such a key, or a session that holds some is deleted from the
  list, the message can never be read, and the client reports the number
  [pending: task 13]. Messages that were lost at the end of a conversation, with no later
  message behind them, leave no skipped key and no notice.
- A client that removes a contact deletes the sessions of that contact. It keeps the
  seen ids and the records until their own rules delete them: an initial message that
  was accepted before the removal would otherwise be accepted again once the id is a
  contact again [pending: task 13].

## 21. The prekey lifecycle

### 21.1 The clock and the prekey ids

- A client reads the time from one clock, in whole seconds. An implementation takes the
  clock as an argument, so that a test can set it [pending: task 13].
- A client that does not run does nothing. The rules of this section take effect after
  a LoggedIn; the deletion of step 1 of section 21.2 also takes effect when the client
  starts.
- A client keeps two counters per identity in its store, one for signed prekeys and one
  for one-time prekeys. The first key of a kind gets the id 1, every later key the id of
  the key before it plus 1. The counter is saved in the transaction that saves the key.
  An id is so never used for two keys of one kind, after a crash and after the deletion
  of a key included [pending: task 13].
- An identity whose counter reached 2^32 - 1 makes no further key of that kind
  [pending: task 13].
- These are rules for the owner of the keys. A receiver accepts any id from 0 to
  2^32 - 1 (section 5.2).

### 21.2 The signed prekey

The newest signed prekey of a client is the one it made last. After every LoggedIn the
client does this, in this order [pending: task 13]:

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
   [pending: task 14].

Step 1 needs no connection. The client also runs it every time it starts, before it
dials the relay [pending: task 14]. A client that stays on one connection SHOULD run the
three steps again when the newest signed prekey reaches the age of step 2 or a grace
period ends.

The grace period [pending: task 13]:

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
  [pending: task 14].
- The relay sends no notice when the number falls (section 9.4). A client MAY refill
  during a connection as well, from the last count the relay reported less the number
  of initial messages it accepted since then that named a one-time prekey.
- The private key of a one-time prekey is deleted when the initial message that names
  it is accepted (section 16.8, step 9), and not when a message that names it fails
  [pending: task 12].
- A client holds at most ONE_TIME_PREKEY_HELD_MAX, 1000, private keys of one-time
  prekeys. Before it makes a batch that would go over, it deletes the ones with the
  lowest ids until the batch fits [pending: task 13]. The count is the word of the
  relay, and fetches by anyone lower it (section 9.3): without this bound a client would
  make keys without end. An initial message that names a key deleted in this way gets
  UNKNOWN_ONE_TIME_PREKEY.

### 21.4 The upload

- An UploadBundle carries the X25519 identity key with its signature, the newest signed
  prekey with its id and its signature, and the new one-time prekeys, if any
  (section 7.8).
- After a LoggedIn a client sends at most one UploadBundle for the steps of sections
  21.2 and 21.3, before any Send of that login (section 23.3) [pending: task 14]. A
  rotation or a refill during the connection (sections 21.2 and 21.3) is a further
  UploadBundle.
- A one-time prekey is uploaded once (section 9.1). The client marks the one-time
  prekeys of an UploadBundle as uploaded in its store before the frame leaves, and never
  puts a marked key into another frame. The keys of an UploadBundle that got no answer
  stay marked [pending: task 13].
- An UploadBundle that the relay refused with an Error whose action is Back off is sent
  again unchanged on the same connection (section 11.1): the same frame, not a new one
  with the same keys in it.
- An UploadBundle that waits in Back off, or that has no answer, when the connection
  ends is not sent again, and after the next LoggedIn the steps of sections 21.2 and
  21.3 build the UploadBundle of that login [pending: task 14]. The one-time prekeys of
  a frame that has no answer stay marked: the relay can hold them. The relay holds none
  of a frame that waits in Back off, because it refused the frame each time it was sent
  (section 11.2): the client deletes the private keys of the one-time prekeys of that
  frame [pending: task 13]. Kept, they would count toward the bound of section 21.3,
  and while the relay refuses every upload a client would in the end delete the keys
  that the relay still hands out.
- The X25519 identity key and its signature are the same in every upload
  (section 5.3).

## 22. The client store

### 22.1 What it holds

A client keeps, for one identity [pending: task 12]:

- the seed of the identity and the private key of its X25519 identity key;
- the private keys of its signed prekeys and of its one-time prekeys with their ids, the
  two counters of section 21.1 and the times that section 21.2 needs;
- its contacts with their pinned X25519 identity keys;
- the sessions of every contact, in their order (sections 17.2 and 20.1);
- the seen ids and the records of accepted initial messages (section 20.4);
- the outbox: for every message that it encrypted and that the relay has not confirmed,
  the message id, the recipient and the bytes of the payload;
- the message log: the texts it sent and received.

No frame and no payload carries the seed or a private key [pending: task 14].

### 22.2 The two ordering rules

On receive [pending: task 12] [pending: task 14]:

- The client sends the Ack for a message that it accepted only after one transaction
  committed everything the message changes: the new ratchet state of its session, the
  text and the seen id, and for an initial message what step 9 of section 16.8 lists.
- An Ack tells the relay to delete the only other copy (section 10.5). A client that
  stops between the commit and the Ack gets the message again after its next login and
  drops it as a duplicate. A client that stops before the commit gets it again and
  decrypts it: its state did not change.
- The Ack for a Deliver that is dropped or that failed (section 20.3) waits for nothing:
  the client saved nothing.

On send [pending: task 12] [pending: task 14]:

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
that deletes it, in none of the files of the store [pending: task 13]. What lies below the
files, the blocks that a filesystem keeps of an overwritten or removed file, is out of
scope, as it is for the relay (section 13.3).

### 22.4 The store of the client of this repository

The rules above hold for every client. How a client keeps its store is its own matter;
the macOS client is free to keep keys in the keychain. The client of this repository does
this [pending: task 12]:

- The store is one SQLite file per identity in a data directory. The directory has mode
  0700 and the file mode 0600, and both are set before the first byte is written.
- The client refuses to start when the directory or the file gives any right to the
  group or to others, that is, when its mode has one of the bits 077.
- The database uses the rollback journal and not a write-ahead log, with `secure_delete`
  on and one connection: no second file keeps older ratchet states.
- The seed is never taken from a command line argument and never printed.

Nothing in the store is encrypted. Whoever can read the file holds the identity and
everything else in section 22.1; the threat model says what follows from that.

## 23. The client transport

### 23.1 The URL

A client is given the URL of its relay; no URL is built into it [pending: task 14].

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
  (section 6.3) [pending: task 14].
- The client connects to the host of the URL itself. It takes no proxy from its
  environment [pending: task 14]: a proxy that the user did not ask for would see the
  address of the relay and, on a `ws` URL, every frame.
- The client answers pings and requires no subprotocol (sections 6.2 and 6.4).

### 23.3 After the login

After a LoggedIn the client does this, in this order [pending: task 14]:

1. The steps of sections 21.2 and 21.3, and the one UploadBundle they ask for. Until the
   relay holds the bundle of an identity, the identity is not registered and nobody can
   send to it (section 8.6), a peer that answers included.
2. Every row of the outbox, oldest first, as a Send (section 22.2).
3. The deletion of the seen ids whose time is over (section 20.4).

A Deliver can arrive from the LoggedIn on, between any two of these steps, and is handled
as it arrives (section 20.2).

### 23.4 The reconnect schedule

This is the wait of the action Retry of section 11.1 [pending: task 14].

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

This is the wait of the action Back off of section 11.1 [pending: task 14].

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
  hold the first three [pending: task 11]. No vector of section 24.3 covers the other
  two, because the padded plaintext is an input of a ratchet vector: the tests of the
  session hold the padding and the largest text [pending: task 12].
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

### 24.3 What the test vectors record

Section 15 holds the schema, and every rule of it applies: every private key, ephemeral
key, nonce and message id is an input, and replaying a vector draws no random byte. The
names of the operations and the keys of their objects enter section 15 with the files.

A vector of the key agreement records [pending: task 10]:

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
[pending: task 11]:

| Object          | Values                                                                                   |
|-----------------|------------------------------------------------------------------------------------------|
| `inputs`        | SK and the session associated data; the key pair of the signed prekey; the 32 random bytes of the ratchet private key of every initialisation of an initiator and of every decryption that reaches sub-step 4 of step 5 of section 17.7, a decryption that then fails included; for every message the message id, the nonce and the padded plaintext; the order in which the messages are delivered |
| `intermediates` | For every DH ratchet step the Diffie-Hellman outputs and the root key and chain key of each KDF_RK; for every message the chain key before it, its message key, the 40 bytes of its header and the 217 bytes of its associated data; every skipped key that was stored or purged |
| `outputs`       | For an encryption the bytes of the `ciphertext` field; for a decryption the plaintext    |

The conversation covers messages in order and out of order, lost messages, several DH
ratchet steps and the negative cases of section 17.7.

Appendix A is reserved for one such run in full, written out in hex.

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
- Several devices per identity, groups, attachments and calls.
- Any claim of deniability (section 25.5).
- Encryption of the client store, and key storage in a keychain or in hardware.
- Moving an identity to another device, and a backup of it.
- Replacing or revoking an identity key.
- Delivery receipts, read receipts and requests to send a message again.
- Expiry of a session by time.
- Kinds of content other than a text. The oneof of section 19.1 is their place.

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

## Appendix A. One key agreement and two messages in hex

This appendix is reserved. It follows the last numbered section and holds one run of the
protocol written out in hex, every value in the order in which sections 16 to 19 compute
it [pending: task 11]:

- the key agreement between an initiator and a responder with a one-time prekey: every
  private key and public key, the signed strings, DH1 to DH4, the input key material, SK
  and the 161 bytes of the session associated data;
- the first message of the initiator: the ratchet key pair, the Diffie-Hellman output,
  the root key and the chain key, the message key, the 40 bytes of the header, the
  message id, the nonce, the padded plaintext, the 217 bytes of the associated data, the
  bytes of the `ciphertext` field, and the fields of its initial header;
- the first message of the responder in answer: the same values for its DH ratchet step
  and its message, without an initial header.

The values are taken from the vector files of sections 15 and 24.3, so that the text and
the vectors cannot differ. Until the appendix is filled, this text has no worked example
of part 2.
