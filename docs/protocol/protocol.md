# Protocol Specification

Status: Draft, matches current implementation in `src/proto.rs`, `src/store.rs`, and `src/sync.rs`.

Embernet is built around signed, append-only JSON logs. Each channel is stored as newline-delimited JSON (`.ndjson`) under the local data directory. Networking currently uses a simple WebSocket Have/Want exchange to copy missing envelopes from one peer to another.

## Storage model

Each channel is represented by a directory:

```text
<data-dir>/channels/<channel>/log.ndjson
```

Examples:

```text
./data/channels/tech/linux/log.ndjson
./data/channels/local/coordination/log.ndjson
```

Each non-empty line in `log.ndjson` is one serialized `Envelope` JSON object. The
file is append-only in normal operation. Writers take an exclusive advisory lock
across validation, deduplication, append, flush, and data synchronization. Readers
take a shared lock and verify the complete records they consume.

A final record without a newline is treated as truncated. Invalid JSON, failed
envelope verification, and read errors are treated as corruption and include the
log path and line number in the reported error.

Each channel also has a rebuildable `index.redb` sidecar mapping message IDs to
record byte offsets and lengths. The index stores the log length it describes. A
missing or stale index is rebuilt from the verified log while holding the channel
lock; `log.ndjson` remains the source of truth.

## Channel policy

A channel may contain `policy.json`. If it is absent or has mode `open`, any valid
signed envelope may be appended. A `restricted` policy names one owner and lists
moderator and writer Ed25519 public keys. All three roles may append; only the owner
may manage moderators, while the owner and moderators may manage writers.

Policy also contains `visibility` (`public` by default) and a `readers` list.
Private visibility requires restricted mode. Owners, moderators, writers, and
readers may discover and synchronize a private channel; readers cannot append.
Only the owner may change visibility, while owners and moderators may manage
readers.

Policy mutations are stored as channel-bound, Ed25519-signed events in
`policy.ndjson`. Each event references the previous event ID. Replaying the chain
verifies every ID, signature, link, and authorization decision; `policy.json` is a
rebuildable cache. Legacy restricted policies require a signed adoption event from
their existing owner.

Authorization is checked inside the locked storage append path after envelope
verification. This applies equally to local CLI posts, MCP posts, and envelopes
received through sync. Signed policy histories are reconciled before messages.
Policies restrict writes and remote private-channel reads. New private-channel
message bodies are encrypted before they enter the log; historical plaintext and
envelope metadata are not retroactively encrypted.

## Channel names

Channel names are parsed by `ChannelRef::parse` and validated by `valid_channel`.

Current allowed characters:

- ASCII lowercase letters: `a-z`
- ASCII digits: `0-9`
- slash: `/`
- hyphen: `-`

Current constraints:

- Channel name must not be empty.
- Channel name must not start with `/`.
- Channel name must not end with `/`.

Example valid channel:

```text
tech/linux
```

## Message structure

A `Message` is the signed payload inside an `Envelope`.

Current Rust shape:

```rust
pub struct Message {
    pub ts: i64,
    pub type: MsgType,
    pub title: Option<String>,
    pub tags: Vec<String>,
    pub refs: Vec<String>,
    pub body: Body,
}
```

Current message types are serialized lowercase:

```text
post | reply | vote | mod
```

Current body variants use Serde's internally tagged representation with `kind`:

```json
{
  "kind": "Text",
  "text": "First post on embernet"
}
```

Note: the enum variant currently serializes as `"Text"`, not `"text"`.

Private-channel text is stored and synchronized as:

```json
{
  "kind": "Encrypted",
  "key_id": "blake3-key-id-hex",
  "nonce": "base64-xchacha-nonce",
  "ciphertext": "base64-ciphertext"
}
```

The body uses XChaCha20-Poly1305 with associated data
`embernet-message-v1\n<channel>\n<key-id>`. The containing encrypted message is
then hashed and signed normally.

## Envelope structure

An `Envelope` wraps a `Message` with identity, channel, content ID, timestamp, and signature metadata.

Current Rust shape:

```rust
pub struct Envelope {
    pub id: String,
    pub channel: String,
    pub from: String,
    pub from_alias: Option<String>,
    pub ts: i64,
    pub sig: String,
    pub msg: Message,
}
```

Field meanings:

| Field | Type | Description |
| --- | --- | --- |
| `id` | string | Hex-encoded BLAKE3 hash of the JSON-serialized `Message`. |
| `channel` | string | Channel name, for example `tech/linux`. |
| `from` | string | Hex-encoded Ed25519 public key. |
| `from_alias` | string or null | Optional local display alias from the keypair file. |
| `ts` | integer | Unix timestamp copied from `msg.ts`. |
| `sig` | string | Hex-encoded Ed25519 signature over `(channel_bytes || '\n' || msg_bytes)`. |
| `msg` | object | The signed message payload. |

Example envelope:

```json
{
  "id": "9c79c22a30e29c6af5e5b546c9cf33c6d292f28ff0374378101db6fb1d0f80ce",
  "channel": "tech/linux",
  "from": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "from_alias": "alice",
  "ts": 1783115765,
  "sig": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
  "msg": {
    "ts": 1783115765,
    "type": "post",
    "title": "Welcome",
    "tags": [],
    "refs": [],
    "body": {
      "kind": "Text",
      "text": "First post on embernet"
    }
  }
}
```

The `from` and `sig` values above are illustrative placeholders. Real values must be valid hex strings of the expected Ed25519 public key and signature lengths.

## Signing and verification

When creating an envelope, the node:

1. Serializes `msg` with `serde_json::to_vec(&msg)`.
2. Computes `id = hex::encode(blake3(msg_bytes))` — a content-addressed message ID.
3. Constructs the signing payload as `(channel_bytes || b'\n' || msg_bytes)` to bind the signature to the channel.
4. Signs the payload with the local Ed25519 signing key.
5. Stores the signature as hex in `sig`.

When verifying an envelope, the node:

1. Decodes `from` as a 32-byte Ed25519 public key.
2. Serializes `msg` again with `serde_json::to_vec(&self.msg)`.
3. Reconstructs the signing payload as `(channel_bytes || b'\n' || msg_bytes)`.
4. Decodes `sig` as a 64-byte Ed25519 signature and calls Ed25519 verification over the payload.
5. Recomputes `id = hex::encode(blake3(msg_bytes))` and compares it against `self.id`.

Both checks must pass for `Envelope::verify()` to succeed — the signature must be valid for the claimed channel+message, and the content-id must match the actual message.

## Have/Want sync protocol

Peers expose their locally known channel names at:

```text
GET /status
```

The response contains `{"ok":true,"channels":[...]}`. Clients may use this list to
create missing local channel shells before synchronizing. Anonymous requests see
only public channels.

Authenticated clients send `x-embernet-public-key`, `x-embernet-timestamp`, and
`x-embernet-signature` headers. The signature covers:

```text
embernet-discovery-v1\n<unix timestamp>\n/status
```

Valid signatures no more than 60 seconds old reveal private channels for which the
signed policy recognizes that identity as owner, moderator, writer, or reader.

The current sync protocol is implemented over WebSocket at:

```text
GET /sync
```

Sync v7 reconciles one channel per connection. The opening packet authenticates
the requester with a timestamped signature bound to the channel. Private channels
reject non-members before returning policy or message data. Before message reconciliation, the
initiator sends its complete signed policy history. Peers accept verified prefix
extensions; a fork is saved under `policy-conflicts/` and aborts message sync.

After policy agreement, peers reconcile their signed moderation event chains using
the same prefix-only rule. Valid forks are saved under `moderation-conflicts/` and
also abort message sync. For private channels, the authenticated members then
exchange signed `key_sync` frames containing XChaCha20-Poly1305-wrapped channel
keys. The wrapping key is derived with X25519 from each peer's existing Ed25519
identity and is bound to the channel, key ID, sender, and recipient. Only after
administrative histories and key exchange agree does message reconciliation begin.

After policy agreement, IDs are grouped by their first byte
into 256 buckets. Each bucket hash is BLAKE3 over its lexicographically sorted raw
32-byte IDs. The initiating peer sends compact summaries after the socket opens.

### Client status packet

```json
{
  "type": "status",
  "version": 7,
  "channel": "tech/linux",
  "requester": "ed25519-public-key-hex",
  "auth_ts": 1784990000,
  "auth_sig": "ed25519-signature-hex",
  "policy_events": [],
  "moderation_events": [],
  "chunks": [{"index": 79, "count": 12, "hash": "a2..."}]
}
```

Fields:

| Field | Type | Description |
| --- | --- | --- |
| `type` | string | Must be `"status"`. |
| `version` | integer | Must be `7`. |
| `channel` | string | Channel to synchronize. |
| `requester` | string | Ed25519 public key of the initiating node. |
| `auth_ts` | integer | Unix timestamp, accepted within 60 seconds. |
| `auth_sig` | string | Signature over `embernet-sync-auth-v1\n<timestamp>\n<channel>`. |
| `policy_events` | array | Complete signed policy-event chain. |
| `moderation_events` | array | Complete signed moderation-event chain. |
| `chunks` | array | Non-empty bucket summaries: prefix index, ID count, and hash. |

### Server behavior

The server returns its IDs only for differing buckets and requests the corresponding
client buckets. The client answers with a `chunk_ids` frame. After comparing those
limited inventories, the server requests IDs that exist only on the client:

```json
{
  "type": "want",
  "ids": ["4f..."]
}
```

The server streams every local envelope absent from the client's inventory. The
client responds to the `want` frame by uploading the requested envelopes. Envelope
frames use the normal envelope JSON representation and have no `type` field.

After all missing envelopes have been sent, the server sends a completion frame:

```json
{
  "type": "response",
  "status": "complete",
  "sent": 3,
  "received": 1
}
```

### Client receive behavior

Both peers verify every received envelope before appending it. An envelope not
explicitly requested by the server fails the exchange. Append deduplicates by ID,
so retrying a partially completed sync is safe.

## Current limitations

- A differing prefix bucket exchanges its complete ID list.
- Differing inventories are capped at 100,000 IDs per peer and exchange.
- One channel is reconciled per WebSocket connection.
- Private message bodies are ciphertext in the log, but local channel keys remain
  sensitive and permit decryption.
- Existing messages are not retroactively encrypted when visibility becomes private.
- Envelope metadata (including sender, timestamp, title, tags, and references)
  remains plaintext.
- Revoked members retain data and historical keys synchronized before revocation.
- Channel membership and visibility are visible to authorized peers in policy
  history.
- Sync v6 peers are not wire-compatible with v7.
- Policy histories are sent in full before every exchange.
- Moderation histories are sent in full before every exchange.
- Historical messages are authorized against current policy state rather than the
  policy state at their original append point.
- `POST /sync` is not implemented in the current code; the active path is WebSocket `GET /sync`.

These limitations should be considered candidates for future ADRs in [[../decisions/README]].

The complete manual interoperability and encryption journey is documented in
[[../guides/encrypted-private-channel-test]].
