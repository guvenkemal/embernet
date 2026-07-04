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

Each non-empty line in `log.ndjson` is one serialized `Envelope` JSON object. The file is append-only in normal operation.

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

The current sync protocol is implemented over WebSocket at:

```text
GET /sync
```

The client sends one status packet after the WebSocket opens.

### Client status packet

```json
{
  "type": "status",
  "channel": "tech/linux",
  "count": 15
}
```

Fields:

| Field | Type | Description |
| --- | --- | --- |
| `type` | string | Must be `"status"`. |
| `channel` | string | Channel to synchronize. |
| `count` | integer | Number of local non-empty log entries the client already has for the channel. |

### Server behavior

The server parses and validates the channel name, then counts its own local messages for the requested channel.

If the server has no additional messages:

```json
{
  "type": "response",
  "status": "up_to_date"
}
```

This is sent when:

```text
server_count <= client_count
```

If the server has more messages, it reads from the client's count offset and streams each missing `Envelope` as a JSON text frame.

After all missing envelopes have been sent, the server sends a completion frame:

```json
{
  "type": "response",
  "status": "complete",
  "sent": 3
}
```

### Client receive behavior

For each text frame received from the peer, the client first tries to parse it as a sync response. If it is not a response, the client treats it as an `Envelope`.

For each received envelope, the client:

1. Deserializes the JSON into `Envelope`.
2. Calls `Envelope::verify()`.
3. Appends the verified envelope to the local channel's `log.ndjson`.

Invalid signatures fail the sync instead of being appended.

## Current limitations

- Sync is count-based. It assumes peers share the same ordered prefix for a channel.
- There is no deduplication by `id` on append.
- The server currently streams server-to-client only for the requested channel.
- `POST /sync` is not implemented in the current code; the active path is WebSocket `GET /sync`.

These limitations should be considered candidates for future ADRs in [[../decisions/README]].
