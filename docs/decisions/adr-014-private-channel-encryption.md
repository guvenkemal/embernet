# ADR 014: Encrypt private-channel message bodies

Status: Accepted

## Context

Private visibility originally prevented unauthorized discovery and synchronization,
but message bodies remained plaintext in `log.ndjson` and on the wire. Users
reasonably expect a private channel's content to be readable only at member
endpoints.

Embernet already identifies members with Ed25519 keys. Adding a second manually
managed identity would complicate initialization and membership policy.

## Decision

New messages posted while a channel is private encrypt their text body with a
random 256-bit channel key using XChaCha20-Poly1305. The ciphertext, nonce, and key
ID replace the plaintext body before the message is hashed and signed, so the
append-only log and synchronization frames contain ciphertext.

Each node keeps the channel keys it knows in `channel-keys.json`, written with
owner-only filesystem permissions. During authenticated sync, members derive
X25519 keys from their existing Ed25519 identity using the standard Edwards-to-
Montgomery conversion. Peers wrap every known channel key for the other member,
sign the offer with Ed25519, and bind it to the channel, key ID, sender, and
recipient.

Only identities authorized by the reconciled signed channel policy may exchange
keys. Revoking a member role generates a new channel key. Historical keys remain
available so retained history can still be decrypted.

## Consequences

- Relays and append-only logs can store and forward private messages without
  seeing their text.
- No additional user-facing identity or key registration is required.
- A newly authorized member receives historical keys and can read retained
  history.
- A revoked member retains messages and keys received before revocation but does
  not receive the rotated key for later messages.
- Existing plaintext messages are not retroactively encrypted.
- Envelope metadata—sender, timestamp, title, tags, and references—remains visible.
- Compromise of an authorized endpoint or its local keyring exposes the channel
  keys stored there.
- Key recovery, multi-device identity management, metadata encryption, and a
  formal mechanism for resolving malicious member-created key epochs remain
  future work.

Related: [[adr-013-private-channel-membership]], [[../protocol/protocol]],
[[../guides/encrypted-private-channel-test]]
