# ADR 016: Pin signed responder identities for persistent peers

Status: Accepted

## Context

Sync v8 introduced one-time, responder-bound challenges, preventing a captured
requester signature from being replayed in another session. A client still needed
a way to know that the responder named in a challenge was the intended remote
node rather than an active relay presenting its own identity.

Automatically trusting the first network response would make configuration easy
but would preserve a first-connection interception risk. Embernet identities are
already portable public keys, so users can exchange them out of band.

## Decision

Every discovery and WebSocket challenge is signed by the responder's Ed25519
identity and bound to its target (`/status` or `/sync`), nonce, responder key, and
expiry.

The signed-challenge wire format is sync v9.

Persistent peer records use schema version 2 and contain:

```json
{
  "url": "ws://127.0.0.1:4444/sync",
  "public_key": "expected-ed25519-public-key-hex"
}
```

`peer-add` requires the expected public key. Discovery and synchronization verify
the challenge signature and require its responder to match the saved pin before
the requester signs or sends channel state. An identity mismatch fails closed.
Changing a pin requires removing the peer and adding it again, making the trust
change explicit.

Version-1 string entries remain readable but are treated as unpinned and cannot
automatically synchronize until the user supplies a public key. The `identity`
command prints the local public key for out-of-band exchange.

Direct ad-hoc `sync` accepts `--public-key`, which saves or verifies the pin.
Library-level unsaved connections remain opportunistically authenticated for
tests and embedding, but persistent automatic synchronization is strict.

## Consequences

- A saved peer cannot silently change identity or be replaced by an active relay.
- Users must exchange public keys through a trusted side channel.
- Existing `peers.json` files remain parseable but require a one-time pinning step.
- Legitimate identity replacement is intentionally explicit: remove, verify the
  new key, and add the peer again.
- URL changes create distinct trust records.

Related: [[adr-011-persistent-peers-and-background-sync]],
[[adr-015-protocol-hardening]], [[../protocol/protocol]]
