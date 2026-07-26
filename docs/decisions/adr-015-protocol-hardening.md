# ADR 015: Bind authentication to one-time challenges and harden local durability

Status: Accepted

## Context

The first authenticated discovery and sync design signed only a timestamp and
request target. A captured signature could therefore be replayed against another
peer during its 60-second validity window. Policy reconciliation could also revoke
a requester after the server's initial membership check but before channel-key
delivery.

An adversarial review also identified local durability and resilience gaps:
identity permissions followed the process umask, conflict resolution replaced the
current branch without preserving it, administrative history reads did not share
writer locks, duplicate uploads could satisfy a Have/Want counter, and network
operations could wait indefinitely.

## Decision

- Discovery uses a bounded set of random, single-use `/challenge` nonces.
- Every WebSocket sync begins with a socket-specific challenge.
- Authentication signatures bind the timestamp, request target or channel,
  challenge nonce, and responder identity.
- Private membership is checked before and again after policy reconciliation,
  before any channel-key offer is sent.
- Sync v8 removes requested IDs from a set and completes only after every distinct
  requested envelope arrives.
- Identity and channel-key files are atomically created with mode `0600` on Unix;
  existing canonical identities are repaired when loaded.
- Policy and moderation histories use shared reader and exclusive writer sidecar
  locks.
- Resolving a fork first saves the displaced local history as another conflict.
- Peer configuration read-modify-write operations are serialized.
- Sync operations have deadlines, manual TUI sync runs outside the render loop,
  and terminal/listener cleanup is guarded for errors, signals, and unwinding.
- Envelope verification requires the outer timestamp to equal the signed message
  timestamp, and channel names reject empty path segments.

## Consequences

- A captured authentication frame cannot be replayed in a later session or
  against a different responder.
- Nodes running sync v7 or earlier are not wire-compatible with sync v8.
- Challenge state consumes bounded memory and is intentionally short-lived.
- Conflict selection remains an explicit potentially destructive choice, but both
  valid branches remain recoverable.
- Administrative reads may briefly wait for an in-progress append instead of
  observing a partial record.
- Local secret files no longer depend on a permissive system umask.

[[adr-016-peer-identity-pinning]] subsequently authenticates signed responder
challenges against explicit pins for persistent peers.

Related: [[adr-003-locked-durable-channel-appends]],
[[adr-013-private-channel-membership]], [[adr-014-private-channel-encryption]],
[[../protocol/protocol]]
