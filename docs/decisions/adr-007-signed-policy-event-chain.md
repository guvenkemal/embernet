# ADR 007: Make signed policy events authoritative

- Status: accepted
- Date: 2026-07-18

## Context

Mutable `policy.json` files enforce local ACLs but cannot prove who changed a role,
detect tampering, or reconstruct earlier policy state.

## Decision

Policy mutations are Ed25519-signed events in `policy.ndjson`. Each event is bound
to the channel and previous event ID. Its ID is BLAKE3 over the canonical JSON
payload, and its signature covers the domain separator `embernet-policy-v1`, a
newline, and those payload bytes.

The event chain is replayed from an open policy. Replay verifies IDs, signatures,
chain links, and the actor's authority at each event. `policy.json` is a rebuildable
cache. Owners may manage moderators and transfer ownership; owners and moderators
may manage writers. A legacy restricted policy can be adopted only by its owner
through a signed genesis event.

## Consequences

- Policy history is attributable, tamper-evident, and reconstructable.
- Ownership transfer and role revocation remain append-only audit records.
- Corrupt or unauthorized events invalidate policy replay.
- [[adr-008-prefix-only-policy-federation]] supersedes the initial local-only scope
  with verified prefix synchronization and explicit fork handling.
