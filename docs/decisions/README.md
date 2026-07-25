# Decision Log

This folder contains Architecture Decision Records (ADRs).

Use ADRs when a technical choice should be durable, reviewable, and understandable by future contributors.

Start from [[adr-template]].

## Accepted

- [[adr-001-log-storage]] — Store channel logs as newline-delimited JSON.
- [[adr-002-id-inventory-sync]] — Reconcile divergent peers by message-ID inventory.
- [[adr-003-locked-durable-channel-appends]] — Serialize durable channel writes and detect corruption.
- [[adr-004-rebuildable-message-index]] — Index IDs and record locations while keeping logs authoritative.
- [[adr-005-prefix-bucket-merkle-sync]] — Reconcile deterministic ID-prefix buckets before messages.
- [[adr-006-local-channel-write-acls]] — Enforce owner, moderator, and writer roles locally.
- [[adr-007-signed-policy-event-chain]] — Derive policy from a signed, chained audit log.
- [[adr-008-prefix-only-policy-federation]] — Reconcile policy prefixes and quarantine forks.
- [[adr-009-signed-moderation-overlay]] — Hide or restore messages without deleting envelopes.
- [[adr-010-thin-terminal-client]] — Build the first frontend as a thin terminal client.
- [[adr-011-persistent-peers-and-background-sync]] — Discover and periodically synchronize saved peers.
- [[adr-012-managed-tui-listener]] — Let the terminal client accept peer connections.
- [[adr-013-private-channel-membership]] — Authenticate discovery and sync against signed membership.

## Suggested ADRs

- Why Rust for the implementation language.
- Why BLAKE3 for message IDs.
- Why Ed25519 signatures for identity and integrity.
- Why newline-delimited JSON (`.ndjson`) for the initial append-only log format.

## Format

Each ADR should include:

- Title
- Status: Proposed, Accepted, or Deprecated
- Context: the problem
- Decision: the choice
- Consequences: pros and cons
