# Decision Log

This folder contains Architecture Decision Records (ADRs).

Use ADRs when a technical choice should be durable, reviewable, and understandable by future contributors.

Start from [[adr-template]].

## Accepted

- [[adr-001-log-storage]] — Store channel logs as newline-delimited JSON.
- [[adr-002-id-inventory-sync]] — Reconcile divergent peers by message-ID inventory.
- [[adr-003-locked-durable-channel-appends]] — Serialize durable channel writes and detect corruption.
- [[adr-004-rebuildable-message-index]] — Index IDs and record locations while keeping logs authoritative.

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
