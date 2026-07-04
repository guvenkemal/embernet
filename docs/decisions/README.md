# Decision Log

This folder contains Architecture Decision Records (ADRs).

Use ADRs when a technical choice should be durable, reviewable, and understandable by future contributors.

Start from [[adr-template]].

## Suggested ADRs

- Why Rust for the implementation language.
- Why BLAKE3 for message IDs.
- Why Ed25519 signatures for identity and integrity.
- Why newline-delimited JSON (`.ndjson`) for the initial append-only log format.
- Why WebSocket Have/Want sync for Phase 1 federation.

## Format

Each ADR should include:

- Title
- Status: Proposed, Accepted, or Deprecated
- Context: the problem
- Decision: the choice
- Consequences: pros and cons
