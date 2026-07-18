# ADR 002: Reconcile channels by message-ID inventory

- Status: accepted
- Date: 2026-07-14

## Context

Sync v1 compared channel message counts and assumed both logs shared the same ordered
prefix. Peers with different messages but equal counts were incorrectly considered
up to date. A retry could also reproduce messages already delivered.

## Decision

Sync v2 exchanges the complete ordered message-ID inventory for one channel. The
server requests client-only IDs and sends server-only envelopes during the same
WebSocket session. Both peers verify received envelopes, and storage deduplicates
appends by ID. Inventories are capped at 100,000 IDs.

## Consequences

- Divergent peers converge without assuming a shared prefix.
- One CLI sync operation transfers messages in both directions.
- Interrupted exchanges can be retried safely.
- Inventory cost remains linear in log size. A persistent ID index and Merkle-chunked
  inventory are the intended follow-up once real workloads justify them.
- Sync v1 peers are not wire-compatible; the explicit version field makes rejection
  deterministic.
