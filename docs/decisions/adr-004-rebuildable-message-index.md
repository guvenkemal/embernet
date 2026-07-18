# ADR 004: Maintain a rebuildable message index

- Status: accepted
- Date: 2026-07-18

## Context

Deduplication and sync inventories previously parsed and verified every envelope in
`log.ndjson`. That work grows with both message count and message size, and sync had
to retain complete envelopes even when the peer requested only a small subset.

## Decision

Each channel maintains `index.redb`, a transactional embedded key/value index. A
message ID maps to the byte offset and length of its complete NDJSON record. Index
metadata records the corresponding log length.

The channel log remains authoritative. Index access occurs while holding the
channel log's exclusive advisory lock. If the index is missing or its recorded log
length differs from the actual log length, Embernet verifies the complete log and
rebuilds the index. Appends synchronize the log before committing the new index
entry and log length, so interruption leaves a detectable stale index.

## Consequences

- Duplicate-ID checks use a keyed lookup rather than parsing the channel log.
- Sync inventories read IDs from the index and requested messages are loaded by
  byte range.
- Existing channels migrate automatically on first indexed operation.
- The inspectable NDJSON log remains the source of truth; the binary index can be
  deleted and regenerated.
- Inventory enumeration remains linear in message count. Merkle chunks are still
  needed to avoid exchanging complete inventories.
- Manual log changes that preserve the exact byte length are not detected by the
  length check alone, although every indexed record is verified when loaded.
