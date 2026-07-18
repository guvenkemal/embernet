# ADR 003: Lock and validate channel-log appends

- Status: accepted
- Date: 2026-07-18

## Context

Posting, MCP writes, and WebSocket sync can append to the same channel concurrently.
Deduplicating before an unlocked append creates a check-then-write race: two writers
can both decide that an ID is absent and then write it. Readers also previously
discarded some line-read errors, which could hide truncated or malformed records.

## Decision

Every channel-log append takes an exclusive advisory lock on `log.ndjson` before it
validates the existing log, checks for a duplicate ID, and writes. The serialized
envelope and terminating newline are prepared as one record, written while holding
the lock, flushed, and synchronized to the underlying file before success is
reported.

Readers take a shared advisory lock and validate every non-empty record. Invalid
JSON, failed envelope verification, I/O errors, and a final record without a newline
are treated as corruption and reported with the log path and line number. Creating
an existing channel preserves its log instead of truncating it.

## Consequences

- Cooperating Embernet processes cannot interleave appends or race deduplication.
- A successful append is flushed to durable storage before its lock is released.
- Corruption is surfaced instead of silently skipped or propagated through sync.
- Append deduplication still scans the complete log and is linear in channel size.
- Advisory locks cannot protect against programs that modify logs without taking
  the same lock.
- A persistent ID index must be updated under this same consistency boundary.
