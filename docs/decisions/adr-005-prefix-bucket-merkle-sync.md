# ADR 005: Reconcile ID-prefix buckets before exchanging messages

- Status: accepted
- Date: 2026-07-18

## Context

Sync v2 exchanged every message ID even when peers were identical. Positional
fixed-size chunks are not stable because two peers can receive the same messages in
different orders, leaving their logs content-equivalent but their chunk boundaries
and hashes different.

## Decision

Sync v3 partitions IDs into 256 buckets using the first byte of each BLAKE3 message
ID. Within a bucket, raw 32-byte IDs are sorted lexicographically and concatenated;
the bucket hash is BLAKE3 over those bytes. The index persists bucket membership and
hashes, and an append updates only its ID-prefix bucket.

Peers first exchange summaries containing bucket number, ID count, and hash. They
exchange complete ID lists only for absent or unequal buckets, then use the existing
bidirectional Want/envelope transfer. Sync v3 is intentionally not wire-compatible
with v2.

## Consequences

- Identical peers exchange at most 256 compact summaries and no message IDs.
- Hashes converge even when peers appended identical messages in different orders.
- Divergence is localized by ID prefix and one append updates one bucket.
- A heavily populated bucket still requires exchanging all IDs in that bucket.
- The 100,000-ID safety limit applies to IDs in differing buckets, not total channel
  size.
