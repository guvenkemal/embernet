# ADR 008: Federate policy histories by verified prefix extension

- Status: accepted
- Date: 2026-07-18

## Context

Messages cannot be authorized consistently across peers unless signed policy state
is reconciled first. Two independently extended policy chains can both be valid but
represent conflicting administrative decisions, so silently choosing or merging a
fork would violate owner intent.

## Decision

Sync v4 exchanges complete signed policy histories before message bucket summaries.
If histories match, or one is a verified prefix of the other, the shorter peer
appends the missing events and rebuilds its policy cache. Only then may ordinary
message reconciliation begin.

If neither history is a prefix, message sync stops. Each peer stores the other valid
chain under `policy-conflicts/<head>.ndjson`. An operator may inspect saved heads and
explicitly select one; Embernet never resolves a fork automatically.

## Consequences

- Message transfer cannot race ahead of policy reconciliation.
- Tampered, unauthorized, or incorrectly chained remote events are rejected.
- Valid concurrent policy changes require explicit human resolution.
- Policy histories are currently sent in full; a future policy-chain inventory can
  optimize long histories.
- Authorization still uses current derived policy rather than policy state at each
  historical message's original append point.
