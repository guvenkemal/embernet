# ADR 009: Moderate through a signed append-only overlay

- Status: accepted
- Date: 2026-07-19

## Context

Communities need to hide spam or harmful content, but physically deleting an
envelope would break the inspectable append-only record and produce inconsistent
histories between peers.

## Decision

Moderation is a separate signed event chain in `moderation.ndjson`. Owners and
moderators may tombstone or restore a target message ID. Each event references the
previous moderation event and the signed policy head that authorized its actor.
This lets replay evaluate authority at the event's historical policy state, even
after ownership or moderator membership changes.

`moderation.json` is a rebuildable cache of currently tombstoned IDs and optional
reasons. Normal CLI and MCP reads omit tombstoned messages; audit reads may include
them. Original envelopes are never removed from `log.ndjson`.

Sync v5 reconciles policy, then moderation, then message buckets. Moderation prefix
extensions are accepted after verification. Valid forks are quarantined under
`moderation-conflicts/` and stop message sync until explicitly resolved.

## Consequences

- Moderation is attributable, reversible, auditable, and federated.
- Different frontends derive a consistent default view without destroying data.
- Open channels must first establish a signed restricted policy before moderation.
- Moderation histories are currently sent in full during synchronization.
