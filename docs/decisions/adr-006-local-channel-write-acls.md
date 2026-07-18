# ADR 006: Enforce local channel write ACLs

- Status: accepted
- Date: 2026-07-18

## Context

Envelope signatures prove authorship and integrity but do not grant permission to
write a channel. Without a separate authorization decision, any valid identity can
inject messages through the CLI, MCP, or federation.

## Decision

Each channel may have a local `policy.json` with an owner, moderators, and writers.
Policies are either `open` or `restricted`. Missing policies are interpreted as
open for compatibility with existing channels.

For restricted channels, owners, moderators, and writers may append. Owners manage
moderators; owners and moderators manage writers. Policy mutation and message
authorization are serialized with channel appends using the channel-log lock.
`append_message` performs the authorization check after signature verification, so
local CLI posts, MCP posts, and synchronized envelopes share one enforcement point.

## Consequences

- A valid signature no longer implies permission to enter a restricted local log.
- Revocation affects subsequent appends without rewriting history.
- Existing channels remain open until a local operator explicitly restricts them.
- Policies are local node configuration and are not currently federated.
- Reads remain public, and policies do not provide confidentiality.
- Policy changes are not yet represented as signed, append-only audit events.
