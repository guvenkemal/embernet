# ADR 011: Discover and periodically synchronize saved peers

- Status: accepted
- Date: 2026-07-24

## Context

The first terminal client required users to know a WebSocket URL, create the same
channel on both nodes, and manually synchronize after every message. This proved
the protocol but did not provide a practical ongoing conversation.

## Decision

Nodes store a sorted, deduplicated list of WebSocket peer URLs in `peers.json`.
The CLI manages this list with `peer-add`, `peer-list`, and `peer-remove`.

The existing HTTP status endpoint returns all locally known channel names,
including nested names. Every three seconds, a TUI background task reloads the
peer list, discovers each peer's channels, creates missing local channel shells,
and runs the existing sync-v5 exchange for each channel. Results are sent to the
rendering task over an internal channel so network work does not block keyboard
input or drawing.

The TUI also fingerprints the local channel list and selected channel's message,
policy, moderation, and conflict metadata every 500 milliseconds. It reloads the
view only when that fingerprint changes. This covers writes received by a local
server or performed by another CLI, MCP, or TUI process without requiring every
writer to coordinate with the frontend.

The timeline follows its calculated bottom as messages arrive. Scrolling upward
disables follow-tail so incoming messages do not interrupt reading; returning to
the bottom enables it again.

## Consequences

- A saved peer is sufficient for channels and new messages to appear in the TUI.
- Offline peers produce visible errors but do not stop the client.
- Peer configuration changes are picked up without restarting the TUI.
- Local changes appear without a manual refresh and unchanged polls do not reload
  the timeline.
- Active conversations stay on the newest message without forcing readers who
  scrolled upward back to the bottom.
- Discovery currently reveals all channel names without authentication.
- Each interval opens one HTTP request per peer and one WebSocket per channel.
- Private channels will require a different, membership-aware discovery design.
