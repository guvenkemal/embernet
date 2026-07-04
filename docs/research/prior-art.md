# Prior Art

This note compares Embernet with related decentralized and federated systems.

## Nostr

Nostr uses signed events distributed through relays. Clients publish and subscribe to event streams, while relays are intentionally simple and may accept, reject, or drop events.

Useful ideas:

- Simple signed event format.
- Relay-oriented distribution.
- Public-key identity as a first-class primitive.

Differences from Embernet:

- Embernet currently stores channel logs as local append-only `.ndjson` files.
- Embernet's current sync is Have/Want by channel count, not subscription filters.
- Embernet is oriented around project/community coordination logs rather than a global social event stream.

## Matrix

Matrix is a federated real-time communication protocol with rooms, homeservers, event graphs, state resolution, and rich client/server APIs.

Useful ideas:

- Federation as a durable network model.
- Room/event history as a synchronization problem.
- Explicit protocol specifications and compatibility expectations.

Differences from Embernet:

- Embernet is much smaller and file-backed; there is no homeserver database requirement.
- Embernet currently avoids global room state resolution.
- Embernet's initial protocol favors inspectable logs over comprehensive real-time chat semantics.

## Scuttlebutt / Secure Scuttlebutt

Scuttlebutt uses append-only feeds signed by identities. Peers replicate feeds and can operate offline-first.

Useful ideas:

- Append-only signed logs.
- Offline-first replication.
- Local data ownership.

Differences from Embernet:

- Embernet logs are organized by channel path rather than only per-author feeds.
- Embernet currently uses JSON lines and a simple WebSocket Have/Want exchange.
- Embernet is being shaped as a coordination protocol with explicit project documentation and decision logs.

## What makes Embernet distinct

Embernet is currently exploring a pragmatic middle ground:

- Signed envelopes for integrity.
- Human-inspectable `.ndjson` logs.
- Rust implementation for reliability and deployability.
- A documentation-first repository where protocol decisions are captured as living design artifacts.
- A small Have/Want synchronization layer that can evolve without requiring an external database.

## Adjacent inspirations (non-protocol)

These systems influenced Embernet's design but are communication/coordination models rather than direct protocol peers.

### IRC

IRC channels, simplicity, and real-time text are a direct ancestor. Embernet channels use a similar name structure (`tech/linux`) but diverge by adding signed auth, persistent append-only history, and offline-first sync.

### Reddit

Forum-style threaded discussions with moderation and community scoping. Embernet borrows the channel-as-topic convention but replaces centralized moderation with signed identities and local-first storage.

### Git

Signed commits and Git's Merkle DAG inspired Embernet's use of content-addressed IDs (BLAKE3) and signed envelopes. The `.ndjson` log is intentionally simpler than a commit graph, but the integrity model — every entry is verifiable — comes from Git.

Related: [[../protocol/protocol]]
