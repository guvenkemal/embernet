# Architecture

This folder contains high-level system diagrams, flow notes, and architectural sketches for Embernet.

## Current modules

- CLI entrypoint: `src/main.rs`
- Interactive terminal client: `src/tui.rs`
- Envelope and message types: `src/proto.rs`
- File-backed append-only storage: `src/store.rs`
- HTTP/WebSocket server: `src/server.rs`
- Have/Want sync logic: `src/sync.rs`
- Persistent peer configuration: `src/peers.rs`

## Core flow

```text
local CLI post
  -> Message
  -> Envelope::sign(...)
  -> policy.json write authorization
  -> locked channels/<channel>/log.ndjson append
  -> transactional channels/<channel>/index.redb update

remote sync
  -> WebSocket /sync
  -> client status packet { version, channel, chunks }
  -> peers expand only differing ID-prefix buckets
  -> server requests client-only ids
  -> peers exchange missing Envelope objects in both directions
  -> each peer Envelope::verify() + deduplicated append

terminal client
  -> shared channel discovery and storage APIs
  -> moderated or audit timeline
  -> signed local post
  -> local metadata fingerprint every 500ms detects server, CLI, and MCP writes
  -> background worker reads peers.json every 3 seconds
  -> GET /status discovers channels
  -> WebSocket /sync reconciles each discovered channel
  -> UI receives connection and timeline updates over an internal channel
```

Related: [[../protocol/protocol]]
