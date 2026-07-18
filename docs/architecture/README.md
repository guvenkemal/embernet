# Architecture

This folder contains high-level system diagrams, flow notes, and architectural sketches for Embernet.

## Current modules

- CLI entrypoint: `src/main.rs`
- Envelope and message types: `src/proto.rs`
- File-backed append-only storage: `src/store.rs`
- HTTP/WebSocket server: `src/server.rs`
- Have/Want sync logic: `src/sync.rs`

## Core flow

```text
local CLI post
  -> Message
  -> Envelope::sign(...)
  -> locked channels/<channel>/log.ndjson append
  -> transactional channels/<channel>/index.redb update

remote sync
  -> WebSocket /sync
  -> client status packet { version, channel, ids }
  -> server requests client-only ids
  -> peers exchange missing Envelope objects in both directions
  -> each peer Envelope::verify() + deduplicated append
```

Related: [[../protocol/protocol]]
