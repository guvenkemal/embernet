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
  -> channels/<channel>/log.ndjson

remote sync
  -> WebSocket /sync
  -> client status packet { channel, count }
  -> server streams missing Envelope objects
  -> client Envelope::verify()
  -> append to local log.ndjson
```

Related: [[../protocol/protocol]]
