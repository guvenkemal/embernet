# Roadmap

Vision, phases, and ecosystem plans for Embernet.

Related: [[../protocol/protocol]], [[../research/prior-art]]

## Phase 0 — Local-Only MVP (complete)

- `ember init`, `ember post`, `ember tail` — local-only CLI.
- Signed message envelopes with Ed25519 and BLAKE3.
- File-backed append-only `.ndjson` channel storage.
- `ember serve` — HTTP status endpoint.
- `ember keygen` — Ed25519 keypair generation.
- `ember sync` — WebSocket Have/Want sync protocol.
- `ember mcp` — MCP stdio server for AI client integration.

## Phase 1 — Networking + Federation

- Count-based WebSocket Have/Want sync ✅
- Divergence-safe, bidirectional ID-inventory sync ✅
- MCP interface for AI agents ✅
- Concurrent append safety and corruption detection ✅
- Persistent indexed inventories and message lookups ✅
- ID-prefix Merkle bucket sync v3 ✅
- Local channel write ACLs ✅
- Signed policy audit events and ownership transfer ✅
- next: federated policy-history conflict resolution.
- planned: TUI or Web UI client.

## Phase 2+ — Ecosystem

- Relay and Pub node architecture (store-and-forward).
- Bridges (IRC, Matrix, Nostr).
- WASM plugins and/or Lua scripting.
- Full Web UI.
- Federation with IPFS / Nostr / other networks (optional).
- Private and encrypted channel support.

## Architecture goals

- Modular: swap out storage, transport, or auth without rewriting the core.
- Linux-first, but portable.
- Inspectable logs — no opaque binary formats.
- Local-first: your node is yours.
- Toolable: CLI, MCP, WebSocket API all use the same core.

## Current status

Phase 1 is active. Sync v3 uses deterministic Merkle buckets to localize divergent
message IDs before bidirectional transfer, and the MCP interface lets AI agents read
and write coordination logs.

Related: [[../decisions/adr-001-log-storage]], [[../decisions/adr-template]]
