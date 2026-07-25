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
- Prefix-only policy federation and explicit fork handling ✅
- Signed moderation events, federation, and filtered views ✅
- First dedicated terminal client ✅
- Persistent peers, channel discovery, and automatic TUI sync ✅
- Automatic TUI refresh for local server, CLI, MCP, and moderation writes ✅
- Bottom-aware TUI follow-tail behavior for incoming messages ✅
- Direct canonical identity generation during node initialization ✅
- Integrated TUI listener with graceful server lifecycle ✅
- Signed private visibility, reader membership, and authenticated discovery ✅
- Authenticated private-channel synchronization ✅
- next: encrypt private-channel contents and rotate membership keys.
- planned: Web UI client.

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

Phase 1 is active. Sync v6 authenticates the initiating identity, enforces private
membership, and reconciles signed policy and moderation histories before
using deterministic Merkle buckets to localize divergent messages. Saved peers let
the terminal client discover channels and synchronize them periodically without
blocking rendering or input. A lightweight local fingerprint also refreshes the
selected timeline when another process writes to the same data directory. CLI,
MCP, and the terminal client all use the same protocol and storage core.

Related: [[../decisions/adr-001-log-storage]], [[../decisions/adr-template]]
