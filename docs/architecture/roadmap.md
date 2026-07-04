# Roadmap

Vision, phases, and ecosystem plans for Embernet.

Related: [[../protocol/protocol]], [[../research/prior-art]]

## Phase 0 — Local-Only MVP (current)

- `ember init`, `ember post`, `ember tail` — local-only CLI.
- Signed message envelopes with Ed25519 and BLAKE3.
- File-backed append-only `.ndjson` channel storage.
- `ember serve` — HTTP status endpoint.
- `ember keygen` — Ed25519 keypair generation.
- `ember sync` — WebSocket Have/Want sync protocol.
- `ember mcp` — MCP stdio server for AI client integration.

## Phase 1 — Networking + Federation

- WebSocket Have/Want sync ✅
- MCP interface for AI agents ✅
- planned: Merkle-chunked logs for efficient delta sync.
- planned: channel ACLs and moderation tools.
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

The Phase 0 CLI is functional. The MCP interface provides the same operations through the standard Model Context Protocol, letting AI agents (Claude Desktop, Hermes, etc.) read and write coordination logs.

Related: [[../decisions/adr-001-log-storage]], [[../decisions/adr-template]]
