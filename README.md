# embernet (Phase 1)

Decentralised coordination protocol with signed append-only logs,
WebSocket Have/Want sync, and MCP AI-agent integration.

## Quickstart

```bash
# 0) build
cargo build

# 1) set up a data directory (keep it outside the repo)
mkdir -p ~/.embernet-test

# 2) make a key (in the data dir, not the repo root)
./target/debug/embernet --data ~/.embernet-test keygen --alias "You" --out ~/.embernet-test/identity.json

# 3) initialise the data dir
./target/debug/embernet --data ~/.embernet-test init --key ~/.embernet-test/identity.json

# 4) create a channel
./target/debug/embernet --data ~/.embernet-test channel-create tech/discuss

# 5) post something
./target/debug/embernet --data ~/.embernet-test post tech/discuss \
  --title "hello world" --body "first post from the bunker" --tags linux rust

# 6) tail
./target/debug/embernet --data ~/.embernet-test tail tech/discuss --n 10

# 7) start the HTTP + WebSocket server
./target/debug/embernet --data ~/.embernet-test serve --listen 127.0.0.1:4444
curl http://127.0.0.1:4444/status | jq

# 8) sync from another node (after setting up a second data dir)
./target/debug/embernet --data ~/.embernet-test-2 sync --peer ws://127.0.0.1:4444/sync tech/discuss

# 9) run as an MCP stdio server for AI clients
./target/debug/embernet --data ~/.embernet-test mcp
```

## Protocol

- **Envelope** = signed, content-addressed message with channel binding.
  - `id = blake3(serde_json(msg))` — content hash.
  - `sig = ed25519(channel || '\n' || serde_json(msg))` — channel-bound signature.
  - `Envelope::verify()` checks both signature validity and id integrity.
- **Storage** = append-only newline-delimited JSON (`.ndjson`) per channel.
- **Sync** = WebSocket `GET /sync` with Have/Want exchange by channel count.
- **MCP** = stdio JSON-RPC server exposing `list_channels`, `tail_channel`, `post_message`.

Full specification: `docs/protocol/protocol.md`

## Commands

```
embernet keygen           Generate an ed25519 identity keypair
embernet init             Initialise data directory with a keypair
embernet channel-create   Create a channel
embernet post             Post a signed text message
embernet tail             Tail recent messages from a channel
embernet serve            Run HTTP/WebSocket server (status + sync)
embernet sync             Pull messages from a remote peer via Have/Want
embernet mcp              Run as an MCP stdio server for AI clients
```

## Scope

- Offline-friendly, federated via store-and-forward.
- Identity is **ed25519 keys** only. No wallets, tokens, or chains.
- File-backed — no external database required.
- AI-agent integration via MCP.

## Documentation

The `docs/` directory is an Obsidian-ready vault:

- `docs/architecture/` — system design and roadmap.
- `docs/protocol/` — envelope spec, sync protocol, MCP interface.
- `docs/research/` — prior art (Nostr, Matrix, Scuttlebutt, IRC, Git).
- `docs/decisions/` — Architecture Decision Records (ADRs).

## License

MIT or AGPL (TBD)
