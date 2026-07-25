# embernet (Phase 1)

Decentralised coordination protocol with signed append-only logs,
WebSocket Have/Want sync, and MCP AI-agent integration.

## Quickstart

```bash
# 0) build
cargo build

# 1) initialise a node and generate its identity
./target/debug/embernet --data ~/.embernet-test init --alias "You"

# 2) create a channel
./target/debug/embernet --data ~/.embernet-test channel-create tech/discuss

# 3) post something
./target/debug/embernet --data ~/.embernet-test post tech/discuss \
  --title "hello world" --body "first post from the bunker" --tags linux rust

# 4) tail
./target/debug/embernet --data ~/.embernet-test tail tech/discuss --n 10

# 5) start the HTTP + WebSocket server
./target/debug/embernet --data ~/.embernet-test serve --listen 127.0.0.1:4444
curl http://127.0.0.1:4444/status | jq

# 6) initialise a second node
./target/debug/embernet --data ~/.embernet-test-2 init --alias "Peer"

# 7) save the first node as its peer
./target/debug/embernet --data ~/.embernet-test-2 peer-add ws://127.0.0.1:4444/sync

# 8) open the terminal client; it discovers and syncs the channel
./target/debug/embernet --data ~/.embernet-test-2 tui

# 9) run as an MCP stdio server for AI clients
./target/debug/embernet --data ~/.embernet-test mcp
```

To import an existing identity instead of generating one:

```bash
./target/debug/embernet --data ~/.embernet-test init --key /path/to/identity.json
```

The imported source file is left unchanged. Embernet always uses
`<data-directory>/keys/identity.json` as the node's canonical identity and refuses
to overwrite it during a later `init`.

## Protocol

- **Envelope** = signed, content-addressed message with channel binding.
  - `id = blake3(serde_json(msg))` — content hash.
  - `sig = ed25519(channel || '\n' || serde_json(msg))` — channel-bound signature.
  - `Envelope::verify()` checks both signature validity and id integrity.
- **Storage** = append-only newline-delimited JSON (`.ndjson`) with a rebuildable per-channel ID index.
- **Sync** = WebSocket `GET /sync` with Merkle-bucket reconciliation and bidirectional Have/Want.
- **MCP** = stdio JSON-RPC server exposing `list_channels`, `tail_channel`, `post_message`.

Full specification: `docs/protocol/protocol.md`

## Commands

```
embernet keygen           Export a standalone ed25519 identity keypair
embernet init             Initialise a node by generating or importing its identity
embernet channel-create   Create a channel
embernet channel-policy   Show a channel's local write policy
embernet channel-policy-history Show verified signed policy events
embernet channel-policy-rebuild Rebuild the derived policy cache
embernet channel-policy-conflicts List saved policy forks
embernet channel-policy-resolve Select a saved policy head
embernet channel-restrict Restrict writes and claim ownership with the local identity
embernet channel-grant    Grant a moderator or writer role
embernet channel-revoke   Revoke a moderator or writer role
embernet channel-transfer-owner Transfer ownership to another public key
embernet moderate-tombstone Tombstone a message from normal views
embernet moderate-restore Restore a tombstoned message
embernet moderation-history Show signed moderation events
embernet moderation-conflicts List saved moderation forks
embernet moderation-resolve Select a saved moderation head
embernet post             Post a signed text message
embernet tail             Tail recent messages from a channel
embernet serve            Run HTTP/WebSocket server (status + sync)
embernet sync             Pull messages from a remote peer via Have/Want
embernet peer-add         Save a peer for automatic synchronization
embernet peer-list        List saved peers
embernet peer-remove      Remove a saved peer
embernet tui              Open the interactive terminal client
embernet mcp              Run as an MCP stdio server for AI clients
```

## Scope

- Offline-friendly, federated via store-and-forward.
- Identity is **ed25519 keys** only. No wallets, tokens, or chains.
- Optional local owner/moderator/writer ACLs gate channel appends.
- File-backed — no external database required.
- Saved peers provide remote channel discovery and periodic TUI synchronization.
- AI-agent integration via MCP.

## Documentation

Embernet is a **documentation-first project**. The `docs/` directory is an Obsidian-ready
vault that serves as the project's technical brain. Every design decision and protocol
detail lives here — treat it as the authoritative source alongside the Rust source code.

### Key documents

| Document | What it covers |
|---|---|
| [Protocol Specification](docs/protocol/protocol.md) | Envelope structure, signing/verification, `.ndjson` storage, Have/Want sync protocol, and current limitations. |
| [MCP Interface](docs/protocol/mcp.md) | Tool definitions (`list_channels`, `tail_channel`, `post_message`), JSON-RPC examples, auth model, and error handling for AI agent integration. |
| [Roadmap](docs/architecture/roadmap.md) | Phase 0 through Phase 2+ vision, current status, and architecture goals. |
| [Prior Art](docs/research/prior-art.md) | Comparisons with Nostr, Matrix, Scuttlebutt, IRC, Reddit, and Git — what we borrow and what we do differently. |
| [ADR 001 — ndjson logs](docs/decisions/adr-001-log-storage.md) | Why we chose newline-delimited JSON over SQLite and binary formats for channel logs. |
| [ADR Template](docs/decisions/adr-template.md) | How to write an Architecture Decision Record for this project. |

### Vault structure

```
docs/
├── README.md                          ← vault index (open this folder in Obsidian)
├── architecture/
│   ├── README.md                      ← system design & module map
│   └── roadmap.md                     ← current phase + future plans
├── protocol/
│   ├── README.md                      ← protocol overview
│   ├── protocol.md                    ← full wire-format spec
│   └── mcp.md                         ← MCP integration spec
├── research/
│   ├── README.md                      ← research index
│   └── prior-art.md                   ← comparison with adjacent systems
└── decisions/
    ├── README.md                      ← decision log index
    ├── adr-template.md                ← ADR template
    └── adr-001-log-storage.md         ← why .ndjson for channel logs
```

Open the vault in Obsidian: **`Open folder as vault` → select `docs/`**.

## License

GNU Affero General Public License v3.0 (AGPL-3.0)
