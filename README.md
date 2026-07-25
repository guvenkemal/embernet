# embernet (Phase 1)

Decentralised coordination protocol with signed append-only logs,
end-to-end encrypted private channels, WebSocket Have/Want sync, and MCP
AI-agent integration.

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

# 5) open the first TUI and accept peer connections
./target/debug/embernet --data ~/.embernet-test tui --listen 127.0.0.1:4444

# from another terminal, verify its embedded server
curl http://127.0.0.1:4444/status | jq

# 6) initialise a second node
./target/debug/embernet --data ~/.embernet-test-2 init --alias "Peer"

# 7) save the first node as its peer
./target/debug/embernet --data ~/.embernet-test-2 peer-add ws://127.0.0.1:4444/sync

# 8) save the second node on the first for symmetric reconnection
./target/debug/embernet --data ~/.embernet-test peer-add ws://127.0.0.1:4445/sync

# 9) open the second terminal client; it discovers and syncs the channel
./target/debug/embernet --data ~/.embernet-test-2 tui --listen 127.0.0.1:4445

# 10) run as an MCP stdio server for AI clients
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
- **Private channels** = XChaCha20-Poly1305 encrypted message bodies with
  authenticated member-to-member channel-key exchange.
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
embernet channel-grant    Grant a moderator, writer, or reader role
embernet channel-revoke   Revoke a moderator, writer, or reader role
embernet channel-transfer-owner Transfer ownership to another public key
embernet channel-visibility Set signed public/private discovery visibility
embernet moderate-tombstone Tombstone a message from normal views
embernet moderate-restore Restore a tombstoned message
embernet moderation-history Show signed moderation events
embernet moderation-conflicts List saved moderation forks
embernet moderation-resolve Select a saved moderation head
embernet post             Post a signed text message
embernet tail             Tail recent messages from a channel
embernet serve            Run HTTP/WebSocket server (status + sync)
embernet sync             Reconcile messages bidirectionally via Have/Want
embernet peer-add         Save a peer for automatic synchronization
embernet peer-list        List saved peers
embernet peer-remove      Remove a saved peer
embernet tui              Open the terminal client, optionally accepting connections
embernet mcp              Run as an MCP stdio server for AI clients
```

## Scope

- Offline-friendly, federated via store-and-forward.
- Identity is **ed25519 keys** only. No wallets, tokens, or chains.
- Signed, federated owner/moderator/writer policies gate channel appends.
- Private visibility and reader membership restrict remote discovery and sync;
  private message bodies are encrypted before entering the append-only log.
- File-backed — no external database required.
- Saved peers provide remote channel discovery and periodic TUI synchronization.
- The TUI can host the HTTP/WebSocket server with `--listen`.
- AI-agent integration via MCP.

### TUI controls

| Key | Action |
|---|---|
| `↑` / `↓` | Select a channel |
| `j` / `k` | Scroll down or up |
| `p` | Compose a signed post |
| `s` | Synchronize immediately and save the peer |
| `a` | Toggle moderated/audit view |
| `r` | Refresh local state |
| `q` | Quit and stop the managed listener |

The timeline follows incoming messages while positioned at the bottom. Scrolling
up disables follow-tail until the view returns to the bottom.

### Encrypted private channels

Private visibility protects discovery and synchronization and encrypts new message
bodies end to end. To create one:

```bash
./target/debug/embernet --data ~/.embernet-test channel-create private/team
./target/debug/embernet --data ~/.embernet-test channel-restrict private/team
./target/debug/embernet --data ~/.embernet-test \
  channel-grant private/team reader <member-public-key>
./target/debug/embernet --data ~/.embernet-test \
  channel-visibility private/team private
```

Owners, moderators, writers, and readers can authenticate discovery and sync.
During sync, channel keys are wrapped to each member using X25519 keys derived from
the existing Ed25519 identities. Readers cannot post. Only the owner can change
visibility. Revoking any role rotates the write key, preventing that identity from
decrypting later messages once remaining members synchronize the new key.

Existing plaintext messages are not retroactively encrypted when a channel becomes
private. Titles, tags, references, sender identities, and timestamps remain visible
in envelope metadata. Treat `channel-keys.json` as sensitive: it is stored locally
with owner-only permissions and is required to decrypt the ciphertext log.

For a complete three-node walkthrough covering ciphertext verification, member
access, non-member exclusion, and key rotation, see
[Test the encrypted private-channel journey](docs/guides/encrypted-private-channel-test.md).

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
| [Encrypted private-channel test](docs/guides/encrypted-private-channel-test.md) | Alice/Bob/John end-to-end tutorial and manual release check. |
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
├── guides/
│   └── encrypted-private-channel-test.md ← encrypted three-node test journey
└── decisions/
    ├── README.md                      ← decision log index
    ├── adr-template.md                ← ADR template
    ├── adr-001-log-storage.md         ← why .ndjson for channel logs
    ├── ...                            ← protocol and storage decisions
    └── adr-012-managed-tui-listener.md
```

Open the vault in Obsidian: **`Open folder as vault` → select `docs/`**.

## License

GNU Affero General Public License v3.0 (AGPL-3.0)
