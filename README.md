# embernet (Phase 0)

Minimal local scaffold to post/tail messages in channels, with signed envelopes and file-backed logs. Networking is stubbed to a status endpoint; real federation comes in Phase 1.

## Quickstart

```bash
# 0) build
cargo build

# 1) make a key
./target/debug/embernet keygen --alias "You" --out identity.json

# 2) init data dir
./target/debug/embernet --data ./data init --key identity.json

# 3) create a channel
./target/debug/embernet --data ./data channel-create tech/discuss

# 4) post something
./target/debug/embernet --data ./data post tech/discuss \
  --title "hello world" --body "first post from the bunker" --tags linux rust

# 5) tail
./target/debug/embernet --data ./data tail tech/discuss --n 10

# 6) status server
./target/debug/embernet --data ./data serve --listen 127.0.0.1:4444
curl http://127.0.0.1:4444/status | jq
```

## Notes

- Logs are **newline-delimited JSON** for readability. Switch to chunked segments + MessagePack later.
- `id = blake3(serde_json(msg))`; `sig = ed25519(signing_key, msg_bytes)`.
- This is enough to begin experimenting with UIs and to wire up Phase-1 sync (have/want + WebSocket) next.

## Scope (no Web3)

- Core spec is **offline-friendly**, federated via store-and-forward. No wallets, tokens, chains, or “anchors.”
- Identity is **ed25519 keys** only. Optional DNS/GitHub text proofs later (purely off-chain).
- Attachments are content-addressed locally; future IPFS support would be optional plugin-only, not required.

## Next Up: Phase‑1 Sync Checklist

- [ ] WebSocket `/sync` endpoint with per-channel **have/want** exchange.
- [ ] Chunked logs (`0000.msgpack`, `0001.msgpack`) + Merkle roots every N messages.
- [ ] Peer ACLs (read/write/relay) + simple token auth for localhost UI.
- [ ] Rate limiting + message/attachment caps.
- [ ] ratatui TUI: channel list, message view, post box.
