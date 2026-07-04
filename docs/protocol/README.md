# Protocol

This folder documents Embernet's wire formats, storage formats, and synchronization behavior.

Start here:

- [[protocol]] — current Envelope and Have/Want sync specification.
- [[mcp]] — MCP interface specification for AI agent integration.

Implementation references:

- `src/proto.rs` — `Envelope`, `Message`, signing, and verification.
- `src/store.rs` — channel paths and `.ndjson` storage.
- `src/sync.rs` — WebSocket Have/Want sync protocol.
