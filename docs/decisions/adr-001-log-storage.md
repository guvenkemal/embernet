# ADR 001: Use of Newline-Delimited JSON (`.ndjson`) for Channel Logs

## Status

Accepted

## Context

We needed a storage format for channel logs that is persistent, append-only, and easily synchronizable.

Key constraints:

- Must be human-readable for debugging.

- Must support efficient appending without re-writing the entire log file.

- Must be easy to parse for our `Have/Want` sync protocol.

We considered:

1. **SQLite**: Good for complex queries, but adds a dependency and makes the log harder to inspect manually.
2. **Binary formats (MessagePack/Protobuf)**: Efficient, but requires tools to inspect; sacrifices human-readability.
3. **Newline-Delimited JSON (`.ndjson`)**: Extremely simple, append-only by design, and supported by all standard text editors and CLI tools like `jq`.

## Decision

We will use newline-delimited JSON (`.ndjson`) as the initial append-only channel log format.

## Consequences

### Pros

- **Human-Readable:** Anyone can open the file in a text editor to verify the contents.

- **Unix Philosophy:** Integrates perfectly with standard tools (e.g., `cat`, `tail`, `grep`, `jq`).

- **Append-Only Performance:** Appending to a file is an $O(1)$ operation, making it ideal for high-frequency logs.

### Cons

- **Storage Efficiency:** Larger than binary formats due to field names being repeated in every line.

- **Verification Overhead:** Every line must be parsed as JSON, which is slower than binary deserialization.

### Follow-up

- Future work may include a "compacting" phase where older logs are moved to a more compressed binary format (e.g., MessagePack) once a channel reaches a certain size.
