# Embernet Living Documentation

This `docs/` directory is the project documentation vault. It is intended to work as both repository documentation and an Obsidian vault.

## Using this folder as an Obsidian vault

Open the repository's `docs/` directory directly in Obsidian:

1. Open Obsidian.
2. Choose "Open folder as vault".
3. Select `docs/` from the root of this repository.

Keep notes in plain Markdown so they stay readable in GitHub, terminals, and code review tools. Prefer small linked notes over large monolithic documents.

## Structure

- `architecture/` — high-level diagrams, system flow notes, and module boundaries.
- `protocol/` — wire formats, `Envelope` structure, Have/Want sync behavior, and storage formats.
- `research/` — prior art and design comparisons, including Nostr, Matrix, and Scuttlebutt.
- `decisions/` — Architecture Decision Records (ADRs) for durable technical decisions.

## Conventions

- Use `[[wikilinks]]` when connecting related notes in Obsidian.
- Keep technical claims aligned with the Rust implementation.
- Use ADRs for decisions that future contributors should not have to rediscover.
- Prefer examples that can be copied into tests or protocol fixtures.

Start with [[protocol/protocol]] for the current wire protocol.
