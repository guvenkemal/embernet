# ADR 010: Build the first frontend as a thin terminal client

- Status: accepted
- Date: 2026-07-19

## Context

Embernet's CLI exposes the protocol one operation at a time, but does not provide
an ongoing view of channels and conversations. The first dedicated frontend must
exercise the existing core without creating a second implementation of storage,
authorization, moderation, or synchronization.

## Decision

The first frontend is an in-process terminal UI built with Ratatui and Crossterm.
It delegates channel discovery, reads, signed appends, policy evaluation, conflict
inspection, and peer synchronization to the same modules used by the CLI and MCP
server.

The initial client provides channel navigation, timeline scrolling, a post
composer, peer sync, moderated and audit views, the local identity's channel role,
and visible policy or moderation conflict counts.

## Consequences

- The protocol gains an interactive client without introducing a browser build or
  a separate application API.
- Terminal rendering and input state can be tested with an in-memory backend.
- Improvements to shared storage and sync behavior apply to every frontend.
- Network synchronization currently occupies the UI while a peer request runs.
- A future web or native client will need a process boundary around the same core.
