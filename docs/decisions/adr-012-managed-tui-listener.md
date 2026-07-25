# ADR 012: Let the terminal client accept peer connections

- Status: accepted
- Date: 2026-07-25

## Context

An interactive node previously required separate `serve` and `tui` processes.
This made two-way testing cumbersome and made one participant appear to be a
special server while the other acted as a client.

## Decision

`embernet tui` accepts an optional `--listen <address>` argument. When present,
the TUI binds the existing HTTP/WebSocket router before entering terminal raw
mode, then runs that server as a managed task beside background peer sync.

The footer displays the bound address. Exiting the TUI signals graceful server
shutdown and waits for the task after restoring the terminal. Bind and address
errors occur before terminal takeover, so they remain readable normal CLI errors.
The standalone `serve` command continues to use the same managed server
implementation.

## Consequences

- Every interactive node can accept and initiate synchronization.
- Users can run a complete node in one terminal process.
- `tui` without `--listen` remains available for outbound-only or offline use.
- Port selection and peer address distribution remain explicit configuration.
- Unexpected runtime server failures are not yet displayed separately from the
  listener's last known state.
