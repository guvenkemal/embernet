# ADR 013: Authenticate discovery and sync against signed membership

- Status: accepted
- Date: 2026-07-25

## Context

Anonymous `/status` responses exposed every channel name, and anyone who guessed a
name could request its messages over `/sync`. Content encryption needs a signed
membership model and access-controlled transport before it can distribute keys
safely.

## Decision

Channel policy gains a backward-compatible `visibility` field, defaulting to
`public`, and a `readers` role list, defaulting to empty. Visibility changes are
signed policy events controlled by the owner. Owners and moderators may manage
readers; readers can discover and synchronize private channels but cannot append.
Owners, moderators, and writers are also implicit readers.

Discovery requests include the requester's public key, a timestamp, and an Ed25519
signature over a domain-separated `/status` payload. Anonymous discovery returns
only public channels. Authenticated discovery additionally returns private
channels for which the requester is a member.

Sync v6 adds a timestamped, channel-bound identity signature to its opening status
packet. A server rejects private-channel synchronization unless its current signed
policy authorizes that identity to read.

## Consequences

- Private channel names and messages are not exposed through Embernet's remote
  discovery or sync interfaces to non-members.
- Existing policy JSON without the new fields remains public and has no readers.
- Reader membership and visibility federate through the existing signed policy
  chain and fork rules.
- Timestamps initially limited replay of discovery and sync authentication to 60
  seconds. [[adr-015-protocol-hardening]] supersedes this with one-time,
  responder-bound challenges.
- Private content is still plaintext on disk and in process memory.
- Revocation prevents future discovery and synchronization but cannot erase data
  that a former member already synchronized.
- Transport confidentiality still depends on using `wss://`; message encryption
  and membership-key rotation remain future work.
