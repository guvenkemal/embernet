# Test the encrypted private-channel journey

This guide is both a user tutorial and a manual release check for Embernet's
public discovery, encrypted private channels, role enforcement, synchronization,
and key rotation.

It creates three fresh nodes:

- **Alice** owns the public and private channels and listens on port `4444`.
- **Bob** is a private-channel writer and listens on port `4445`.
- **John** is not a private-channel member and listens on port `4446`.

Run all commands from the Embernet repository unless a step says otherwise.

## 1. Stop existing nodes

Exit each running TUI with `q`, and stop standalone servers with `Ctrl-C`.

Confirm that the test ports are free:

```bash
lsof -nP -iTCP:4444 -iTCP:4445 -iTCP:4446
```

The command should produce no output.

## 2. Build the current implementation

```bash
cd ~/Projects/embernet
cargo build
```

All nodes must run the same build. Sync v9 is not compatible with earlier sync
versions.

## 3. Reset the test data

For recoverable cleanup, rename any existing directories with a timestamp:

```bash
backup_suffix=$(date +%Y%m%d-%H%M%S)
test -e ~/.embernet-alice && mv ~/.embernet-alice ~/.embernet-alice."$backup_suffix"
test -e ~/.embernet-bob && mv ~/.embernet-bob ~/.embernet-bob."$backup_suffix"
test -e ~/.embernet-john && mv ~/.embernet-john ~/.embernet-john."$backup_suffix"
```

Alternatively, the following command permanently deletes the three test nodes,
including their identities, messages, policies, and channel keys:

```bash
rm -rf \
  ~/.embernet-alice \
  ~/.embernet-bob \
  ~/.embernet-john
```

## 4. Create Alice, Bob, and John

```bash
./target/debug/embernet --data ~/.embernet-alice init --alias alice
./target/debug/embernet --data ~/.embernet-bob init --alias bob
./target/debug/embernet --data ~/.embernet-john init --alias john
```

Load their public keys into shell variables:

```bash
alice_key=$(jq -r .public_key ~/.embernet-alice/keys/identity.json)
bob_key=$(jq -r .public_key ~/.embernet-bob/keys/identity.json)
john_key=$(jq -r .public_key ~/.embernet-john/keys/identity.json)

printf 'Alice: %s\nBob:   %s\nJohn:  %s\n' \
  "$alice_key" "$bob_key" "$john_key"
```

Each value should be a different 64-character hexadecimal Ed25519 public key.

## 5. Create a public channel

```bash
./target/debug/embernet --data ~/.embernet-alice \
  channel-create tech/discuss

./target/debug/embernet --data ~/.embernet-alice \
  post tech/discuss \
  --body "Welcome to the public channel"
```

## 6. Create a private channel for Alice and Bob

```bash
./target/debug/embernet --data ~/.embernet-alice \
  channel-create private/team

./target/debug/embernet --data ~/.embernet-alice \
  channel-restrict private/team

./target/debug/embernet --data ~/.embernet-alice \
  channel-grant private/team writer "$bob_key"

./target/debug/embernet --data ~/.embernet-alice \
  channel-visibility private/team private
```

Bob is a writer, so he can read and post. John has no private-channel role.

## 7. Verify encryption at Alice's endpoint

Post a new private message:

```bash
./target/debug/embernet --data ~/.embernet-alice \
  post private/team \
  --body "This message should be encrypted"
```

The plaintext must not occur in the append-only log:

```bash
grep -n "This message should be encrypted" \
  ~/.embernet-alice/channels/private/team/log.ndjson
```

Expected result: no output and a non-zero exit status.

Inspect the stored body:

```bash
tail -n 1 ~/.embernet-alice/channels/private/team/log.ndjson |
  jq '.msg.body'
```

Expected shape:

```json
{
  "kind": "Encrypted",
  "key_id": "...",
  "nonce": "...",
  "ciphertext": "..."
}
```

The normal client view should transparently decrypt it:

```bash
./target/debug/embernet --data ~/.embernet-alice \
  tail private/team --n 10
```

Expected result: the output includes `This message should be encrypted`.

## 8. Start Alice

In **terminal 1**:

```bash
cd ~/Projects/embernet

./target/debug/embernet \
  --data ~/.embernet-alice \
  tui --listen 127.0.0.1:4444
```

Leave this terminal running.

## 9. Connect Bob

In **terminal 2**:

```bash
cd ~/Projects/embernet

./target/debug/embernet --data ~/.embernet-bob \
  peer-add ws://127.0.0.1:4444/sync \
  --public-key "$(jq -r .public_key ~/.embernet-alice/keys/identity.json)"

./target/debug/embernet \
  --data ~/.embernet-bob \
  tui --listen 127.0.0.1:4445
```

Bob should discover both `tech/discuss` and `private/team`. The private timeline
should display Alice's decrypted message.

From another terminal, confirm Bob stores ciphertext:

```bash
tail -n 1 ~/.embernet-bob/channels/private/team/log.ndjson |
  jq '.msg.body'
```

The body should have `kind: "Encrypted"`, while the normal tail command should
show plaintext:

```bash
./target/debug/embernet --data ~/.embernet-bob \
  tail private/team --n 10
```

## 10. Post an encrypted reply as Bob

In Bob's TUI:

1. Select `private/team`.
2. Press `p`.
3. Type a message.
4. Press Enter.

Alice should receive and decrypt the reply automatically. The newest raw record
at Bob's endpoint should still contain an encrypted body:

```bash
tail -n 1 ~/.embernet-bob/channels/private/team/log.ndjson |
  jq '.msg.body'
```

## 11. Confirm John sees public channels only

In **terminal 3**:

```bash
cd ~/Projects/embernet

./target/debug/embernet --data ~/.embernet-john \
  peer-add ws://127.0.0.1:4444/sync \
  --public-key "$(jq -r .public_key ~/.embernet-alice/keys/identity.json)"

./target/debug/embernet \
  --data ~/.embernet-john \
  tui --listen 127.0.0.1:4446
```

John should discover `tech/discuss` but must not discover `private/team`.

## 12. Test revocation and key rotation

Exit Bob's TUI with `q`. In another terminal, reload Bob's key in case this is a
new shell, then revoke him:

```bash
bob_key=$(jq -r .public_key ~/.embernet-bob/keys/identity.json)

./target/debug/embernet --data ~/.embernet-alice \
  channel-revoke private/team writer "$bob_key"
```

Post a message under the rotated key:

```bash
./target/debug/embernet --data ~/.embernet-alice \
  post private/team \
  --body "Posted after Bob was revoked"
```

Bob must no longer discover or synchronize `private/team`. His existing local
copy remains readable because revocation cannot erase messages or historical keys
already delivered to an endpoint, but he cannot receive the rotated key or decrypt
later messages.

## What this journey proves

- Public channels are discoverable by authenticated peers without membership.
- Private channels are discoverable only by policy members.
- New private message bodies are ciphertext in local logs and sync frames.
- Authorized endpoints transparently decrypt private messages.
- A writer can read and post; a non-member cannot discover the channel.
- Revocation rotates the channel key and blocks future synchronization.

This test does not prove that old plaintext messages were retroactively encrypted:
changing visibility affects new posts only. It also does not hide envelope
metadata such as sender, timestamp, title, tags, and references.

Related: [[../protocol/protocol]], [[../decisions/adr-014-private-channel-encryption]]
