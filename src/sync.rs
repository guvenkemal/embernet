//! Divergence-safe, bidirectional Have/Want sync over WebSocket.

use crate::proto::{Envelope, KeypairFile, verify_bytes};
use crate::server::AppState;
use crate::store::{self, ChannelRef, append_message};
use anyhow::{Context, Result, bail};
use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

const SYNC_VERSION: u32 = 9;
const MAX_DIFFERING_IDS: usize = 100_000;
const MAX_POLICY_EVENTS: usize = 10_000;
const MAX_MODERATION_EVENTS: usize = 100_000;
const MAX_KEY_OFFERS: usize = 4_096;
const MAX_DISCOVERED_CHANNELS: usize = 10_000;
const MAX_STATUS_BYTES: usize = 1_048_576;
const SYNC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
pub(crate) const DISCOVERY_KEY_HEADER: &str = "x-embernet-public-key";
pub(crate) const DISCOVERY_TIMESTAMP_HEADER: &str = "x-embernet-timestamp";
pub(crate) const DISCOVERY_SIGNATURE_HEADER: &str = "x-embernet-signature";
pub(crate) const DISCOVERY_NONCE_HEADER: &str = "x-embernet-nonce";

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AuthChallenge {
    #[serde(rename = "type", default)]
    msg_type: String,
    pub nonce: String,
    pub responder: String,
    pub expires: i64,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
struct PeerStatus {
    ok: bool,
    channels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSyncSummary {
    pub channels: usize,
    pub received: u64,
}

#[derive(Debug, Deserialize)]
struct StatusMessage {
    #[serde(rename = "type")]
    msg_type: String,
    version: u32,
    channel: String,
    requester: String,
    auth_ts: i64,
    auth_sig: String,
    policy_events: Vec<store::PolicyEvent>,
    moderation_events: Vec<store::ModerationEvent>,
    chunks: Vec<store::ChunkSummary>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PolicySync {
    #[serde(rename = "type")]
    msg_type: String,
    status: String,
    events: Vec<store::PolicyEvent>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ModerationSync {
    #[serde(rename = "type")]
    msg_type: String,
    status: String,
    events: Vec<store::ModerationEvent>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeySync {
    #[serde(rename = "type")]
    msg_type: String,
    identity: String,
    offers: Vec<crate::crypto::KeyOffer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChunkIds {
    index: u64,
    ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChunkDiff {
    #[serde(rename = "type")]
    msg_type: String,
    chunks: Vec<ChunkIds>,
    want_chunks: Vec<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChunkBatch {
    #[serde(rename = "type")]
    msg_type: String,
    chunks: Vec<ChunkIds>,
}

#[derive(Debug, Serialize, Deserialize)]
struct WantMessage {
    #[serde(rename = "type")]
    msg_type: String,
    ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SyncResponse {
    #[serde(rename = "type")]
    msg_type: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sent: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    received: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl SyncResponse {
    fn complete(sent: u64, received: u64) -> Self {
        Self {
            msg_type: "response".into(),
            status: "complete".into(),
            sent: Some(sent),
            received: Some(received),
            error: None,
        }
    }

    fn to_json(&self) -> String {
        serde_json::to_string(self).expect("SyncResponse is serializable")
    }
}

pub async fn handle_sync(ws: WebSocket, state: Arc<AppState>) {
    tracing::info!("sync: new websocket connection");
    if let Err(error) = run_sync(ws, &state).await {
        tracing::error!("sync session failed: {error:#}");
    }
}

async fn run_sync(mut ws: WebSocket, state: &AppState) -> Result<()> {
    let datadir = &state.datadir;
    let challenge = make_auth_challenge(&state.identity, "/sync")?;
    ws.send(Message::Text(serde_json::to_string(&challenge)?))
        .await
        .context("send sync authentication challenge")?;
    let status = read_status(&mut ws).await?;
    if status.version != SYNC_VERSION {
        bail!("unsupported sync version: {}", status.version);
    }
    if status.policy_events.len() > MAX_POLICY_EVENTS {
        bail!("policy history exceeds {MAX_POLICY_EVENTS} events");
    }
    if status.moderation_events.len() > MAX_MODERATION_EVENTS {
        bail!("moderation history exceeds {MAX_MODERATION_EVENTS} events");
    }
    if status.chunks.len() > store::MERKLE_BUCKET_COUNT
        || status
            .chunks
            .iter()
            .any(|chunk| chunk.index >= store::MERKLE_BUCKET_COUNT as u64)
    {
        bail!("invalid chunk summary inventory");
    }
    let chan = ChannelRef::parse(&status.channel).context("invalid channel name in status")?;
    if (chrono::Utc::now().timestamp() - status.auth_ts).abs() > 60 {
        bail!("stale sync authentication");
    }
    if challenge.expires < chrono::Utc::now().timestamp() {
        bail!("expired sync authentication challenge");
    }
    verify_bytes(
        &status.requester,
        &status.auth_sig,
        &sync_auth_payload(
            status.auth_ts,
            &status.channel,
            &challenge.nonce,
            &challenge.responder,
        ),
    )
    .context("invalid sync authentication")?;
    store::validate_policy_history(&chan, &status.policy_events)?;
    let local_policy = store::read_policy_history(datadir, &chan)?;
    let current_policy = store::read_channel_policy(datadir, &chan)?;
    if !store::policy_allows_read(&current_policy, &status.requester) {
        bail!(
            "requester is not a member of private channel {}",
            chan.full_name
        );
    }
    let local_prefix = is_policy_prefix(&local_policy, &status.policy_events);
    let remote_prefix = is_policy_prefix(&status.policy_events, &local_policy);
    if !local_prefix && !remote_prefix {
        store::save_policy_conflict(datadir, &chan, &status.policy_events)?;
        ws.send(Message::Text(serde_json::to_string(&PolicySync {
            msg_type: "policy_sync".into(),
            status: "conflict".into(),
            events: local_policy,
        })?))
        .await?;
        bail!("policy history fork");
    }
    if local_prefix && status.policy_events.len() > local_policy.len() {
        store::append_remote_policy_history(datadir, &chan, &status.policy_events)?;
    }
    let reconciled_policy_state = store::read_channel_policy(datadir, &chan)?;
    if !store::policy_allows_read(&reconciled_policy_state, &status.requester) {
        bail!(
            "requester is not a member of private channel {} after policy reconciliation",
            chan.full_name
        );
    }
    let reconciled_policy = store::read_policy_history(datadir, &chan)?;
    ws.send(Message::Text(serde_json::to_string(&PolicySync {
        msg_type: "policy_sync".into(),
        status: "update".into(),
        events: reconciled_policy,
    })?))
    .await
    .context("send policy sync")?;
    store::validate_moderation_history(datadir, &chan, &status.moderation_events)?;
    let local_moderation = store::read_moderation_history(datadir, &chan)?;
    let local_prefix = is_moderation_prefix(&local_moderation, &status.moderation_events);
    let remote_prefix = is_moderation_prefix(&status.moderation_events, &local_moderation);
    if !local_prefix && !remote_prefix {
        store::save_moderation_conflict(datadir, &chan, &status.moderation_events)?;
        ws.send(Message::Text(serde_json::to_string(&ModerationSync {
            msg_type: "moderation_sync".into(),
            status: "conflict".into(),
            events: local_moderation,
        })?))
        .await?;
        bail!("moderation history fork");
    }
    if local_prefix && status.moderation_events.len() > local_moderation.len() {
        store::append_remote_moderation_history(datadir, &chan, &status.moderation_events)?;
    }
    ws.send(Message::Text(serde_json::to_string(&ModerationSync {
        msg_type: "moderation_sync".into(),
        status: "update".into(),
        events: store::read_moderation_history(datadir, &chan)?,
    })?))
    .await
    .context("send moderation sync")?;
    let policy = store::read_channel_policy(datadir, &chan)?;
    if !store::policy_allows_read(&policy, &status.requester) {
        bail!("requester is not authorized to receive channel keys");
    }
    let server_identity = if policy.visibility == store::ChannelVisibility::Private {
        let identity = KeypairFile::load_secure(&datadir.join("keys/identity.json"))
            .context("load server identity for private channel-key exchange")?;
        if !store::policy_allows_read(&policy, &identity.public_key) {
            bail!("serving identity is not a member of private channel");
        }
        Some(identity)
    } else {
        None
    };
    let offers = server_identity
        .as_ref()
        .map(|identity| {
            crate::crypto::make_key_offers(datadir, &chan.full_name, identity, &status.requester)
        })
        .transpose()?
        .unwrap_or_default();
    ws.send(Message::Text(serde_json::to_string(&KeySync {
        msg_type: "key_sync".into(),
        identity: server_identity
            .as_ref()
            .map(|identity| identity.public_key.clone())
            .unwrap_or_default(),
        offers,
    })?))
    .await
    .context("send channel keys")?;
    let key_sync = read_key_sync(&mut ws).await?;
    if key_sync.identity != status.requester {
        bail!("channel-key response identity does not match requester");
    }
    if policy.visibility == store::ChannelVisibility::Private
        && !store::policy_allows_read(&policy, &key_sync.identity)
    {
        bail!("channel-key sender is not a channel member");
    }
    validate_key_offers(&key_sync)?;
    if let Some(server_identity) = &server_identity {
        crate::crypto::accept_key_offers(
            datadir,
            &chan.full_name,
            server_identity,
            &key_sync.offers,
        )?;
    } else if !key_sync.offers.is_empty() {
        bail!("received channel keys for a public channel");
    }
    let server_summaries = store::chunk_summaries(datadir, &chan)?;
    let client_hashes: std::collections::HashMap<u64, &str> = status
        .chunks
        .iter()
        .map(|chunk| (chunk.index, chunk.hash.as_str()))
        .collect();
    if client_hashes.len() != status.chunks.len()
        || status.chunks.iter().any(|chunk| {
            hex::decode(&chunk.hash)
                .map(|hash| hash.len() != 32)
                .unwrap_or(true)
        })
    {
        bail!("invalid chunk summary");
    }
    let server_hashes: std::collections::HashMap<u64, &str> = server_summaries
        .iter()
        .map(|chunk| (chunk.index, chunk.hash.as_str()))
        .collect();
    let mut differing: Vec<u64> = server_hashes
        .keys()
        .chain(client_hashes.keys())
        .copied()
        .collect::<HashSet<_>>()
        .into_iter()
        .filter(|index| server_hashes.get(index) != client_hashes.get(index))
        .collect();
    differing.sort_unstable();
    let server_chunks: Vec<ChunkIds> = differing
        .iter()
        .map(|index| {
            Ok(ChunkIds {
                index: *index,
                ids: store::chunk_ids(datadir, &chan, *index)?,
            })
        })
        .collect::<Result<_>>()?;
    let expected_chunks: HashSet<u64> = differing.iter().copied().collect();
    ws.send(Message::Text(serde_json::to_string(&ChunkDiff {
        msg_type: "chunk_diff".into(),
        chunks: server_chunks.clone(),
        want_chunks: differing,
    })?))
    .await
    .context("send chunk diff")?;

    let batch = read_chunk_batch(&mut ws).await?;
    let returned_chunks: HashSet<u64> = batch.chunks.iter().map(|chunk| chunk.index).collect();
    if returned_chunks != expected_chunks || returned_chunks.len() != batch.chunks.len() {
        bail!("peer returned unexpected chunk inventory");
    }
    for chunk in &batch.chunks {
        for id in &chunk.ids {
            let bytes = hex::decode(id).context("invalid message id in chunk inventory")?;
            if bytes.len() != 32 || bytes[0] as u64 != chunk.index {
                bail!("message id does not belong to chunk {}", chunk.index);
            }
        }
    }
    let client_ids: HashSet<String> = batch.chunks.into_iter().flat_map(|c| c.ids).collect();
    let server_ids: HashSet<String> = server_chunks.into_iter().flat_map(|c| c.ids).collect();
    if client_ids.len() > MAX_DIFFERING_IDS || server_ids.len() > MAX_DIFFERING_IDS {
        bail!("differing inventory exceeds {MAX_DIFFERING_IDS} ids");
    }
    let wanted_from_client: Vec<String> = client_ids.difference(&server_ids).cloned().collect();
    let to_client: Vec<String> = server_ids.difference(&client_ids).cloned().collect();

    let want = WantMessage {
        msg_type: "want".into(),
        ids: wanted_from_client.clone(),
    };
    ws.send(Message::Text(serde_json::to_string(&want)?))
        .await
        .context("send want")?;

    for id in &to_client {
        let env = store::read_message_by_id(datadir, &chan, id)?;
        ws.send(Message::Text(serde_json::to_string(&env)?))
            .await
            .context("send envelope")?;
    }

    let mut wanted: HashSet<String> = wanted_from_client.into_iter().collect();
    let mut received = 0_u64;
    while !wanted.is_empty() {
        let msg = ws.next().await.context("peer closed during upload")??;
        let Message::Text(text) = msg else {
            continue;
        };
        let env: Envelope = serde_json::from_str(&text).context("deserialize uploaded envelope")?;
        accept_requested_id(&mut wanted, &env.id)?;
        if env.channel != chan.full_name {
            bail!("uploaded envelope {} belongs to {}", env.id, env.channel);
        }
        env.verify()
            .with_context(|| format!("verify uploaded envelope {}", env.id))?;
        append_message(datadir, &chan, &env)?;
        received += 1;
    }

    let sent = to_client.len() as u64;
    ws.send(Message::Text(
        SyncResponse::complete(sent, received).to_json(),
    ))
    .await
    .context("send complete")?;
    tracing::info!("sync: sent {sent}, received {received}");
    Ok(())
}

fn accept_requested_id(wanted: &mut HashSet<String>, id: &str) -> Result<()> {
    if !wanted.remove(id) {
        bail!("client uploaded unrequested envelope {id}");
    }
    Ok(())
}

fn is_policy_prefix(prefix: &[store::PolicyEvent], history: &[store::PolicyEvent]) -> bool {
    prefix.len() <= history.len()
        && prefix
            .iter()
            .zip(history)
            .all(|(left, right)| left.id == right.id)
}

fn is_moderation_prefix(
    prefix: &[store::ModerationEvent],
    history: &[store::ModerationEvent],
) -> bool {
    prefix.len() <= history.len()
        && prefix
            .iter()
            .zip(history)
            .all(|(left, right)| left.id == right.id)
}

async fn read_status(ws: &mut WebSocket) -> Result<StatusMessage> {
    let msg = ws
        .next()
        .await
        .context("ws closed before status")?
        .context("ws error reading status")?;
    let Message::Text(text) = msg else {
        bail!("expected text status");
    };
    let status: StatusMessage = serde_json::from_str(&text).context("invalid status packet")?;
    if status.msg_type != "status" {
        bail!("expected type=status, got type={}", status.msg_type);
    }
    Ok(status)
}

async fn read_chunk_batch(ws: &mut WebSocket) -> Result<ChunkBatch> {
    loop {
        let msg = ws
            .next()
            .await
            .context("peer closed before chunk inventory")??;
        if let Message::Text(text) = msg {
            let batch: ChunkBatch = serde_json::from_str(&text).context("invalid chunk batch")?;
            if batch.msg_type != "chunk_ids" {
                bail!("expected type=chunk_ids");
            }
            return Ok(batch);
        }
    }
}

async fn read_key_sync(ws: &mut WebSocket) -> Result<KeySync> {
    loop {
        let msg = ws
            .next()
            .await
            .context("peer closed before channel-key response")??;
        if let Message::Text(text) = msg {
            let sync: KeySync =
                serde_json::from_str(&text).context("invalid channel-key response")?;
            if sync.msg_type != "key_sync" {
                bail!("expected type=key_sync");
            }
            return Ok(sync);
        }
    }
}

fn validate_key_offers(sync: &KeySync) -> Result<()> {
    if sync.offers.len() > MAX_KEY_OFFERS {
        bail!("channel-key exchange exceeds {MAX_KEY_OFFERS} offers");
    }
    if sync
        .offers
        .iter()
        .any(|offer| offer.sender != sync.identity)
    {
        bail!("channel-key offer sender does not match peer identity");
    }
    Ok(())
}

pub async fn sync_from_peer(datadir: &Path, peer_url: &str, channel: &str) -> Result<u64> {
    tokio::time::timeout(
        SYNC_TIMEOUT,
        sync_from_peer_inner(datadir, peer_url, channel),
    )
    .await
    .context("peer synchronization timed out")?
}

async fn sync_from_peer_inner(datadir: &Path, peer_url: &str, channel: &str) -> Result<u64> {
    use tokio_tungstenite::connect_async;

    let chan = ChannelRef::parse(channel)?;
    let local_chunks = store::chunk_summaries(datadir, &chan)?;
    let policy_events = store::read_policy_history(datadir, &chan)?;
    let moderation_events = store::read_moderation_history(datadir, &chan)?;
    let identity = KeypairFile::load_secure(&datadir.join("keys/identity.json"))
        .context("load identity for synchronization")?;
    let auth_ts = chrono::Utc::now().timestamp();

    let (mut ws, _) = connect_async(peer_url).await.context("connect to peer")?;
    let challenge = read_client_challenge(&mut ws).await?;
    let expected = crate::peers::expected_peer_key(datadir, peer_url)?;
    verify_auth_challenge(&challenge, "/sync", expected.as_deref())?;
    let auth_sig = identity.sign_bytes(&sync_auth_payload(
        auth_ts,
        channel,
        &challenge.nonce,
        &challenge.responder,
    ))?;
    let status = serde_json::json!({
        "type": "status",
        "version": SYNC_VERSION,
        "channel": channel,
        "requester": identity.public_key,
        "auth_ts": auth_ts,
        "auth_sig": auth_sig,
        "policy_events": policy_events,
        "moderation_events": moderation_events,
        "chunks": local_chunks,
    });
    ws.send(tokio_tungstenite::tungstenite::Message::Text(
        status.to_string(),
    ))
    .await
    .context("send status to peer")?;

    let mut received = 0_u64;
    let mut completed = false;
    while let Some(msg) = ws.next().await {
        let msg = msg.context("ws read error")?;
        let tokio_tungstenite::tungstenite::Message::Text(text) = msg else {
            continue;
        };

        if let Ok(response) = serde_json::from_str::<SyncResponse>(&text) {
            if response.status == "complete" {
                completed = true;
                break;
            }
            if response.status == "error" {
                bail!(
                    "peer error: {}",
                    response.error.as_deref().unwrap_or("unknown")
                );
            }
        }

        if let Ok(policy) = serde_json::from_str::<PolicySync>(&text)
            && policy.msg_type == "policy_sync"
        {
            if policy.status == "conflict" {
                store::save_policy_conflict(datadir, &chan, &policy.events)?;
                bail!("policy history fork");
            }
            if policy.status != "update" {
                bail!("unexpected policy sync status {}", policy.status);
            }
            store::append_remote_policy_history(datadir, &chan, &policy.events)?;
            continue;
        }

        if let Ok(moderation) = serde_json::from_str::<ModerationSync>(&text)
            && moderation.msg_type == "moderation_sync"
        {
            if moderation.status == "conflict" {
                store::save_moderation_conflict(datadir, &chan, &moderation.events)?;
                bail!("moderation history fork");
            }
            if moderation.status != "update" {
                bail!("unexpected moderation sync status {}", moderation.status);
            }
            store::append_remote_moderation_history(datadir, &chan, &moderation.events)?;
            continue;
        }

        if let Ok(key_sync) = serde_json::from_str::<KeySync>(&text)
            && key_sync.msg_type == "key_sync"
        {
            validate_key_offers(&key_sync)?;
            let policy = store::read_channel_policy(datadir, &chan)?;
            if policy.visibility == store::ChannelVisibility::Private
                && !store::policy_allows_read(&policy, &key_sync.identity)
            {
                bail!("channel-key sender is not a channel member");
            }
            if policy.visibility == store::ChannelVisibility::Private {
                crate::crypto::accept_key_offers(
                    datadir,
                    &chan.full_name,
                    &identity,
                    &key_sync.offers,
                )?;
            } else if !key_sync.offers.is_empty() {
                bail!("received channel keys for a public channel");
            }
            let offers = if policy.visibility == store::ChannelVisibility::Private {
                crate::crypto::make_key_offers(
                    datadir,
                    &chan.full_name,
                    &identity,
                    &key_sync.identity,
                )?
            } else {
                Vec::new()
            };
            ws.send(tokio_tungstenite::tungstenite::Message::Text(
                serde_json::to_string(&KeySync {
                    msg_type: "key_sync".into(),
                    identity: identity.public_key.clone(),
                    offers,
                })?,
            ))
            .await
            .context("send channel-key response")?;
            continue;
        }

        if let Ok(diff) = serde_json::from_str::<ChunkDiff>(&text)
            && diff.msg_type == "chunk_diff"
        {
            let chunks = diff
                .want_chunks
                .into_iter()
                .map(|index| {
                    Ok(ChunkIds {
                        index,
                        ids: store::chunk_ids(datadir, &chan, index)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            ws.send(tokio_tungstenite::tungstenite::Message::Text(
                serde_json::to_string(&ChunkBatch {
                    msg_type: "chunk_ids".into(),
                    chunks,
                })?,
            ))
            .await
            .context("send chunk ids")?;
            continue;
        }

        if let Ok(want) = serde_json::from_str::<WantMessage>(&text)
            && want.msg_type == "want"
        {
            for id in &want.ids {
                let env = store::read_message_by_id(datadir, &chan, id)?;
                ws.send(tokio_tungstenite::tungstenite::Message::Text(
                    serde_json::to_string(&env)?,
                ))
                .await
                .context("upload wanted envelope")?;
            }
            continue;
        }

        let env: Envelope = serde_json::from_str(&text).context("deserialize envelope")?;
        if env.channel != chan.full_name {
            bail!("downloaded envelope {} belongs to {}", env.id, env.channel);
        }
        env.verify()
            .with_context(|| format!("verify downloaded envelope {}", env.id))?;
        append_message(datadir, &chan, &env)?;
        received += 1;
    }
    if !completed {
        bail!("peer closed before sync completion");
    }
    Ok(received)
}

async fn read_client_challenge(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Result<AuthChallenge> {
    let message = ws
        .next()
        .await
        .context("peer closed before authentication challenge")??;
    let tokio_tungstenite::tungstenite::Message::Text(text) = message else {
        bail!("expected text authentication challenge");
    };
    let challenge: AuthChallenge =
        serde_json::from_str(&text).context("invalid authentication challenge")?;
    if challenge.msg_type != "challenge" {
        bail!("expected type=challenge");
    }
    Ok(challenge)
}

fn responder_challenge_payload(
    target: &str,
    nonce: &str,
    responder: &str,
    expires: i64,
) -> Vec<u8> {
    format!("embernet-responder-challenge-v1\n{target}\n{nonce}\n{responder}\n{expires}")
        .into_bytes()
}

pub(crate) fn make_auth_challenge(identity: &KeypairFile, target: &str) -> Result<AuthChallenge> {
    let nonce = hex::encode(rand::random::<[u8; 32]>());
    let expires = chrono::Utc::now().timestamp() + 60;
    let payload = responder_challenge_payload(target, &nonce, &identity.public_key, expires);
    Ok(AuthChallenge {
        msg_type: "challenge".into(),
        nonce,
        responder: identity.public_key.clone(),
        expires,
        signature: identity.sign_bytes(&payload)?,
    })
}

fn verify_auth_challenge(
    challenge: &AuthChallenge,
    target: &str,
    expected: Option<&str>,
) -> Result<()> {
    if challenge.msg_type != "challenge" {
        bail!("expected type=challenge");
    }
    if challenge.expires < chrono::Utc::now().timestamp()
        || challenge.expires > chrono::Utc::now().timestamp() + 60
    {
        bail!("invalid authentication challenge expiry");
    }
    let nonce = hex::decode(&challenge.nonce).context("invalid challenge nonce")?;
    if nonce.len() != 32 {
        bail!("challenge nonce must contain 32 bytes");
    }
    if let Some(expected) = expected
        && challenge.responder != expected
    {
        bail!(
            "peer identity mismatch: expected {expected}, received {}",
            challenge.responder
        );
    }
    verify_bytes(
        &challenge.responder,
        &challenge.signature,
        &responder_challenge_payload(
            target,
            &challenge.nonce,
            &challenge.responder,
            challenge.expires,
        ),
    )
    .context("invalid responder challenge signature")
}

fn sync_auth_payload(timestamp: i64, channel: &str, nonce: &str, responder: &str) -> Vec<u8> {
    format!("embernet-sync-auth-v2\n{timestamp}\n{channel}\n{nonce}\n{responder}").into_bytes()
}

pub(crate) fn discovery_auth_payload(timestamp: i64, nonce: &str, responder: &str) -> Vec<u8> {
    format!("embernet-discovery-v2\n{timestamp}\n/status\n{nonce}\n{responder}").into_bytes()
}

pub async fn discover_peer_channels(datadir: &Path, peer_url: &str) -> Result<Vec<String>> {
    let mut status_url =
        reqwest::Url::parse(peer_url).context("invalid peer URL for channel discovery")?;
    let http_scheme = match status_url.scheme() {
        "ws" => "http",
        "wss" => "https",
        scheme => bail!("unsupported peer URL scheme {scheme}"),
    };
    status_url
        .set_scheme(http_scheme)
        .map_err(|_| anyhow::anyhow!("could not convert peer URL to HTTP"))?;
    status_url.set_path("/status");
    status_url.set_query(None);
    status_url.set_fragment(None);

    let identity = KeypairFile::load_secure(&datadir.join("keys/identity.json"))
        .context("load identity for channel discovery")?;
    let mut challenge_url = status_url.clone();
    challenge_url.set_path("/challenge");
    let challenge: AuthChallenge = reqwest::Client::new()
        .get(challenge_url)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .context("request discovery challenge")?
        .error_for_status()
        .context("discovery challenge returned an error")?
        .json()
        .await
        .context("decode discovery challenge")?;
    let expected = crate::peers::expected_peer_key(datadir, peer_url)?;
    verify_auth_challenge(&challenge, "/status", expected.as_deref())?;
    let timestamp = chrono::Utc::now().timestamp();
    let signature = identity.sign_bytes(&discovery_auth_payload(
        timestamp,
        &challenge.nonce,
        &challenge.responder,
    ))?;
    let response = reqwest::Client::new()
        .get(status_url)
        .header(DISCOVERY_KEY_HEADER, &identity.public_key)
        .header(DISCOVERY_TIMESTAMP_HEADER, timestamp.to_string())
        .header(DISCOVERY_SIGNATURE_HEADER, signature)
        .header(DISCOVERY_NONCE_HEADER, challenge.nonce)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .context("request peer status")?
        .error_for_status()
        .context("peer status returned an error")?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_STATUS_BYTES as u64)
    {
        bail!("peer status exceeds {MAX_STATUS_BYTES} bytes");
    }
    let body = response.bytes().await.context("read peer status")?;
    if body.len() > MAX_STATUS_BYTES {
        bail!("peer status exceeds {MAX_STATUS_BYTES} bytes");
    }
    let status: PeerStatus = serde_json::from_slice(&body).context("decode peer status")?;
    if !status.ok {
        bail!("peer reported an unhealthy status");
    }
    if status.channels.len() > MAX_DISCOVERED_CHANNELS {
        bail!("peer advertises more than {MAX_DISCOVERED_CHANNELS} channels");
    }
    let mut channels = status
        .channels
        .into_iter()
        .filter(|channel| ChannelRef::parse(channel).is_ok())
        .collect::<Vec<_>>();
    channels.sort();
    channels.dedup();
    Ok(channels)
}

pub async fn sync_all_from_peer(datadir: &Path, peer_url: &str) -> Result<PeerSyncSummary> {
    let channels = discover_peer_channels(datadir, peer_url).await?;
    let mut received = 0;
    for channel in &channels {
        let chan = ChannelRef::parse(channel)?;
        store::create_channel(datadir, &chan)?;
        received += sync_from_peer(datadir, peer_url, channel).await?;
    }
    Ok(PeerSyncSummary {
        channels: channels.len(),
        received,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{KeypairFile, Message};
    use crate::store::{
        ChannelVisibility, PolicyRole, create_channel, grant_role, init_layout,
        list_moderation_conflicts, list_policy_conflicts, message_ids, moderation_state,
        read_channel_tail_decrypted, read_policy_history, restrict_channel, set_channel_visibility,
        sign_message_for_channel, tombstone_message,
    };
    use crate::util::channel_to_path;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("embernet_sync_{label}_{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn add_message(base: &Path, chan: &ChannelRef, body: &str) -> String {
        let env = Envelope::sign(
            KeypairFile::generate(Some(body.into())),
            &chan.full_name,
            Message::new_text(None, vec![], body.into(), vec![]),
        )
        .unwrap();
        append_message(base, chan, &env).unwrap();
        env.id
    }

    #[test]
    fn duplicate_upload_cannot_satisfy_distinct_wanted_ids() {
        let mut wanted = HashSet::from(["first".to_string(), "second".to_string()]);
        accept_requested_id(&mut wanted, "first").unwrap();
        assert!(accept_requested_id(&mut wanted, "first").is_err());
        assert_eq!(wanted, HashSet::from(["second".to_string()]));
    }

    #[test]
    fn responder_challenge_requires_its_signer_and_expected_pin() {
        let responder = KeypairFile::generate(Some("responder".into()));
        let other = KeypairFile::generate(Some("other".into()));
        let challenge = make_auth_challenge(&responder, "/sync").unwrap();
        verify_auth_challenge(&challenge, "/sync", Some(&responder.public_key)).unwrap();
        assert!(verify_auth_challenge(&challenge, "/status", None).is_err());
        assert!(verify_auth_challenge(&challenge, "/sync", Some(&other.public_key)).is_err());

        let mut forged = challenge;
        forged.responder = other.public_key.clone();
        assert!(verify_auth_challenge(&forged, "/sync", None).is_err());
    }

    #[tokio::test]
    async fn pinned_peer_rejects_a_different_responder_identity() {
        let server_dir = temp_dir("pin_server");
        let client_dir = temp_dir("pin_client");
        for dir in [&server_dir, &client_dir] {
            init_layout(dir).unwrap();
        }
        let server_identity = ensure_identity(&server_dir);
        ensure_identity(&client_dir);
        let chan = ChannelRef::parse("test/pinning").unwrap();
        create_channel(&server_dir, &chan).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = crate::server::router(server_dir);
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let peer = format!("ws://{addr}/sync");

        crate::peers::add_peer(&client_dir, &peer, Some(&server_identity.public_key)).unwrap();
        assert_eq!(
            discover_peer_channels(&client_dir, &peer).await.unwrap(),
            vec!["test/pinning"]
        );
        crate::peers::remove_peer(&client_dir, &peer).unwrap();
        crate::peers::add_peer(
            &client_dir,
            &peer,
            Some(&KeypairFile::generate(None).public_key),
        )
        .unwrap();
        assert!(discover_peer_channels(&client_dir, &peer).await.is_err());
        assert!(
            sync_from_peer(&client_dir, &peer, &chan.full_name)
                .await
                .is_err()
        );
        task.abort();
    }

    fn ensure_identity(base: &Path) -> KeypairFile {
        let identity_path = base.join("keys/identity.json");
        if identity_path.exists() {
            return KeypairFile::load(&identity_path).unwrap();
        }
        let identity = KeypairFile::generate(Some("sync test".into()));
        identity.save(&identity_path).unwrap();
        identity
    }

    #[tokio::test]
    async fn equal_length_divergent_peers_converge() {
        let server_dir = temp_dir("server");
        let client_dir = temp_dir("client");
        let chan = ChannelRef::parse("test/divergence").unwrap();
        for dir in [&server_dir, &client_dir] {
            init_layout(dir).unwrap();
            create_channel(dir, &chan).unwrap();
        }
        ensure_identity(&client_dir);
        let server_id = add_message(&server_dir, &chan, "from server");
        let client_id = add_message(&client_dir, &chan, "from client");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = crate::server::router(server_dir.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let received = sync_from_peer(&client_dir, &format!("ws://{addr}/sync"), &chan.full_name)
            .await
            .unwrap();
        task.abort();

        assert_eq!(received, 1);
        let expected: HashSet<String> = [server_id, client_id].into_iter().collect();
        assert_eq!(
            message_ids(&server_dir, &chan)
                .unwrap()
                .into_iter()
                .collect::<HashSet<_>>(),
            expected
        );
        assert_eq!(
            message_ids(&client_dir, &chan)
                .unwrap()
                .into_iter()
                .collect::<HashSet<_>>(),
            expected
        );
        assert_eq!(
            store::chunk_summaries(&server_dir, &chan).unwrap(),
            store::chunk_summaries(&client_dir, &chan).unwrap()
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = crate::server::router(server_dir.clone());
        let retry_task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let retry_received =
            sync_from_peer(&client_dir, &format!("ws://{addr}/sync"), &chan.full_name)
                .await
                .unwrap();
        retry_task.abort();
        assert_eq!(retry_received, 0);
    }

    #[tokio::test]
    async fn discovers_nested_channels_and_syncs_without_local_creation() {
        let server_dir = temp_dir("discovery_server");
        let client_dir = temp_dir("discovery_client");
        init_layout(&server_dir).unwrap();
        init_layout(&client_dir).unwrap();
        ensure_identity(&client_dir);
        let chan = ChannelRef::parse("tech/discuss").unwrap();
        create_channel(&server_dir, &chan).unwrap();
        add_message(&server_dir, &chan, "discovered");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = crate::server::router(server_dir.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let peer = format!("ws://{addr}/sync");

        assert_eq!(
            discover_peer_channels(&client_dir, &peer).await.unwrap(),
            vec!["tech/discuss"]
        );
        let summary = sync_all_from_peer(&client_dir, &peer).await.unwrap();
        task.abort();

        assert_eq!(summary.channels, 1);
        assert_eq!(summary.received, 1);
        assert_eq!(
            store::list_channels(&client_dir).unwrap(),
            vec!["tech/discuss"]
        );
        assert_eq!(message_ids(&client_dir, &chan).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn private_channels_are_discovered_and_synced_only_by_members() {
        let server_dir = temp_dir("private_server");
        let member_dir = temp_dir("private_member");
        let outsider_dir = temp_dir("private_outsider");
        for dir in [&server_dir, &member_dir, &outsider_dir] {
            init_layout(dir).unwrap();
        }
        let owner = KeypairFile::generate(Some("owner".into()));
        owner.save(&server_dir.join("keys/identity.json")).unwrap();
        let member = ensure_identity(&member_dir);
        let outsider = ensure_identity(&outsider_dir);
        let chan = ChannelRef::parse("private/discuss").unwrap();
        create_channel(&server_dir, &chan).unwrap();
        restrict_channel(&server_dir, &chan, &owner).unwrap();
        grant_role(
            &server_dir,
            &chan,
            &owner,
            PolicyRole::Reader,
            &member.public_key,
        )
        .unwrap();
        set_channel_visibility(&server_dir, &chan, &owner, ChannelVisibility::Private).unwrap();
        let envelope = sign_message_for_channel(
            &server_dir,
            &chan,
            owner.clone(),
            Message::new_text(None, vec![], "members only".into(), vec![]),
        )
        .unwrap();
        assert!(matches!(
            envelope.msg.body,
            crate::proto::Body::Encrypted { .. }
        ));
        append_message(&server_dir, &chan, &envelope).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = crate::server::router(server_dir.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let peer = format!("ws://{addr}/sync");
        let anonymous: PeerStatus = reqwest::get(format!("http://{addr}/status"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(anonymous.channels.is_empty());

        assert_eq!(
            discover_peer_channels(&member_dir, &peer).await.unwrap(),
            vec!["private/discuss"]
        );
        let summary = sync_all_from_peer(&member_dir, &peer).await.unwrap();
        assert_eq!(summary.received, 1);
        assert!(matches!(
            store::read_message_by_id(&member_dir, &chan, &envelope.id)
                .unwrap()
                .msg
                .body,
            crate::proto::Body::Encrypted { .. }
        ));
        assert_eq!(
            read_channel_tail_decrypted(&member_dir, &chan, 10).unwrap()[0].body_text(),
            Some("members only")
        );

        let key_before_revoke = crate::crypto::current_channel_key(&server_dir, &chan.full_name)
            .unwrap()
            .id
            .clone();
        store::revoke_role(
            &server_dir,
            &chan,
            &owner,
            PolicyRole::Reader,
            &member.public_key,
        )
        .unwrap();
        assert_ne!(
            crate::crypto::current_channel_key(&server_dir, &chan.full_name)
                .unwrap()
                .id,
            key_before_revoke
        );
        assert!(
            discover_peer_channels(&member_dir, &peer)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            sync_from_peer(&member_dir, &peer, &chan.full_name)
                .await
                .is_err()
        );

        assert!(
            discover_peer_channels(&outsider_dir, &peer)
                .await
                .unwrap()
                .is_empty()
        );
        create_channel(&outsider_dir, &chan).unwrap();
        assert!(
            sync_from_peer(&outsider_dir, &peer, &chan.full_name)
                .await
                .is_err()
        );
        assert_ne!(member.public_key, outsider.public_key);
        task.abort();
    }

    #[tokio::test]
    async fn reconciled_revocation_blocks_channel_key_delivery() {
        let server_dir = temp_dir("stale_private_server");
        let client_dir = temp_dir("revoked_private_client");
        for dir in [&server_dir, &client_dir] {
            init_layout(dir).unwrap();
        }
        let owner = KeypairFile::generate(Some("owner".into()));
        owner.save(&server_dir.join("keys/identity.json")).unwrap();
        let member = ensure_identity(&client_dir);
        let chan = ChannelRef::parse("private/stale-policy").unwrap();
        create_channel(&server_dir, &chan).unwrap();
        restrict_channel(&server_dir, &chan, &owner).unwrap();
        grant_role(
            &server_dir,
            &chan,
            &owner,
            PolicyRole::Reader,
            &member.public_key,
        )
        .unwrap();
        set_channel_visibility(&server_dir, &chan, &owner, ChannelVisibility::Private).unwrap();

        create_channel(&client_dir, &chan).unwrap();
        copy_policy_history(&server_dir, &client_dir, &chan);
        crate::store::rebuild_policy_cache(&client_dir, &chan).unwrap();
        crate::store::revoke_role(
            &client_dir,
            &chan,
            &owner,
            PolicyRole::Reader,
            &member.public_key,
        )
        .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = crate::server::router(server_dir.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        assert!(
            sync_from_peer(&client_dir, &format!("ws://{addr}/sync"), &chan.full_name)
                .await
                .is_err()
        );
        assert!(!store::policy_allows_read(
            &store::read_channel_policy(&server_dir, &chan).unwrap(),
            &member.public_key
        ));
        task.abort();
    }

    #[tokio::test]
    async fn restricted_server_rejects_unauthorized_upload() {
        let server_dir = temp_dir("acl_server");
        let client_dir = temp_dir("acl_client");
        let chan = ChannelRef::parse("test/restricted").unwrap();
        for dir in [&server_dir, &client_dir] {
            init_layout(dir).unwrap();
            create_channel(dir, &chan).unwrap();
        }
        ensure_identity(&client_dir);
        let owner = KeypairFile::generate(Some("owner".into()));
        restrict_channel(&server_dir, &chan, &owner).unwrap();
        add_message(&client_dir, &chan, "unauthorized");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = crate::server::router(server_dir.clone());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let result =
            sync_from_peer(&client_dir, &format!("ws://{addr}/sync"), &chan.full_name).await;
        task.abort();

        assert!(result.is_err());
        assert!(message_ids(&server_dir, &chan).unwrap().is_empty());
    }

    fn copy_policy_history(from: &Path, to: &Path, chan: &ChannelRef) {
        let source = channel_to_path(from, &chan.full_name).join("policy.ndjson");
        let target = channel_to_path(to, &chan.full_name).join("policy.ndjson");
        std::fs::copy(source, target).unwrap();
    }

    async fn sync_once(server_dir: &Path, client_dir: &Path, chan: &ChannelRef) -> Result<u64> {
        ensure_identity(client_dir);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let app = crate::server::router(server_dir.to_path_buf());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let result =
            sync_from_peer(client_dir, &format!("ws://{addr}/sync"), &chan.full_name).await;
        task.abort();
        result
    }

    #[tokio::test]
    async fn policy_prefixes_sync_in_both_directions() {
        let server_dir = temp_dir("policy_server");
        let client_dir = temp_dir("policy_client");
        let chan = ChannelRef::parse("test/policy-sync").unwrap();
        for dir in [&server_dir, &client_dir] {
            init_layout(dir).unwrap();
            create_channel(dir, &chan).unwrap();
        }
        let owner = KeypairFile::generate(None);
        let first_writer = KeypairFile::generate(None);
        let second_writer = KeypairFile::generate(None);
        restrict_channel(&server_dir, &chan, &owner).unwrap();
        copy_policy_history(&server_dir, &client_dir, &chan);

        grant_role(
            &server_dir,
            &chan,
            &owner,
            PolicyRole::Writer,
            &first_writer.public_key,
        )
        .unwrap();
        sync_once(&server_dir, &client_dir, &chan).await.unwrap();
        assert_eq!(
            read_policy_history(&server_dir, &chan).unwrap(),
            read_policy_history(&client_dir, &chan).unwrap()
        );

        grant_role(
            &client_dir,
            &chan,
            &owner,
            PolicyRole::Writer,
            &second_writer.public_key,
        )
        .unwrap();
        sync_once(&server_dir, &client_dir, &chan).await.unwrap();
        assert_eq!(
            read_policy_history(&server_dir, &chan).unwrap(),
            read_policy_history(&client_dir, &chan).unwrap()
        );
    }

    #[tokio::test]
    async fn policy_fork_is_saved_and_blocks_message_sync() {
        let server_dir = temp_dir("fork_server");
        let client_dir = temp_dir("fork_client");
        let chan = ChannelRef::parse("test/policy-fork").unwrap();
        for dir in [&server_dir, &client_dir] {
            init_layout(dir).unwrap();
            create_channel(dir, &chan).unwrap();
        }
        let owner = KeypairFile::generate(None);
        restrict_channel(&server_dir, &chan, &owner).unwrap();
        copy_policy_history(&server_dir, &client_dir, &chan);
        for (dir, writer) in [
            (&server_dir, KeypairFile::generate(None)),
            (&client_dir, KeypairFile::generate(None)),
        ] {
            grant_role(dir, &chan, &owner, PolicyRole::Writer, &writer.public_key).unwrap();
        }

        assert!(sync_once(&server_dir, &client_dir, &chan).await.is_err());
        assert_eq!(list_policy_conflicts(&server_dir, &chan).unwrap().len(), 1);
        assert_eq!(list_policy_conflicts(&client_dir, &chan).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn moderation_prefix_syncs_before_message_views() {
        let server_dir = temp_dir("mod_server");
        let client_dir = temp_dir("mod_client");
        let chan = ChannelRef::parse("test/mod-sync").unwrap();
        for dir in [&server_dir, &client_dir] {
            init_layout(dir).unwrap();
            create_channel(dir, &chan).unwrap();
        }
        let owner = KeypairFile::generate(None);
        restrict_channel(&server_dir, &chan, &owner).unwrap();
        copy_policy_history(&server_dir, &client_dir, &chan);
        let env = Envelope::sign(
            owner.clone(),
            &chan.full_name,
            Message::new_text(None, vec![], "moderated".into(), vec![]),
        )
        .unwrap();
        append_message(&server_dir, &chan, &env).unwrap();
        append_message(&client_dir, &chan, &env).unwrap();
        tombstone_message(&server_dir, &chan, &owner, &env.id, Some("spam".into())).unwrap();

        sync_once(&server_dir, &client_dir, &chan).await.unwrap();
        assert!(
            moderation_state(&client_dir, &chan)
                .unwrap()
                .tombstoned
                .contains_key(&env.id)
        );
    }

    #[tokio::test]
    async fn moderation_fork_is_saved_and_blocks_message_sync() {
        let server_dir = temp_dir("mod_fork_server");
        let client_dir = temp_dir("mod_fork_client");
        let chan = ChannelRef::parse("test/mod-fork").unwrap();
        for dir in [&server_dir, &client_dir] {
            init_layout(dir).unwrap();
            create_channel(dir, &chan).unwrap();
        }
        let owner = KeypairFile::generate(None);
        restrict_channel(&server_dir, &chan, &owner).unwrap();
        copy_policy_history(&server_dir, &client_dir, &chan);
        let env = Envelope::sign(
            owner.clone(),
            &chan.full_name,
            Message::new_text(None, vec![], "target".into(), vec![]),
        )
        .unwrap();
        for dir in [&server_dir, &client_dir] {
            append_message(dir, &chan, &env).unwrap();
        }
        tombstone_message(&server_dir, &chan, &owner, &env.id, Some("server".into())).unwrap();
        tombstone_message(&client_dir, &chan, &owner, &env.id, Some("client".into())).unwrap();

        assert!(sync_once(&server_dir, &client_dir, &chan).await.is_err());
        assert_eq!(
            list_moderation_conflicts(&server_dir, &chan).unwrap().len(),
            1
        );
        assert_eq!(
            list_moderation_conflicts(&client_dir, &chan).unwrap().len(),
            1
        );
    }
}
