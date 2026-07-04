//! Have/Want sync protocol over WebSocket.
//!
//! Protocol:
//!   1. Client connects via WS to `/sync`.
//!   2. Client sends: `{"type":"status","channel":"<name>","count":<N>}`
//!   3. Server compares its log count for that channel:
//!       a. If server count <= client count → `{"type":"response","status":"up_to_date"}`
//!       b. If server has more → streams each missing Envelope as a JSON text frame,
//!          then sends `{"type":"response","status":"complete","sent":<N>}`
//!   4. Client verifies each incoming Envelope with `Envelope::verify()` before
//!      appending to its local log.
//!   5. Either side may close the socket after the exchange.

use crate::proto::Envelope;
use crate::store::{self, ChannelRef, append_message};
use anyhow::{Context, Result, bail};
use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

use crate::server::AppState;

// ── wire types ────────────────────────────────────────────────────────────────

/// Incoming status packet from the client.
#[derive(Debug, Deserialize)]
struct StatusMessage {
    #[serde(rename = "type")]
    msg_type: String,
    channel: String,
    count: u64,
}

/// Outgoing response from the server.
#[derive(Debug, Serialize, Deserialize)]
struct SyncResponse {
    #[serde(rename = "type")]
    msg_type: String, // "response"
    status: String, // "up_to_date" | "complete" | "error"
    #[serde(skip_serializing_if = "Option::is_none")]
    sent: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl SyncResponse {
    fn up_to_date() -> Self {
        Self {
            msg_type: "response".into(),
            status: "up_to_date".into(),
            sent: None,
            error: None,
        }
    }

    fn complete(sent: u64) -> Self {
        Self {
            msg_type: "response".into(),
            status: "complete".into(),
            sent: Some(sent),
            error: None,
        }
    }

    #[allow(dead_code)]
    fn error(msg: impl Into<String>) -> Self {
        Self {
            msg_type: "response".into(),
            status: "error".into(),
            sent: None,
            error: Some(msg.into()),
        }
    }

    fn to_json(&self) -> String {
        // unwrap is safe — SyncResponse is always serializable
        serde_json::to_string(self).unwrap()
    }
}

// ── handler ───────────────────────────────────────────────────────────────────

/// Handle a single WebSocket sync session.
///
/// Reads one status packet, compares channel counts, and streams
/// any missing envelopes back to the peer.
pub async fn handle_sync(ws: WebSocket, state: Arc<AppState>) {
    tracing::info!("sync: new websocket connection");

    if let Err(e) = run_sync(ws, &state.datadir).await {
        tracing::error!("sync session failed: {e:#}");
    }
}

async fn run_sync(mut ws: WebSocket, datadir: &Path) -> Result<()> {
    // ── 1. read the status packet ──
    let status_msg = read_status(&mut ws).await?;

    // validate channel name
    let chan = ChannelRef::parse(&status_msg.channel).context("invalid channel name in status")?;

    tracing::info!(
        "sync: peer has {} messages for channel '{}'",
        status_msg.count,
        status_msg.channel
    );

    // ── 2. compare counts ──
    let server_count = store::count_messages(datadir, &chan)
        .with_context(|| format!("count_messages failed for {}", status_msg.channel))?;

    tracing::info!(
        "sync: server has {} messages for channel '{}'",
        server_count,
        status_msg.channel
    );

    if server_count <= status_msg.count {
        // peer is up to date (or ahead — nothing to give)
        ws.send(Message::Text(SyncResponse::up_to_date().to_json().into()))
            .await
            .context("send up_to_date")?;
        tracing::info!("sync: peer up to date, done.");
        return Ok(());
    }

    // ── 3. stream missing envelopes ──
    let from = status_msg.count; // 0-indexed — skip what they already have
    let envelopes = store::read_channel_from(datadir, &chan, from)
        .with_context(|| format!("read_channel_from({}) failed", status_msg.channel))?;

    let sent = envelopes.len() as u64;

    for env in &envelopes {
        let json = serde_json::to_string(env).context("serialize envelope")?;
        ws.send(Message::Text(json.into()))
            .await
            .context("send envelope")?;
    }

    // ── 4. completion marker ──
    ws.send(Message::Text(SyncResponse::complete(sent).to_json().into()))
        .await
        .context("send complete")?;

    tracing::info!("sync: sent {sent} envelopes, done.");
    Ok(())
}

/// Read exactly one text message from the socket and deserialize as StatusMessage.
async fn read_status(ws: &mut WebSocket) -> Result<StatusMessage> {
    let msg = ws
        .next()
        .await
        .context("ws closed before status")?
        .context("ws error reading status")?;

    let text = match msg {
        Message::Text(t) => t.to_string(),
        Message::Close(_) => bail!("peer closed before sending status"),
        other => bail!("expected text status, got {other:?}"),
    };

    serde_json::from_str::<StatusMessage>(&text)
        .context("invalid status packet")
        .and_then(|s| {
            if s.msg_type != "status" {
                bail!("expected type=status, got type={}", s.msg_type);
            }
            Ok(s)
        })
}

// ── client-side sync helper ───────────────────────────────────────────────────

/// Connect to a remote peer's `/sync` endpoint, send a status packet,
/// and receive+verify+append any missing envelopes.
///
/// This is intended for CLI-driven or background sync — it opens a
/// client WebSocket, performs the Have/Want handshake, and writes
/// verified envelopes into the local store.
pub async fn sync_from_peer(datadir: &Path, peer_url: &str, channel: &str) -> Result<u64> {
    use futures_util::StreamExt;
    use tokio_tungstenite::connect_async;

    let chan = ChannelRef::parse(channel)?;
    let local_count = store::count_messages(datadir, &chan)?;

    // Build the status packet
    let status = serde_json::json!({
        "type": "status",
        "channel": channel,
        "count": local_count,
    });

    tracing::info!(
        "sync_client: connecting to {} for channel '{}' (local count={})",
        peer_url,
        channel,
        local_count
    );

    let (mut ws_stream, _) = connect_async(peer_url).await.context("connect to peer")?;

    // Send our status
    ws_stream
        .send(tokio_tungstenite::tungstenite::Message::Text(
            status.to_string(),
        ))
        .await
        .context("send status to peer")?;

    let mut received: u64 = 0;

    // Read responses: envelope JSON frames, then the final response frame
    while let Some(msg) = ws_stream.next().await {
        let msg = msg.context("ws read error")?;
        let text = match msg {
            tokio_tungstenite::tungstenite::Message::Text(t) => t.to_string(),
            tokio_tungstenite::tungstenite::Message::Close(_) => break,
            _ => continue,
        };

        // Try deserializing as a response frame first
        if let Ok(resp) = serde_json::from_str::<SyncResponse>(&text) {
            match resp.status.as_str() {
                "up_to_date" => {
                    tracing::info!("sync_client: already up to date");
                    break;
                }
                "complete" => {
                    tracing::info!(
                        "sync_client: sync complete, received {} envelopes",
                        received
                    );
                    break;
                }
                "error" => {
                    bail!("peer error: {}", resp.error.as_deref().unwrap_or("unknown"));
                }
                _ => {
                    tracing::warn!("sync_client: unexpected response status: {}", resp.status);
                    break;
                }
            }
        }

        // Otherwise, treat it as an envelope
        let env: Envelope = serde_json::from_str(&text).context("deserialize envelope")?;

        // ── integrity check ──
        env.verify()
            .with_context(|| format!("signature verification failed for {}", env.id))?;

        // Append to local log
        append_message(datadir, &chan, &env)?;
        received += 1;
    }

    Ok(received)
}
