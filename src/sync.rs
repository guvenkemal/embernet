//! Divergence-safe, bidirectional Have/Want sync over WebSocket.

use crate::proto::Envelope;
use crate::server::AppState;
use crate::store::{self, ChannelRef, append_message};
use anyhow::{Context, Result, bail};
use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

const SYNC_VERSION: u32 = 3;
const MAX_DIFFERING_IDS: usize = 100_000;

#[derive(Debug, Deserialize)]
struct StatusMessage {
    #[serde(rename = "type")]
    msg_type: String,
    version: u32,
    channel: String,
    chunks: Vec<store::ChunkSummary>,
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
    if let Err(error) = run_sync(ws, &state.datadir).await {
        tracing::error!("sync session failed: {error:#}");
    }
}

async fn run_sync(mut ws: WebSocket, datadir: &Path) -> Result<()> {
    let status = read_status(&mut ws).await?;
    if status.version != SYNC_VERSION {
        bail!("unsupported sync version: {}", status.version);
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

    let wanted: HashSet<String> = wanted_from_client.into_iter().collect();
    let mut received = 0_u64;
    while received < wanted.len() as u64 {
        let msg = ws.next().await.context("peer closed during upload")??;
        let Message::Text(text) = msg else {
            continue;
        };
        let env: Envelope = serde_json::from_str(&text).context("deserialize uploaded envelope")?;
        if !wanted.contains(&env.id) {
            bail!("client uploaded unrequested envelope {}", env.id);
        }
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

pub async fn sync_from_peer(datadir: &Path, peer_url: &str, channel: &str) -> Result<u64> {
    use tokio_tungstenite::connect_async;

    let chan = ChannelRef::parse(channel)?;
    let local_chunks = store::chunk_summaries(datadir, &chan)?;
    let status = serde_json::json!({
        "type": "status",
        "version": SYNC_VERSION,
        "channel": channel,
        "chunks": local_chunks,
    });

    let (mut ws, _) = connect_async(peer_url).await.context("connect to peer")?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{KeypairFile, Message};
    use crate::store::{create_channel, init_layout, message_ids, restrict_channel};
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

    #[tokio::test]
    async fn equal_length_divergent_peers_converge() {
        let server_dir = temp_dir("server");
        let client_dir = temp_dir("client");
        let chan = ChannelRef::parse("test/divergence").unwrap();
        for dir in [&server_dir, &client_dir] {
            init_layout(dir).unwrap();
            create_channel(dir, &chan).unwrap();
        }
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
    async fn restricted_server_rejects_unauthorized_upload() {
        let server_dir = temp_dir("acl_server");
        let client_dir = temp_dir("acl_client");
        let chan = ChannelRef::parse("test/restricted").unwrap();
        for dir in [&server_dir, &client_dir] {
            init_layout(dir).unwrap();
            create_channel(dir, &chan).unwrap();
        }
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
}
