use crate::proto::{KeypairFile, verify_bytes};
use crate::sync;
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::State,
    extract::ws::WebSocketUpgrade,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub struct AppState {
    pub datadir: PathBuf,
    pub responder: String,
    discovery_challenges: std::sync::Mutex<HashMap<String, i64>>,
}

#[derive(Serialize)]
struct Status {
    ok: bool,
    channels: Vec<String>,
}

#[derive(Serialize)]
struct Challenge {
    nonce: String,
    responder: String,
    expires: i64,
}

pub struct ServerHandle {
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<()>>>,
}

impl ServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task
            .take()
            .context("server task is unavailable")?
            .await
            .context("join server task")?
    }

    pub async fn wait(mut self) -> Result<()> {
        self.task
            .take()
            .context("server task is unavailable")?
            .await
            .context("join server task")?
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

pub async fn start(datadir: PathBuf, listen: &str) -> Result<ServerHandle> {
    let requested: SocketAddr = listen
        .parse()
        .with_context(|| format!("invalid listen address '{listen}'"))?;
    let listener = tokio::net::TcpListener::bind(requested)
        .await
        .with_context(|| format!("bind {requested}"))?;
    let addr = listener.local_addr()?;
    let app = router(datadir);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .context("serve HTTP/WebSocket")
    });
    Ok(ServerHandle {
        addr,
        shutdown: Some(shutdown_tx),
        task: Some(task),
    })
}

pub async fn run(datadir: PathBuf, listen: String) -> Result<()> {
    let server = start(datadir, &listen).await?;
    tracing::info!("listening on {}", server.local_addr());
    server.wait().await
}

pub(crate) fn router(datadir: PathBuf) -> Router {
    let responder = KeypairFile::load_secure(&datadir.join("keys/identity.json"))
        .map(|identity| identity.public_key.clone())
        .unwrap_or_else(|_| hex::encode(rand::random::<[u8; 32]>()));
    let state = AppState {
        datadir,
        responder,
        discovery_challenges: std::sync::Mutex::new(HashMap::new()),
    };
    Router::new()
        .route("/challenge", get(challenge))
        .route("/status", get(status))
        .route("/sync", get(ws_sync_handler))
        .with_state(Arc::new(state))
}

async fn challenge(State(state): State<Arc<AppState>>) -> Response {
    const MAX_DISCOVERY_CHALLENGES: usize = 10_000;
    let nonce = hex::encode(rand::random::<[u8; 32]>());
    let expires = chrono::Utc::now().timestamp() + 60;
    let mut challenges = match state.discovery_challenges.lock() {
        Ok(challenges) => challenges,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "error": "challenge state unavailable"})),
            )
                .into_response();
        }
    };
    let now = chrono::Utc::now().timestamp();
    challenges.retain(|_, expiry| *expiry >= now);
    if challenges.len() >= MAX_DISCOVERY_CHALLENGES {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"ok": false, "error": "too many active challenges"})),
        )
            .into_response();
    }
    challenges.insert(nonce.clone(), expires);
    Json(Challenge {
        nonce,
        responder: state.responder.clone(),
        expires,
    })
    .into_response()
}

async fn status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let requester = match discovery_requester(&state, &headers) {
        Ok(requester) => requester,
        Err(error) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"ok": false, "error": error.to_string()})),
            )
                .into_response();
        }
    };
    let list = crate::store::list_readable_channels(&state.datadir, requester.as_deref())
        .unwrap_or_default();
    Json(Status {
        ok: true,
        channels: list,
    })
    .into_response()
}

fn discovery_requester(state: &AppState, headers: &HeaderMap) -> Result<Option<String>> {
    let key = headers.get(sync::DISCOVERY_KEY_HEADER);
    let timestamp = headers.get(sync::DISCOVERY_TIMESTAMP_HEADER);
    let signature = headers.get(sync::DISCOVERY_SIGNATURE_HEADER);
    let nonce = headers.get(sync::DISCOVERY_NONCE_HEADER);
    if key.is_none() && timestamp.is_none() && signature.is_none() && nonce.is_none() {
        return Ok(None);
    }
    let key = key.context("missing discovery public key")?.to_str()?;
    let timestamp: i64 = timestamp
        .context("missing discovery timestamp")?
        .to_str()?
        .parse()
        .context("invalid discovery timestamp")?;
    let signature = signature.context("missing discovery signature")?.to_str()?;
    let nonce = nonce.context("missing discovery nonce")?.to_str()?;
    if (chrono::Utc::now().timestamp() - timestamp).abs() > 60 {
        anyhow::bail!("stale discovery signature");
    }
    let mut challenges = state
        .discovery_challenges
        .lock()
        .map_err(|_| anyhow::anyhow!("challenge state unavailable"))?;
    let expires = challenges
        .get(nonce)
        .copied()
        .context("unknown or already consumed discovery challenge")?;
    if expires < chrono::Utc::now().timestamp() {
        anyhow::bail!("expired discovery challenge");
    }
    verify_bytes(
        key,
        signature,
        &sync::discovery_auth_payload(timestamp, nonce, &state.responder),
    )
    .context("invalid discovery signature")?;
    challenges.remove(nonce);
    Ok(Some(key.to_string()))
}

/// Upgrade HTTP GET to WebSocket and hand off to the sync protocol handler.
async fn ws_sync_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| sync::handle_sync(socket, state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[tokio::test]
    async fn managed_server_reports_actual_address_and_shuts_down() {
        let datadir = std::env::temp_dir().join("embernet_managed_server_test");
        let _ = std::fs::remove_dir_all(&datadir);
        crate::store::init_layout(&datadir).unwrap();
        let server = start(datadir, "127.0.0.1:0").await.unwrap();
        let status_url = format!("http://{}/status", server.local_addr());

        let response: serde_json::Value = reqwest::get(status_url)
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(response["ok"], true);
        let address = server.local_addr();
        server.shutdown().await.unwrap();
        tokio::net::TcpListener::bind(address).await.unwrap();
    }

    #[tokio::test]
    async fn managed_server_rejects_an_occupied_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let result = start(PathBuf::new(), &address.to_string()).await;
        assert!(result.is_err());
    }

    #[test]
    fn discovery_challenge_is_consumed_once() {
        let identity = KeypairFile::generate(Some("alice".into()));
        let nonce = hex::encode(rand::random::<[u8; 32]>());
        let responder = hex::encode(rand::random::<[u8; 32]>());
        let timestamp = chrono::Utc::now().timestamp();
        let signature = identity
            .sign_bytes(&sync::discovery_auth_payload(timestamp, &nonce, &responder))
            .unwrap();
        let state = AppState {
            datadir: PathBuf::new(),
            responder,
            discovery_challenges: std::sync::Mutex::new(HashMap::from([(
                nonce.clone(),
                timestamp + 60,
            )])),
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            sync::DISCOVERY_KEY_HEADER,
            HeaderValue::from_str(&identity.public_key).unwrap(),
        );
        headers.insert(
            sync::DISCOVERY_TIMESTAMP_HEADER,
            HeaderValue::from_str(&timestamp.to_string()).unwrap(),
        );
        headers.insert(
            sync::DISCOVERY_SIGNATURE_HEADER,
            HeaderValue::from_str(&signature).unwrap(),
        );
        headers.insert(
            sync::DISCOVERY_NONCE_HEADER,
            HeaderValue::from_str(&nonce).unwrap(),
        );
        assert_eq!(
            discovery_requester(&state, &headers).unwrap(),
            Some(identity.public_key.clone())
        );
        assert!(discovery_requester(&state, &headers).is_err());
    }
}
