use crate::sync;
use anyhow::{Context, Result};
use axum::{
    Router, extract::State, extract::ws::WebSocketUpgrade, response::IntoResponse, routing::get,
};
use serde::Serialize;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct AppState {
    pub datadir: PathBuf,
}

#[derive(Serialize)]
struct Status {
    ok: bool,
    channels: Vec<String>,
}

pub struct ServerHandle {
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<()>>,
}

impl ServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.await.context("join server task")?
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
        task,
    })
}

pub async fn run(datadir: PathBuf, listen: String) -> Result<()> {
    let server = start(datadir, &listen).await?;
    tracing::info!("listening on {}", server.local_addr());
    server.task.await.context("join server task")?
}

pub(crate) fn router(datadir: PathBuf) -> Router {
    let state = AppState { datadir };
    Router::new()
        .route("/status", get(status))
        .route("/sync", get(ws_sync_handler))
        .with_state(Arc::new(state))
}

async fn status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let list = crate::store::list_channels(&state.datadir).unwrap_or_default();
    axum::Json(Status {
        ok: true,
        channels: list,
    })
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
}
