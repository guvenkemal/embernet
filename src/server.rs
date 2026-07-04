use crate::sync;
use anyhow::Result;
use axum::{
    Router, extract::State, extract::ws::WebSocketUpgrade, response::IntoResponse, routing::get,
};
use serde::Serialize;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub datadir: PathBuf,
}

#[derive(Serialize)]
struct Status {
    ok: bool,
    channels: Vec<String>,
}

pub async fn run(datadir: PathBuf, listen: String) -> Result<()> {
    let state = AppState {
        datadir: datadir.clone(),
    };
    let app = Router::new()
        .route("/status", get(status))
        .route("/sync", get(ws_sync_handler))
        .with_state(Arc::new(state));

    let addr: SocketAddr = listen.parse().expect("bad listen addr");
    tracing::info!("listening on {}", addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app).await?;
    Ok(())
}

async fn status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let ch_root = state.datadir.join("channels");
    let mut list = Vec::new();
    if let Ok(rd) = fs::read_dir(&ch_root) {
        for entry in rd.flatten() {
            if let Ok(ft) = entry.file_type() {
                if ft.is_dir() {
                    if let Ok(name) = entry.file_name().into_string() {
                        list.push(name);
                    }
                }
            }
        }
    }
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
