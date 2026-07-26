use anyhow::{Context, Result, bail};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Serialize, Deserialize)]
struct PeerConfig {
    version: u32,
    peers: Vec<String>,
}

fn config_path(datadir: &Path) -> PathBuf {
    datadir.join("peers.json")
}

pub fn normalize_peer_url(value: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(value.trim()).context("invalid peer URL")?;
    if !matches!(url.scheme(), "ws" | "wss") {
        bail!("peer URL must use ws:// or wss://");
    }
    if url.host_str().is_none() {
        bail!("peer URL must include a host");
    }
    url.set_query(None);
    url.set_fragment(None);
    if url.path().is_empty() || url.path() == "/" {
        url.set_path("/sync");
    }
    Ok(url.to_string())
}

pub fn list_peers(datadir: &Path) -> Result<Vec<String>> {
    let path = config_path(datadir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let mut config: PeerConfig =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    config.peers.sort();
    config.peers.dedup();
    Ok(config.peers)
}

pub fn add_peer(datadir: &Path, value: &str) -> Result<String> {
    let peer = normalize_peer_url(value)?;
    let _lock = lock_config(datadir)?;
    let mut peers = list_peers(datadir)?;
    if !peers.contains(&peer) {
        peers.push(peer.clone());
    }
    write_peers(datadir, peers)?;
    Ok(peer)
}

pub fn remove_peer(datadir: &Path, value: &str) -> Result<bool> {
    let peer = normalize_peer_url(value)?;
    let _lock = lock_config(datadir)?;
    let mut peers = list_peers(datadir)?;
    let original_len = peers.len();
    peers.retain(|candidate| candidate != &peer);
    let removed = peers.len() != original_len;
    write_peers(datadir, peers)?;
    Ok(removed)
}

fn lock_config(datadir: &Path) -> Result<std::fs::File> {
    std::fs::create_dir_all(datadir)
        .with_context(|| format!("create data directory {}", datadir.display()))?;
    let path = datadir.join("peers.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)?;
    file.lock_exclusive()
        .with_context(|| format!("lock {}", path.display()))?;
    Ok(file)
}

fn write_peers(datadir: &Path, mut peers: Vec<String>) -> Result<()> {
    std::fs::create_dir_all(datadir)
        .with_context(|| format!("create data directory {}", datadir.display()))?;
    peers.sort();
    peers.dedup();
    let config = PeerConfig { version: 1, peers };
    let path = config_path(datadir);
    let temporary = datadir.join(format!("peers.json.tmp-{:016x}", rand::random::<u64>()));
    let mut bytes = serde_json::to_vec_pretty(&config)?;
    bytes.push(b'\n');
    std::fs::write(&temporary, bytes).with_context(|| format!("write {}", temporary.display()))?;
    std::fs::rename(&temporary, &path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "embernet_peer_test_{}",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn peers_are_normalized_deduplicated_and_removed() {
        let datadir = temp_dir();
        add_peer(&datadir, "ws://localhost:4444").unwrap();
        add_peer(&datadir, "ws://localhost:4444/sync").unwrap();
        assert_eq!(
            list_peers(&datadir).unwrap(),
            vec!["ws://localhost:4444/sync"]
        );
        assert!(remove_peer(&datadir, "ws://localhost:4444").unwrap());
        assert!(list_peers(&datadir).unwrap().is_empty());
    }

    #[test]
    fn peer_url_rejects_non_websocket_schemes() {
        assert!(normalize_peer_url("https://localhost:4444").is_err());
        assert!(normalize_peer_url("not a URL").is_err());
    }

    #[test]
    fn concurrent_peer_updates_do_not_clobber_each_other() {
        let datadir = temp_dir();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let threads = ["ws://localhost:4444/sync", "ws://localhost:4445/sync"]
            .into_iter()
            .map(|peer| {
                let datadir = datadir.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    add_peer(&datadir, peer).unwrap();
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(
            list_peers(&datadir).unwrap(),
            vec!["ws://localhost:4444/sync", "ws://localhost:4445/sync"]
        );
    }
}
