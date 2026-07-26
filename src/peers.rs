use anyhow::{Context, Result, bail};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerRecord {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum StoredPeer {
    Legacy(String),
    Record(PeerRecord),
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PeerConfig {
    version: u32,
    peers: Vec<StoredPeer>,
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

fn validate_public_key(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    let bytes = hex::decode(&normalized).context("peer public key must be hexadecimal")?;
    if bytes.len() != 32 {
        bail!("peer public key must encode 32 bytes");
    }
    Ok(normalized)
}

pub fn list_peer_records(datadir: &Path) -> Result<Vec<PeerRecord>> {
    let path = config_path(datadir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let config: PeerConfig =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    if !matches!(config.version, 1 | 2) {
        bail!("unsupported peer configuration version {}", config.version);
    }
    let mut records = Vec::<PeerRecord>::new();
    for stored in config.peers {
        let mut record = match stored {
            StoredPeer::Legacy(url) => PeerRecord {
                url,
                public_key: None,
            },
            StoredPeer::Record(record) => record,
        };
        record.url = normalize_peer_url(&record.url)?;
        record.public_key = record
            .public_key
            .as_deref()
            .map(validate_public_key)
            .transpose()?;
        if let Some(existing) = records.iter_mut().find(|peer| peer.url == record.url) {
            if existing.public_key.is_none() {
                existing.public_key = record.public_key;
            } else if record.public_key.is_some() && existing.public_key != record.public_key {
                bail!("peer {} has conflicting pinned identities", record.url);
            }
        } else {
            records.push(record);
        }
    }
    records.sort_by(|left, right| left.url.cmp(&right.url));
    Ok(records)
}

pub fn list_peers(datadir: &Path) -> Result<Vec<String>> {
    Ok(list_peer_records(datadir)?
        .into_iter()
        .map(|peer| peer.url)
        .collect())
}

pub fn expected_peer_key(datadir: &Path, value: &str) -> Result<Option<String>> {
    let url = normalize_peer_url(value)?;
    let Some(record) = list_peer_records(datadir)?
        .into_iter()
        .find(|peer| peer.url == url)
    else {
        return Ok(None);
    };
    record.public_key.map(Some).context(format!(
        "peer {url} is unpinned; add it again with --public-key"
    ))
}

pub fn add_peer(datadir: &Path, value: &str, public_key: Option<&str>) -> Result<PeerRecord> {
    let url = normalize_peer_url(value)?;
    let public_key = public_key.map(validate_public_key).transpose()?;
    let _lock = lock_config(datadir)?;
    let mut peers = list_peer_records(datadir)?;
    if let Some(existing) = peers.iter_mut().find(|peer| peer.url == url) {
        if let Some(public_key) = public_key {
            if let Some(current) = &existing.public_key
                && current != &public_key
            {
                bail!(
                    "peer {url} is already pinned to {current}; remove it before trusting a new identity"
                );
            }
            existing.public_key = Some(public_key);
        }
    } else {
        peers.push(PeerRecord {
            url: url.clone(),
            public_key,
        });
    }
    write_peers(datadir, &peers)?;
    Ok(peers
        .into_iter()
        .find(|peer| peer.url == url)
        .expect("peer was inserted"))
}

pub fn remove_peer(datadir: &Path, value: &str) -> Result<bool> {
    let url = normalize_peer_url(value)?;
    let _lock = lock_config(datadir)?;
    let mut peers = list_peer_records(datadir)?;
    let original_len = peers.len();
    peers.retain(|candidate| candidate.url != url);
    let removed = peers.len() != original_len;
    write_peers(datadir, &peers)?;
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

fn write_peers(datadir: &Path, peers: &[PeerRecord]) -> Result<()> {
    std::fs::create_dir_all(datadir)
        .with_context(|| format!("create data directory {}", datadir.display()))?;
    let mut peers = peers.to_vec();
    peers.sort_by(|left, right| left.url.cmp(&right.url));
    let config = PeerConfig {
        version: 2,
        peers: peers.into_iter().map(StoredPeer::Record).collect(),
    };
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

    fn key(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    #[test]
    fn peers_are_normalized_pinned_and_removed() {
        let datadir = temp_dir();
        add_peer(&datadir, "ws://localhost:4444", None).unwrap();
        let record = add_peer(&datadir, "ws://localhost:4444/sync", Some(&key(1))).unwrap();
        assert_eq!(record.public_key, Some(key(1)));
        assert_eq!(
            list_peers(&datadir).unwrap(),
            vec!["ws://localhost:4444/sync"]
        );
        assert_eq!(
            expected_peer_key(&datadir, "ws://localhost:4444")
                .unwrap()
                .unwrap(),
            key(1)
        );
        assert!(remove_peer(&datadir, "ws://localhost:4444").unwrap());
        assert!(list_peers(&datadir).unwrap().is_empty());
    }

    #[test]
    fn legacy_string_peers_load_as_unpinned() {
        let datadir = temp_dir();
        std::fs::create_dir_all(&datadir).unwrap();
        std::fs::write(
            config_path(&datadir),
            br#"{"version":1,"peers":["ws://localhost:4444/sync"]}"#,
        )
        .unwrap();
        assert_eq!(list_peer_records(&datadir).unwrap().len(), 1);
        assert!(expected_peer_key(&datadir, "ws://localhost:4444").is_err());
    }

    #[test]
    fn pinned_identity_change_requires_remove() {
        let datadir = temp_dir();
        add_peer(&datadir, "ws://localhost:4444", Some(&key(1))).unwrap();
        assert!(add_peer(&datadir, "ws://localhost:4444", Some(&key(2))).is_err());
        assert_eq!(
            expected_peer_key(&datadir, "ws://localhost:4444")
                .unwrap()
                .unwrap(),
            key(1)
        );
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
                    add_peer(&datadir, peer, Some(&key(1))).unwrap();
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
