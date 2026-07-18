use crate::proto::Envelope;
use crate::util::{channel_to_path, ensure_dir, valid_channel};
use anyhow::{Context, Result, bail};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ChannelRef {
    pub full_name: String,
}

impl ChannelRef {
    pub fn parse(name: &str) -> Result<Self> {
        if !valid_channel(name) {
            bail!("invalid channel name");
        }
        Ok(Self {
            full_name: name.to_string(),
        })
    }
}

pub fn init_layout(base: &Path) -> Result<()> {
    ensure_dir(base)?;
    ensure_dir(&base.join("keys"))?;
    ensure_dir(&base.join("channels"))?;
    Ok(())
}

pub fn create_channel(base: &Path, chan: &ChannelRef) -> Result<()> {
    let p = channel_to_path(base, &chan.full_name);
    ensure_dir(&p)?;
    std::fs::write(p.join("log.ndjson"), b"")?;
    Ok(())
}

pub fn append_message(base: &Path, chan: &ChannelRef, env: &Envelope) -> Result<String> {
    let p = channel_to_path(base, &chan.full_name).join("log.ndjson");

    // Dedup: skip if this id already exists in the log.
    if p.exists() && log_contains_id(&p, &env.id)? {
        tracing::debug!("append_message: duplicate id {}, skipping", env.id);
        return Ok(env.id.clone());
    }

    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p)
        .with_context(|| format!("open {}", p.display()))?;
    serde_json::to_writer(&mut f, &env)?;
    f.write_all(b"\n")?;
    Ok(env.id.clone())
}

/// Check whether a log file already contains a line with the given id.
///
/// The id is a 64-char hex string (blake3 output). We scan each line
/// for the id substring — false positives are astronomically unlikely
/// and this avoids deserializing every envelope.
fn log_contains_id(path: &Path, id: &str) -> Result<bool> {
    let file = OpenOptions::new().read(true).open(path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        if line.contains(id) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn read_channel_tail(base: &Path, chan: &ChannelRef, n: usize) -> Result<Vec<Envelope>> {
    let p = channel_to_path(base, &chan.full_name).join("log.ndjson");
    let file = OpenOptions::new().read(true).open(&p)?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();
    let start = lines.len().saturating_sub(n);

    let mut out = Vec::new();
    for ln in &lines[start..] {
        if ln.trim().is_empty() {
            continue;
        }
        let env: Envelope = serde_json::from_str(ln)?;
        // hard fail if signature doesn't verify
        env.verify()
            .map_err(|e| anyhow::anyhow!("bad sig for {}: {}", env.id, e))?;
        out.push(env);
    }
    Ok(out)
}

/// Count total messages (non-empty lines) in a channel log.
#[cfg(test)]
pub fn count_messages(base: &Path, chan: &ChannelRef) -> Result<u64> {
    let p = channel_to_path(base, &chan.full_name).join("log.ndjson");
    if !p.exists() {
        return Ok(0);
    }
    let file = OpenOptions::new().read(true).open(&p)?;
    let reader = BufReader::new(file);
    let count = reader
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .count() as u64;
    Ok(count)
}

/// Read envelopes starting from `from` (0-indexed) to end of log.
/// Each envelope is verified before being returned.
pub fn read_channel_from(base: &Path, chan: &ChannelRef, from: u64) -> Result<Vec<Envelope>> {
    let p = channel_to_path(base, &chan.full_name).join("log.ndjson");
    let file = OpenOptions::new().read(true).open(&p)?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .collect();

    let from = from as usize;
    if from >= lines.len() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    for ln in &lines[from..] {
        let env: Envelope = serde_json::from_str(ln)?;
        env.verify()
            .map_err(|e| anyhow::anyhow!("bad sig for {}: {}", env.id, e))?;
        out.push(env);
    }
    Ok(out)
}

/// Read and verify every envelope in a channel.
pub fn read_channel_all(base: &Path, chan: &ChannelRef) -> Result<Vec<Envelope>> {
    read_channel_from(base, chan, 0)
}

/// Return the ordered message-id inventory for a channel.
#[cfg(test)]
pub fn message_ids(base: &Path, chan: &ChannelRef) -> Result<Vec<String>> {
    Ok(read_channel_all(base, chan)?
        .into_iter()
        .map(|env| env.id)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{Envelope, KeypairFile, Message};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("embernet_test_{n}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn append_then_count() {
        let base = temp_dir();
        init_layout(&base).unwrap();

        let chan = ChannelRef::parse("test/chan").unwrap();
        create_channel(&base, &chan).unwrap();

        let kp = KeypairFile::generate(Some("tester".into()));
        let msg = Message::new_text(None, vec![], "hello".into(), vec![]);
        let env = Envelope::sign(kp, &chan.full_name, msg).unwrap();

        let id = append_message(&base, &chan, &env).unwrap();
        assert_eq!(id, env.id);
        assert_eq!(count_messages(&base, &chan).unwrap(), 1);
    }

    #[test]
    fn append_dedup_same_id() {
        let base = temp_dir();
        init_layout(&base).unwrap();

        let chan = ChannelRef::parse("test/chan").unwrap();
        create_channel(&base, &chan).unwrap();

        let kp = KeypairFile::generate(Some("tester".into()));
        let msg = Message::new_text(None, vec![], "hello".into(), vec![]);
        let env = Envelope::sign(kp, &chan.full_name, msg).unwrap();

        // First append: succeeds, count = 1.
        let id1 = append_message(&base, &chan, &env).unwrap();
        assert_eq!(id1, env.id);
        assert_eq!(count_messages(&base, &chan).unwrap(), 1);

        // Second append with same envelope: returns same id, count still 1.
        let id2 = append_message(&base, &chan, &env).unwrap();
        assert_eq!(id2, env.id);
        assert_eq!(count_messages(&base, &chan).unwrap(), 1);
    }

    #[test]
    fn append_dedup_different_ids() {
        let base = temp_dir();
        init_layout(&base).unwrap();

        let chan = ChannelRef::parse("test/chan").unwrap();
        create_channel(&base, &chan).unwrap();

        let kp = KeypairFile::generate(Some("tester".into()));

        let msg1 = Message::new_text(None, vec![], "first".into(), vec![]);
        let env1 = Envelope::sign(kp.clone(), &chan.full_name, msg1).unwrap();
        append_message(&base, &chan, &env1).unwrap();

        let msg2 = Message::new_text(None, vec![], "second".into(), vec![]);
        let env2 = Envelope::sign(kp, &chan.full_name, msg2).unwrap();
        append_message(&base, &chan, &env2).unwrap();

        // Two different messages, count = 2.
        assert_eq!(count_messages(&base, &chan).unwrap(), 2);
        // ids must differ.
        assert_ne!(env1.id, env2.id);
    }

    #[test]
    fn message_ids_preserve_log_order() {
        let base = temp_dir();
        init_layout(&base).unwrap();
        let chan = ChannelRef::parse("test/chan").unwrap();
        create_channel(&base, &chan).unwrap();
        let kp = KeypairFile::generate(Some("tester".into()));
        let first = Envelope::sign(
            kp.clone(),
            &chan.full_name,
            Message::new_text(None, vec![], "first".into(), vec![]),
        )
        .unwrap();
        let second = Envelope::sign(
            kp,
            &chan.full_name,
            Message::new_text(None, vec![], "second".into(), vec![]),
        )
        .unwrap();
        append_message(&base, &chan, &first).unwrap();
        append_message(&base, &chan, &second).unwrap();

        assert_eq!(
            message_ids(&base, &chan).unwrap(),
            vec![first.id, second.id]
        );
    }
}
