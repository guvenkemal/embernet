use crate::proto::Envelope;
use crate::util::{channel_to_path, ensure_dir, valid_channel};
use anyhow::{Context, Result, bail};
use fs2::FileExt;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
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
    let log = p.join("log.ndjson");
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .with_context(|| format!("create {}", log.display()))?;
    Ok(())
}

pub fn append_message(base: &Path, chan: &ChannelRef, env: &Envelope) -> Result<String> {
    let p = channel_to_path(base, &chan.full_name).join("log.ndjson");
    if env.channel != chan.full_name {
        bail!(
            "envelope {} belongs to {}, not {}",
            env.id,
            env.channel,
            chan.full_name
        );
    }
    env.verify()
        .with_context(|| format!("refusing to append invalid envelope {}", env.id))?;
    let mut record = serde_json::to_vec(env).context("serialize envelope")?;
    record.push(b'\n');

    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(&p)
        .with_context(|| format!("open {}", p.display()))?;
    FileExt::lock_exclusive(&file).with_context(|| format!("lock {}", p.display()))?;

    file.seek(SeekFrom::Start(0))?;
    let existing = read_verified_file(&mut file, &p)?;
    if existing.iter().any(|existing| existing.id == env.id) {
        tracing::debug!("append_message: duplicate id {}, skipping", env.id);
        return Ok(env.id.clone());
    }

    file.write_all(&record)
        .with_context(|| format!("append {}", p.display()))?;
    file.flush()
        .with_context(|| format!("flush {}", p.display()))?;
    file.sync_data()
        .with_context(|| format!("sync {}", p.display()))?;
    Ok(env.id.clone())
}

fn read_verified_log(path: &Path) -> Result<Vec<Envelope>> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    FileExt::lock_shared(&file).with_context(|| format!("lock {}", path.display()))?;
    read_verified_file(&mut file, path)
}

fn read_verified_file(file: &mut std::fs::File, path: &Path) -> Result<Vec<Envelope>> {
    let mut reader = BufReader::new(file);
    let mut envelopes = Vec::new();
    let mut bytes = Vec::new();
    let mut line_number = 0_usize;

    loop {
        bytes.clear();
        let read = reader
            .read_until(b'\n', &mut bytes)
            .with_context(|| format!("read {} at line {}", path.display(), line_number + 1))?;
        if read == 0 {
            break;
        }
        line_number += 1;
        if !bytes.ends_with(b"\n") {
            bail!(
                "corrupt log {} at line {}: truncated record (missing newline)",
                path.display(),
                line_number
            );
        }
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        if bytes.iter().all(u8::is_ascii_whitespace) {
            continue;
        }

        let env: Envelope = serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "corrupt log {} at line {}: invalid envelope JSON",
                path.display(),
                line_number
            )
        })?;
        env.verify().with_context(|| {
            format!(
                "corrupt log {} at line {}: envelope {} failed verification",
                path.display(),
                line_number,
                env.id
            )
        })?;
        envelopes.push(env);
    }
    Ok(envelopes)
}

pub fn read_channel_tail(base: &Path, chan: &ChannelRef, n: usize) -> Result<Vec<Envelope>> {
    let p = channel_to_path(base, &chan.full_name).join("log.ndjson");
    let envelopes = read_verified_log(&p)?;
    let start = envelopes.len().saturating_sub(n);
    Ok(envelopes[start..].to_vec())
}

/// Count total messages (non-empty lines) in a channel log.
#[cfg(test)]
pub fn count_messages(base: &Path, chan: &ChannelRef) -> Result<u64> {
    let p = channel_to_path(base, &chan.full_name).join("log.ndjson");
    if !p.exists() {
        return Ok(0);
    }
    Ok(read_verified_log(&p)?.len() as u64)
}

/// Read envelopes starting from `from` (0-indexed) to end of log.
/// Each envelope is verified before being returned.
pub fn read_channel_from(base: &Path, chan: &ChannelRef, from: u64) -> Result<Vec<Envelope>> {
    let p = channel_to_path(base, &chan.full_name).join("log.ndjson");
    let envelopes = read_verified_log(&p)?;
    let from = from as usize;
    if from >= envelopes.len() {
        return Ok(Vec::new());
    }
    Ok(envelopes[from..].to_vec())
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
    use std::sync::{Arc, Barrier};

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

    #[test]
    fn create_channel_preserves_existing_log() {
        let base = temp_dir();
        init_layout(&base).unwrap();
        let chan = ChannelRef::parse("test/chan").unwrap();
        create_channel(&base, &chan).unwrap();
        let env = Envelope::sign(
            KeypairFile::generate(Some("tester".into())),
            &chan.full_name,
            Message::new_text(None, vec![], "keep me".into(), vec![]),
        )
        .unwrap();
        append_message(&base, &chan, &env).unwrap();

        create_channel(&base, &chan).unwrap();

        assert_eq!(message_ids(&base, &chan).unwrap(), vec![env.id]);
    }

    #[test]
    fn concurrent_duplicate_appends_write_one_record() {
        let base = temp_dir();
        init_layout(&base).unwrap();
        let chan = ChannelRef::parse("test/concurrent").unwrap();
        create_channel(&base, &chan).unwrap();
        let env = Arc::new(
            Envelope::sign(
                KeypairFile::generate(Some("tester".into())),
                &chan.full_name,
                Message::new_text(None, vec![], "same message".into(), vec![]),
            )
            .unwrap(),
        );
        let barrier = Arc::new(Barrier::new(16));
        let mut threads = Vec::new();
        for _ in 0..16 {
            let base = base.clone();
            let chan = chan.clone();
            let env = Arc::clone(&env);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                append_message(&base, &chan, &env).unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }

        assert_eq!(count_messages(&base, &chan).unwrap(), 1);
    }

    #[test]
    fn concurrent_distinct_appends_remain_valid() {
        let base = temp_dir();
        init_layout(&base).unwrap();
        let chan = ChannelRef::parse("test/concurrent").unwrap();
        create_channel(&base, &chan).unwrap();
        let barrier = Arc::new(Barrier::new(16));
        let mut threads = Vec::new();
        for n in 0..16 {
            let base = base.clone();
            let chan = chan.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                let env = Envelope::sign(
                    KeypairFile::generate(Some(format!("tester-{n}"))),
                    &chan.full_name,
                    Message::new_text(None, vec![], format!("message {n}"), vec![]),
                )
                .unwrap();
                barrier.wait();
                append_message(&base, &chan, &env).unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }

        let ids = message_ids(&base, &chan).unwrap();
        assert_eq!(ids.len(), 16);
        assert_eq!(
            ids.iter().collect::<std::collections::HashSet<_>>().len(),
            16
        );
    }

    #[test]
    fn truncated_record_reports_file_and_line() {
        let base = temp_dir();
        init_layout(&base).unwrap();
        let chan = ChannelRef::parse("test/corrupt").unwrap();
        create_channel(&base, &chan).unwrap();
        let path = channel_to_path(&base, &chan.full_name).join("log.ndjson");
        std::fs::write(&path, br#"{"id":"unfinished"}"#).unwrap();

        let error = read_channel_all(&base, &chan).unwrap_err().to_string();
        assert!(error.contains(&path.display().to_string()));
        assert!(error.contains("line 1"));
        assert!(error.contains("truncated record"));
    }

    #[test]
    fn invalid_record_reports_file_and_line() {
        let base = temp_dir();
        init_layout(&base).unwrap();
        let chan = ChannelRef::parse("test/corrupt").unwrap();
        create_channel(&base, &chan).unwrap();
        let path = channel_to_path(&base, &chan.full_name).join("log.ndjson");
        std::fs::write(&path, b"not-json\n").unwrap();

        let error = read_channel_all(&base, &chan).unwrap_err().to_string();
        assert!(error.contains(&path.display().to_string()));
        assert!(error.contains("line 1"));
        assert!(error.contains("invalid envelope JSON"));
    }

    #[test]
    fn unverifiable_record_reports_file_and_line() {
        let base = temp_dir();
        init_layout(&base).unwrap();
        let chan = ChannelRef::parse("test/corrupt").unwrap();
        create_channel(&base, &chan).unwrap();
        let path = channel_to_path(&base, &chan.full_name).join("log.ndjson");
        let mut env = Envelope::sign(
            KeypairFile::generate(Some("tester".into())),
            &chan.full_name,
            Message::new_text(None, vec![], "original".into(), vec![]),
        )
        .unwrap();
        env.sig = "00".repeat(64);
        let mut record = serde_json::to_vec(&env).unwrap();
        record.push(b'\n');
        std::fs::write(&path, record).unwrap();

        let error = read_channel_all(&base, &chan).unwrap_err().to_string();
        assert!(error.contains(&path.display().to_string()));
        assert!(error.contains("line 1"));
        assert!(error.contains("failed verification"));
    }
}
