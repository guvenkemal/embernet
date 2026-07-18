use crate::proto::Envelope;
use crate::util::{channel_to_path, ensure_dir, valid_channel};
use anyhow::{Context, Result, bail};
use fs2::FileExt;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const INDEX: TableDefinition<&str, &[u8]> = TableDefinition::new("messages");
const INDEX_META: TableDefinition<&str, u64> = TableDefinition::new("metadata");
const INDEX_CHUNKS: TableDefinition<u64, &[u8]> = TableDefinition::new("chunk_members");
const INDEX_CHUNK_HASHES: TableDefinition<u64, &[u8]> = TableDefinition::new("chunk_hashes");
const INDEX_LOG_LEN: &str = "log_len";
const INDEX_MESSAGE_COUNT: &str = "message_count";
const INDEX_SCHEMA: &str = "schema";
const INDEX_SCHEMA_VERSION: u64 = 2;
pub const MERKLE_BUCKET_COUNT: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkSummary {
    pub index: u64,
    pub count: u64,
    pub hash: String,
}

#[derive(Debug)]
struct ScannedEnvelope {
    envelope: Envelope,
    offset: u64,
    length: u64,
}

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

    let db = ensure_index(&mut file, &p)?;
    if index_contains(&db, &env.id)? {
        tracing::debug!("append_message: duplicate id {}, skipping", env.id);
        return Ok(env.id.clone());
    }

    file.write_all(&record)
        .with_context(|| format!("append {}", p.display()))?;
    file.flush()
        .with_context(|| format!("flush {}", p.display()))?;
    file.sync_data()
        .with_context(|| format!("sync {}", p.display()))?;
    let offset = file.metadata()?.len() - record.len() as u64;
    index_insert(
        &db,
        &env.id,
        offset,
        record.len() as u64,
        file.metadata()?.len(),
    )?;
    Ok(env.id.clone())
}

fn index_path(log_path: &Path) -> PathBuf {
    log_path.with_file_name("index.redb")
}

fn encode_location(offset: u64, length: u64) -> [u8; 16] {
    let mut value = [0_u8; 16];
    value[..8].copy_from_slice(&offset.to_be_bytes());
    value[8..].copy_from_slice(&length.to_be_bytes());
    value
}

fn decode_location(value: &[u8]) -> Result<(u64, u64)> {
    if value.len() != 16 {
        bail!("invalid index location length {}", value.len());
    }
    let offset = u64::from_be_bytes(value[..8].try_into()?);
    let length = u64::from_be_bytes(value[8..].try_into()?);
    Ok((offset, length))
}

fn ensure_index(log: &mut std::fs::File, log_path: &Path) -> Result<Database> {
    let path = index_path(log_path);
    let log_len = log.metadata()?.len();
    let db = Database::create(&path).with_context(|| format!("open {}", path.display()))?;
    let current = {
        let read = db.begin_read()?;
        match read.open_table(INDEX_META) {
            Ok(table) => (
                table.get(INDEX_LOG_LEN)?.map(|value| value.value()),
                table.get(INDEX_SCHEMA)?.map(|value| value.value()),
            ),
            Err(_) => (None, None),
        }
    };
    if current != (Some(log_len), Some(INDEX_SCHEMA_VERSION)) {
        rebuild_index(&db, log, log_path, log_len)?;
    }
    Ok(db)
}

fn rebuild_index(
    db: &Database,
    log: &mut std::fs::File,
    log_path: &Path,
    log_len: u64,
) -> Result<()> {
    log.seek(SeekFrom::Start(0))?;
    let scanned = scan_verified_file(log, log_path)?;
    let message_count = scanned.len() as u64;
    let ids: Vec<String> = scanned
        .iter()
        .map(|item| item.envelope.id.clone())
        .collect();
    let write = db.begin_write()?;
    let _ = write.delete_table(INDEX);
    let _ = write.delete_table(INDEX_META);
    let _ = write.delete_table(INDEX_CHUNKS);
    let _ = write.delete_table(INDEX_CHUNK_HASHES);
    {
        let mut index = write.open_table(INDEX)?;
        for item in scanned {
            let location = encode_location(item.offset, item.length);
            index.insert(item.envelope.id.as_str(), location.as_slice())?;
        }
    }
    {
        let mut chunks = write.open_table(INDEX_CHUNKS)?;
        let mut hashes = write.open_table(INDEX_CHUNK_HASHES)?;
        let mut buckets = vec![Vec::new(); MERKLE_BUCKET_COUNT];
        for id in ids {
            let bytes = hex::decode(id)?;
            buckets[bytes[0] as usize].push(bytes);
        }
        for (index, mut ids) in buckets.into_iter().enumerate() {
            if ids.is_empty() {
                continue;
            }
            ids.sort();
            let members: Vec<u8> = ids.into_iter().flatten().collect();
            let hash = blake3::hash(&members);
            chunks.insert(index as u64, members.as_slice())?;
            hashes.insert(index as u64, hash.as_bytes().as_slice())?;
        }
    }
    {
        let mut meta = write.open_table(INDEX_META)?;
        meta.insert(INDEX_LOG_LEN, log_len)?;
        meta.insert(INDEX_MESSAGE_COUNT, message_count)?;
        meta.insert(INDEX_SCHEMA, INDEX_SCHEMA_VERSION)?;
    }
    write.commit()?;
    Ok(())
}

fn index_contains(db: &Database, id: &str) -> Result<bool> {
    let read = db.begin_read()?;
    let table = read.open_table(INDEX)?;
    Ok(table.get(id)?.is_some())
}

fn index_insert(db: &Database, id: &str, offset: u64, length: u64, log_len: u64) -> Result<()> {
    let location = encode_location(offset, length);
    let write = db.begin_write()?;
    let message_count = {
        let meta = write.open_table(INDEX_META)?;
        meta.get(INDEX_MESSAGE_COUNT)?
            .map_or(0, |value| value.value())
    };
    let id_bytes = hex::decode(id)?;
    if id_bytes.len() != 32 {
        bail!("invalid message id length in index");
    }
    let chunk_index = id_bytes[0] as u64;
    let mut members = {
        let chunks = write.open_table(INDEX_CHUNKS)?;
        chunks
            .get(chunk_index)?
            .map_or_else(Vec::new, |value| value.value().to_vec())
    };
    members.extend_from_slice(&id_bytes);
    let mut ids: Vec<Vec<u8>> = members.chunks_exact(32).map(<[u8]>::to_vec).collect();
    ids.sort();
    members = ids.into_iter().flatten().collect();
    let chunk_hash = blake3::hash(&members);
    {
        let mut index = write.open_table(INDEX)?;
        index.insert(id, location.as_slice())?;
    }
    {
        let mut chunks = write.open_table(INDEX_CHUNKS)?;
        chunks.insert(chunk_index, members.as_slice())?;
    }
    {
        let mut hashes = write.open_table(INDEX_CHUNK_HASHES)?;
        hashes.insert(chunk_index, chunk_hash.as_bytes().as_slice())?;
    }
    {
        let mut meta = write.open_table(INDEX_META)?;
        meta.insert(INDEX_LOG_LEN, log_len)?;
        meta.insert(INDEX_MESSAGE_COUNT, message_count + 1)?;
        meta.insert(INDEX_SCHEMA, INDEX_SCHEMA_VERSION)?;
    }
    write.commit()?;
    Ok(())
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
    Ok(scan_verified_file(file, path)?
        .into_iter()
        .map(|item| item.envelope)
        .collect())
}

fn scan_verified_file(file: &mut std::fs::File, path: &Path) -> Result<Vec<ScannedEnvelope>> {
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
        let length = read as u64;
        let offset = reader.stream_position()? - length;
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
        envelopes.push(ScannedEnvelope {
            envelope: env,
            offset,
            length,
        });
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
#[cfg(test)]
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
#[cfg(test)]
pub fn read_channel_all(base: &Path, chan: &ChannelRef) -> Result<Vec<Envelope>> {
    read_channel_from(base, chan, 0)
}

/// Return the ordered message-id inventory for a channel.
#[cfg(test)]
pub fn message_ids(base: &Path, chan: &ChannelRef) -> Result<Vec<String>> {
    let log_path = channel_to_path(base, &chan.full_name).join("log.ndjson");
    let mut log = OpenOptions::new().read(true).open(&log_path)?;
    FileExt::lock_exclusive(&log).with_context(|| format!("lock {}", log_path.display()))?;
    let db = ensure_index(&mut log, &log_path)?;
    let read = db.begin_read()?;
    let table = read.open_table(INDEX)?;
    let mut entries = Vec::new();
    for entry in table.iter()? {
        let (id, location) = entry?;
        let (offset, _) = decode_location(location.value())?;
        entries.push((offset, id.value().to_string()));
    }
    entries.sort_by_key(|(offset, _)| *offset);
    Ok(entries.into_iter().map(|(_, id)| id).collect())
}

pub fn chunk_summaries(base: &Path, chan: &ChannelRef) -> Result<Vec<ChunkSummary>> {
    let log_path = channel_to_path(base, &chan.full_name).join("log.ndjson");
    let mut log = OpenOptions::new().read(true).open(&log_path)?;
    FileExt::lock_exclusive(&log).with_context(|| format!("lock {}", log_path.display()))?;
    let db = ensure_index(&mut log, &log_path)?;
    let read = db.begin_read()?;
    let chunks = read.open_table(INDEX_CHUNKS)?;
    let hashes = read.open_table(INDEX_CHUNK_HASHES)?;
    let mut summaries = Vec::new();
    for entry in chunks.iter()? {
        let (index, members) = entry?;
        let index = index.value();
        let members = members.value();
        let hash = hashes
            .get(index)?
            .context("chunk hash missing from index")?;
        summaries.push(ChunkSummary {
            index,
            count: (members.len() / 32) as u64,
            hash: hex::encode(hash.value()),
        });
    }
    Ok(summaries)
}

pub fn chunk_ids(base: &Path, chan: &ChannelRef, chunk_index: u64) -> Result<Vec<String>> {
    let log_path = channel_to_path(base, &chan.full_name).join("log.ndjson");
    let mut log = OpenOptions::new().read(true).open(&log_path)?;
    FileExt::lock_exclusive(&log).with_context(|| format!("lock {}", log_path.display()))?;
    let db = ensure_index(&mut log, &log_path)?;
    let read = db.begin_read()?;
    let chunks = read.open_table(INDEX_CHUNKS)?;
    let Some(members) = chunks.get(chunk_index)? else {
        return Ok(Vec::new());
    };
    if members.value().len() % 32 != 0 {
        bail!("invalid chunk {chunk_index} membership length");
    }
    Ok(members.value().chunks_exact(32).map(hex::encode).collect())
}

/// Read and verify one envelope using its indexed byte range.
pub fn read_message_by_id(base: &Path, chan: &ChannelRef, id: &str) -> Result<Envelope> {
    let log_path = channel_to_path(base, &chan.full_name).join("log.ndjson");
    let mut log = OpenOptions::new().read(true).open(&log_path)?;
    FileExt::lock_exclusive(&log).with_context(|| format!("lock {}", log_path.display()))?;
    let db = ensure_index(&mut log, &log_path)?;
    let location = {
        let read = db.begin_read()?;
        let table = read.open_table(INDEX)?;
        let value = table
            .get(id)?
            .with_context(|| format!("message {id} is not indexed"))?;
        decode_location(value.value())?
    };
    let (offset, length) = location;
    log.seek(SeekFrom::Start(offset))?;
    let mut record = vec![0_u8; length as usize];
    log.read_exact(&mut record)?;
    if record.pop() != Some(b'\n') {
        bail!("corrupt indexed record {id}: missing newline");
    }
    let env: Envelope = serde_json::from_slice(&record)
        .with_context(|| format!("corrupt indexed record {id}: invalid JSON"))?;
    if env.id != id || env.channel != chan.full_name {
        bail!("corrupt indexed record {id}: identity or channel mismatch");
    }
    env.verify()
        .with_context(|| format!("corrupt indexed record {id}: failed verification"))?;
    Ok(env)
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
    fn missing_index_is_rebuilt_from_existing_log() {
        let base = temp_dir();
        init_layout(&base).unwrap();
        let chan = ChannelRef::parse("test/index").unwrap();
        create_channel(&base, &chan).unwrap();
        let env = Envelope::sign(
            KeypairFile::generate(Some("tester".into())),
            &chan.full_name,
            Message::new_text(None, vec![], "pre-index".into(), vec![]),
        )
        .unwrap();
        let log_path = channel_to_path(&base, &chan.full_name).join("log.ndjson");
        let mut record = serde_json::to_vec(&env).unwrap();
        record.push(b'\n');
        std::fs::write(&log_path, record).unwrap();

        assert_eq!(message_ids(&base, &chan).unwrap(), vec![env.id.clone()]);
        assert!(index_path(&log_path).exists());
        assert_eq!(
            read_message_by_id(&base, &chan, &env.id).unwrap().id,
            env.id
        );
    }

    #[test]
    fn stale_index_is_rebuilt_after_unindexed_log_append() {
        let base = temp_dir();
        init_layout(&base).unwrap();
        let chan = ChannelRef::parse("test/index").unwrap();
        create_channel(&base, &chan).unwrap();
        let key = KeypairFile::generate(Some("tester".into()));
        let first = Envelope::sign(
            key.clone(),
            &chan.full_name,
            Message::new_text(None, vec![], "first".into(), vec![]),
        )
        .unwrap();
        let second = Envelope::sign(
            key,
            &chan.full_name,
            Message::new_text(None, vec![], "second".into(), vec![]),
        )
        .unwrap();
        append_message(&base, &chan, &first).unwrap();
        let log_path = channel_to_path(&base, &chan.full_name).join("log.ndjson");
        let mut record = serde_json::to_vec(&second).unwrap();
        record.push(b'\n');
        OpenOptions::new()
            .append(true)
            .open(&log_path)
            .unwrap()
            .write_all(&record)
            .unwrap();

        assert_eq!(
            message_ids(&base, &chan).unwrap(),
            vec![first.id, second.id]
        );
    }

    #[test]
    fn chunk_hashes_ignore_arrival_order() {
        let first_base = temp_dir();
        let second_base = temp_dir();
        let chan = ChannelRef::parse("test/chunks").unwrap();
        for base in [&first_base, &second_base] {
            init_layout(base).unwrap();
            create_channel(base, &chan).unwrap();
        }
        let key = KeypairFile::generate(Some("tester".into()));
        let first = Envelope::sign(
            key.clone(),
            &chan.full_name,
            Message::new_text(None, vec![], "first".into(), vec![]),
        )
        .unwrap();
        let second = Envelope::sign(
            key,
            &chan.full_name,
            Message::new_text(None, vec![], "second".into(), vec![]),
        )
        .unwrap();
        append_message(&first_base, &chan, &first).unwrap();
        append_message(&first_base, &chan, &second).unwrap();
        append_message(&second_base, &chan, &second).unwrap();
        append_message(&second_base, &chan, &first).unwrap();

        assert_eq!(
            chunk_summaries(&first_base, &chan).unwrap(),
            chunk_summaries(&second_base, &chan).unwrap()
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
