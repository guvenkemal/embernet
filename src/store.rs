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
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p)
        .with_context(|| format!("open {}", p.display()))?;
    serde_json::to_writer(&mut f, &env)?;
    f.write_all(b"\n")?;
    Ok(env.id.clone())
}

pub fn read_channel_tail(base: &Path, chan: &ChannelRef, n: usize) -> Result<Vec<Envelope>> {
    let p = channel_to_path(base, &chan.full_name).join("log.ndjson");
    let file = OpenOptions::new().read(true).open(&p)?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();
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
pub fn count_messages(base: &Path, chan: &ChannelRef) -> Result<u64> {
    let p = channel_to_path(base, &chan.full_name).join("log.ndjson");
    if !p.exists() {
        return Ok(0);
    }
    let file = OpenOptions::new().read(true).open(&p)?;
    let reader = BufReader::new(file);
    let count = reader
        .lines()
        .filter_map(|l| l.ok())
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
        .filter_map(|l| l.ok())
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
