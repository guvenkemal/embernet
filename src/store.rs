use crate::proto::{Envelope, KeypairFile, verify_bytes};
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    Open,
    Restricted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelPolicy {
    pub version: u32,
    pub mode: PolicyMode,
    pub owner: Option<String>,
    pub moderators: Vec<String>,
    pub writers: Vec<String>,
}

impl Default for ChannelPolicy {
    fn default() -> Self {
        Self {
            version: 1,
            mode: PolicyMode::Open,
            owner: None,
            moderators: Vec::new(),
            writers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRole {
    Moderator,
    Writer,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyAction {
    Restrict {
        owner: String,
    },
    Adopt {
        policy: ChannelPolicy,
    },
    Grant {
        role: PolicyRole,
        public_key: String,
    },
    Revoke {
        role: PolicyRole,
        public_key: String,
    },
    TransferOwner {
        new_owner: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyEvent {
    pub id: String,
    pub channel: String,
    pub actor: String,
    pub ts: i64,
    pub previous: Option<String>,
    pub action: PolicyAction,
    pub sig: String,
}

#[derive(Serialize)]
struct PolicyEventPayload<'a> {
    channel: &'a str,
    actor: &'a str,
    ts: i64,
    previous: &'a Option<String>,
    action: &'a PolicyAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ModerationAction {
    Tombstone {
        target: String,
        reason: Option<String>,
    },
    Restore {
        target: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModerationEvent {
    pub id: String,
    pub channel: String,
    pub actor: String,
    pub ts: i64,
    pub previous: Option<String>,
    pub policy_head: String,
    pub action: ModerationAction,
    pub sig: String,
}

#[derive(Serialize)]
struct ModerationEventPayload<'a> {
    channel: &'a str,
    actor: &'a str,
    ts: i64,
    previous: &'a Option<String>,
    policy_head: &'a str,
    action: &'a ModerationAction,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModerationState {
    pub tombstoned: std::collections::BTreeMap<String, Option<String>>,
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

    authorize_append(base, chan, &env.from)?;

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

fn policy_path(base: &Path, chan: &ChannelRef) -> PathBuf {
    channel_to_path(base, &chan.full_name).join("policy.json")
}

fn validate_public_key(key: &str) -> Result<()> {
    let bytes = hex::decode(key).context("public key must be hexadecimal")?;
    if bytes.len() != 32 {
        bail!("public key must encode 32 bytes");
    }
    Ok(())
}

pub fn read_channel_policy(base: &Path, chan: &ChannelRef) -> Result<ChannelPolicy> {
    if policy_log_path(base, chan).exists() {
        return derive_policy(chan, &read_policy_history(base, chan)?);
    }
    let path = policy_path(base, chan);
    if !path.exists() {
        return Ok(ChannelPolicy::default());
    }
    let policy: ChannelPolicy = serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("invalid channel policy {}", path.display()))?;
    if policy.version != 1 {
        bail!("unsupported channel policy version {}", policy.version);
    }
    if policy.mode == PolicyMode::Restricted && policy.owner.is_none() {
        bail!("restricted channel policy has no owner");
    }
    if let Some(owner) = &policy.owner {
        validate_public_key(owner)?;
    }
    for key in policy.moderators.iter().chain(&policy.writers) {
        validate_public_key(key)?;
    }
    Ok(policy)
}

fn authorize_append(base: &Path, chan: &ChannelRef, author: &str) -> Result<()> {
    let policy = read_channel_policy(base, chan)?;
    if policy.mode == PolicyMode::Open
        || policy.owner.as_deref() == Some(author)
        || policy.moderators.iter().any(|key| key == author)
        || policy.writers.iter().any(|key| key == author)
    {
        return Ok(());
    }
    bail!(
        "author {} is not allowed to write channel {}",
        author,
        chan.full_name
    )
}

pub fn restrict_channel(
    base: &Path,
    chan: &ChannelRef,
    signer: &KeypairFile,
) -> Result<ChannelPolicy> {
    append_policy_action(
        base,
        chan,
        signer,
        PolicyAction::Restrict {
            owner: signer.public_key.clone(),
        },
    )
}

pub fn grant_role(
    base: &Path,
    chan: &ChannelRef,
    signer: &KeypairFile,
    role: PolicyRole,
    public_key: &str,
) -> Result<ChannelPolicy> {
    append_policy_action(
        base,
        chan,
        signer,
        PolicyAction::Grant {
            role,
            public_key: public_key.to_string(),
        },
    )
}

pub fn revoke_role(
    base: &Path,
    chan: &ChannelRef,
    signer: &KeypairFile,
    role: PolicyRole,
    public_key: &str,
) -> Result<ChannelPolicy> {
    append_policy_action(
        base,
        chan,
        signer,
        PolicyAction::Revoke {
            role,
            public_key: public_key.to_string(),
        },
    )
}

pub fn transfer_ownership(
    base: &Path,
    chan: &ChannelRef,
    signer: &KeypairFile,
    new_owner: &str,
) -> Result<ChannelPolicy> {
    append_policy_action(
        base,
        chan,
        signer,
        PolicyAction::TransferOwner {
            new_owner: new_owner.to_string(),
        },
    )
}

fn authorize_policy_change(policy: &ChannelPolicy, actor: &str, role: PolicyRole) -> Result<()> {
    if policy.mode != PolicyMode::Restricted {
        bail!("channel must be restricted before roles can be changed");
    }
    let owner = policy.owner.as_deref() == Some(actor);
    let moderator = policy.moderators.iter().any(|key| key == actor);
    match role {
        PolicyRole::Moderator if !owner => bail!("only the owner can manage moderators"),
        PolicyRole::Writer if !owner && !moderator => {
            bail!("only the owner or a moderator can manage writers")
        }
        _ => Ok(()),
    }
}

fn policy_log_path(base: &Path, chan: &ChannelRef) -> PathBuf {
    channel_to_path(base, &chan.full_name).join("policy.ndjson")
}

pub fn read_policy_history(base: &Path, chan: &ChannelRef) -> Result<Vec<PolicyEvent>> {
    let path = policy_log_path(base, chan);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let reader = BufReader::new(std::fs::File::open(&path)?);
    let mut events = Vec::new();
    for (line_index, line) in reader.lines().enumerate() {
        let line =
            line.with_context(|| format!("read {} line {}", path.display(), line_index + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        events.push(serde_json::from_str(&line).with_context(|| {
            format!(
                "invalid policy event {} line {}",
                path.display(),
                line_index + 1
            )
        })?);
    }
    derive_policy(chan, &events)?;
    Ok(events)
}

fn append_policy_action(
    base: &Path,
    chan: &ChannelRef,
    signer: &KeypairFile,
    action: PolicyAction,
) -> Result<ChannelPolicy> {
    let channel_dir = channel_to_path(base, &chan.full_name);
    let log_path = channel_dir.join("log.ndjson");
    let log = OpenOptions::new().read(true).open(&log_path)?;
    FileExt::lock_exclusive(&log).with_context(|| format!("lock {}", log_path.display()))?;
    let mut events = read_policy_history(base, chan)?;
    let first_new_event = events.len();
    let cached = read_channel_policy(base, chan)?;
    if events.is_empty() && cached.mode == PolicyMode::Restricted {
        if cached.owner.as_deref() != Some(&signer.public_key) {
            bail!("only the legacy policy owner can adopt it into signed history");
        }
        events.push(sign_policy_event(
            chan,
            signer,
            None,
            PolicyAction::Adopt { policy: cached },
        )?);
    }
    let previous = events.last().map(|event| event.id.clone());
    events.push(sign_policy_event(chan, signer, previous, action)?);
    let policy = derive_policy(chan, &events)?;
    let history_path = policy_log_path(base, chan);
    let mut history = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&history_path)?;
    for event in &events[first_new_event..] {
        serde_json::to_writer(&mut history, event)?;
        history.write_all(b"\n")?;
    }
    history.flush()?;
    history.sync_data()?;
    let path = policy_path(base, chan);
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, serde_json::to_vec_pretty(&policy)?)?;
    std::fs::rename(&temp, &path)?;
    Ok(policy)
}

fn sign_policy_event(
    chan: &ChannelRef,
    signer: &KeypairFile,
    previous: Option<String>,
    action: PolicyAction,
) -> Result<PolicyEvent> {
    let ts = chrono::Utc::now().timestamp();
    let payload = serde_json::to_vec(&PolicyEventPayload {
        channel: &chan.full_name,
        actor: &signer.public_key,
        ts,
        previous: &previous,
        action: &action,
    })?;
    let id = hex::encode(blake3::hash(&payload).as_bytes());
    let mut signed = b"embernet-policy-v1\n".to_vec();
    signed.extend_from_slice(&payload);
    Ok(PolicyEvent {
        id,
        channel: chan.full_name.clone(),
        actor: signer.public_key.clone(),
        ts,
        previous,
        action,
        sig: signer.sign_bytes(&signed)?,
    })
}

fn derive_policy(chan: &ChannelRef, events: &[PolicyEvent]) -> Result<ChannelPolicy> {
    let mut policy = ChannelPolicy::default();
    let mut previous: Option<String> = None;
    for event in events {
        if event.channel != chan.full_name || event.previous != previous {
            bail!("invalid policy event chain at {}", event.id);
        }
        let payload = serde_json::to_vec(&PolicyEventPayload {
            channel: &event.channel,
            actor: &event.actor,
            ts: event.ts,
            previous: &event.previous,
            action: &event.action,
        })?;
        if event.id != hex::encode(blake3::hash(&payload).as_bytes()) {
            bail!("policy event {} has an invalid id", event.id);
        }
        let mut signed = b"embernet-policy-v1\n".to_vec();
        signed.extend_from_slice(&payload);
        verify_bytes(&event.actor, &event.sig, &signed)
            .with_context(|| format!("verify policy event {}", event.id))?;
        apply_policy_action(&mut policy, &event.actor, &event.action)?;
        previous = Some(event.id.clone());
    }
    Ok(policy)
}

fn apply_policy_action(
    policy: &mut ChannelPolicy,
    actor: &str,
    action: &PolicyAction,
) -> Result<()> {
    match action {
        PolicyAction::Restrict { owner } => {
            if policy.mode != PolicyMode::Open || owner != actor {
                bail!("invalid restrict policy event");
            }
            validate_public_key(owner)?;
            policy.mode = PolicyMode::Restricted;
            policy.owner = Some(owner.clone());
        }
        PolicyAction::Adopt { policy: adopted } => {
            if policy.mode != PolicyMode::Open
                || adopted.mode != PolicyMode::Restricted
                || adopted.owner.as_deref() != Some(actor)
            {
                bail!("invalid legacy policy adoption");
            }
            *policy = adopted.clone();
        }
        PolicyAction::Grant { role, public_key } => {
            validate_public_key(public_key)?;
            authorize_policy_change(policy, actor, *role)?;
            let members = match role {
                PolicyRole::Moderator => &mut policy.moderators,
                PolicyRole::Writer => &mut policy.writers,
            };
            if !members.contains(public_key) {
                members.push(public_key.clone());
                members.sort();
            }
        }
        PolicyAction::Revoke { role, public_key } => {
            authorize_policy_change(policy, actor, *role)?;
            let members = match role {
                PolicyRole::Moderator => &mut policy.moderators,
                PolicyRole::Writer => &mut policy.writers,
            };
            members.retain(|key| key != public_key);
        }
        PolicyAction::TransferOwner { new_owner } => {
            validate_public_key(new_owner)?;
            if policy.owner.as_deref() != Some(actor) {
                bail!("only the owner can transfer ownership");
            }
            policy.owner = Some(new_owner.clone());
            policy.moderators.retain(|key| key != new_owner);
            policy.writers.retain(|key| key != new_owner);
        }
    }
    Ok(())
}

pub fn rebuild_policy_cache(base: &Path, chan: &ChannelRef) -> Result<ChannelPolicy> {
    let policy = derive_policy(chan, &read_policy_history(base, chan)?)?;
    let path = policy_path(base, chan);
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, serde_json::to_vec_pretty(&policy)?)?;
    std::fs::rename(temp, path)?;
    Ok(policy)
}

pub fn validate_policy_history(chan: &ChannelRef, events: &[PolicyEvent]) -> Result<ChannelPolicy> {
    derive_policy(chan, events)
}

pub fn append_remote_policy_history(
    base: &Path,
    chan: &ChannelRef,
    remote: &[PolicyEvent],
) -> Result<ChannelPolicy> {
    let channel_dir = channel_to_path(base, &chan.full_name);
    let log_path = channel_dir.join("log.ndjson");
    let log = OpenOptions::new().read(true).open(&log_path)?;
    FileExt::lock_exclusive(&log).with_context(|| format!("lock {}", log_path.display()))?;
    let local = read_policy_history(base, chan)?;
    validate_policy_history(chan, remote)?;
    if local.len() > remote.len()
        || !local
            .iter()
            .zip(remote)
            .all(|(left, right)| left.id == right.id)
    {
        bail!("remote policy history does not extend the local history");
    }
    if remote.len() > local.len() {
        let path = policy_log_path(base, chan);
        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
        for event in &remote[local.len()..] {
            serde_json::to_writer(&mut file, event)?;
            file.write_all(b"\n")?;
        }
        file.flush()?;
        file.sync_data()?;
    }
    let policy = derive_policy(chan, remote)?;
    write_policy_cache(base, chan, &policy)?;
    Ok(policy)
}

fn policy_conflict_dir(base: &Path, chan: &ChannelRef) -> PathBuf {
    channel_to_path(base, &chan.full_name).join("policy-conflicts")
}

pub fn save_policy_conflict(
    base: &Path,
    chan: &ChannelRef,
    events: &[PolicyEvent],
) -> Result<String> {
    validate_policy_history(chan, events)?;
    let head = events
        .last()
        .context("cannot save an empty policy conflict")?
        .id
        .clone();
    let dir = policy_conflict_dir(base, chan);
    ensure_dir(&dir)?;
    let path = dir.join(format!("{head}.ndjson"));
    let mut bytes = Vec::new();
    for event in events {
        serde_json::to_writer(&mut bytes, event)?;
        bytes.push(b'\n');
    }
    std::fs::write(path, bytes)?;
    Ok(head)
}

pub fn list_policy_conflicts(base: &Path, chan: &ChannelRef) -> Result<Vec<String>> {
    let dir = policy_conflict_dir(base, chan);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut heads = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && let Some(name) = entry.path().file_stem().and_then(|name| name.to_str())
        {
            heads.push(name.to_string());
        }
    }
    heads.sort();
    Ok(heads)
}

pub fn resolve_policy_conflict(
    base: &Path,
    chan: &ChannelRef,
    head: &str,
) -> Result<ChannelPolicy> {
    validate_public_key(head).context("policy head must be a 32-byte hex ID")?;
    let path = policy_conflict_dir(base, chan).join(format!("{head}.ndjson"));
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let events: Vec<PolicyEvent> = String::from_utf8(bytes)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    if events.last().map(|event| event.id.as_str()) != Some(head) {
        bail!("saved policy conflict does not match requested head");
    }
    let policy = validate_policy_history(chan, &events)?;
    let log_path = channel_to_path(base, &chan.full_name).join("log.ndjson");
    let log = OpenOptions::new().read(true).open(&log_path)?;
    FileExt::lock_exclusive(&log).with_context(|| format!("lock {}", log_path.display()))?;
    let history_path = policy_log_path(base, chan);
    let temp = history_path.with_extension("ndjson.tmp");
    let mut data = Vec::new();
    for event in &events {
        serde_json::to_writer(&mut data, event)?;
        data.push(b'\n');
    }
    std::fs::write(&temp, data)?;
    std::fs::rename(temp, history_path)?;
    write_policy_cache(base, chan, &policy)?;
    Ok(policy)
}

fn write_policy_cache(base: &Path, chan: &ChannelRef, policy: &ChannelPolicy) -> Result<()> {
    let path = policy_path(base, chan);
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, serde_json::to_vec_pretty(policy)?)?;
    std::fs::rename(temp, path)?;
    Ok(())
}

fn moderation_log_path(base: &Path, chan: &ChannelRef) -> PathBuf {
    channel_to_path(base, &chan.full_name).join("moderation.ndjson")
}

fn moderation_cache_path(base: &Path, chan: &ChannelRef) -> PathBuf {
    channel_to_path(base, &chan.full_name).join("moderation.json")
}

pub fn read_moderation_history(base: &Path, chan: &ChannelRef) -> Result<Vec<ModerationEvent>> {
    let path = moderation_log_path(base, chan);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let reader = BufReader::new(std::fs::File::open(&path)?);
    let mut events = Vec::new();
    for (line_index, line) in reader.lines().enumerate() {
        let line =
            line.with_context(|| format!("read {} line {}", path.display(), line_index + 1))?;
        if !line.trim().is_empty() {
            events.push(serde_json::from_str(&line).with_context(|| {
                format!(
                    "invalid moderation event {} line {}",
                    path.display(),
                    line_index + 1
                )
            })?);
        }
    }
    derive_moderation(base, chan, &events)?;
    Ok(events)
}

pub fn moderation_state(base: &Path, chan: &ChannelRef) -> Result<ModerationState> {
    derive_moderation(base, chan, &read_moderation_history(base, chan)?)
}

pub fn tombstone_message(
    base: &Path,
    chan: &ChannelRef,
    signer: &KeypairFile,
    target: &str,
    reason: Option<String>,
) -> Result<ModerationState> {
    read_message_by_id(base, chan, target).context("cannot tombstone an unknown message")?;
    append_moderation_action(
        base,
        chan,
        signer,
        ModerationAction::Tombstone {
            target: target.to_string(),
            reason,
        },
    )
}

pub fn restore_message(
    base: &Path,
    chan: &ChannelRef,
    signer: &KeypairFile,
    target: &str,
) -> Result<ModerationState> {
    append_moderation_action(
        base,
        chan,
        signer,
        ModerationAction::Restore {
            target: target.to_string(),
        },
    )
}

fn append_moderation_action(
    base: &Path,
    chan: &ChannelRef,
    signer: &KeypairFile,
    action: ModerationAction,
) -> Result<ModerationState> {
    let log_path = channel_to_path(base, &chan.full_name).join("log.ndjson");
    let log = OpenOptions::new().read(true).open(&log_path)?;
    FileExt::lock_exclusive(&log).with_context(|| format!("lock {}", log_path.display()))?;
    let mut events = read_moderation_history(base, chan)?;
    let previous = events.last().map(|event| event.id.clone());
    let policy_head = read_policy_history(base, chan)?
        .last()
        .context("moderation requires a signed restricted policy")?
        .id
        .clone();
    events.push(sign_moderation_event(
        chan,
        signer,
        previous,
        policy_head,
        action,
    )?);
    let state = derive_moderation(base, chan, &events)?;
    let path = moderation_log_path(base, chan);
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    serde_json::to_writer(&mut file, events.last().expect("event was appended"))?;
    file.write_all(b"\n")?;
    file.flush()?;
    file.sync_data()?;
    write_moderation_cache(base, chan, &state)?;
    Ok(state)
}

fn sign_moderation_event(
    chan: &ChannelRef,
    signer: &KeypairFile,
    previous: Option<String>,
    policy_head: String,
    action: ModerationAction,
) -> Result<ModerationEvent> {
    let ts = chrono::Utc::now().timestamp();
    let payload = serde_json::to_vec(&ModerationEventPayload {
        channel: &chan.full_name,
        actor: &signer.public_key,
        ts,
        previous: &previous,
        policy_head: &policy_head,
        action: &action,
    })?;
    let id = hex::encode(blake3::hash(&payload).as_bytes());
    let mut signed = b"embernet-moderation-v1\n".to_vec();
    signed.extend_from_slice(&payload);
    Ok(ModerationEvent {
        id,
        channel: chan.full_name.clone(),
        actor: signer.public_key.clone(),
        ts,
        previous,
        policy_head,
        action,
        sig: signer.sign_bytes(&signed)?,
    })
}

pub fn validate_moderation_history(
    base: &Path,
    chan: &ChannelRef,
    events: &[ModerationEvent],
) -> Result<ModerationState> {
    derive_moderation(base, chan, events)
}

fn derive_moderation(
    base: &Path,
    chan: &ChannelRef,
    events: &[ModerationEvent],
) -> Result<ModerationState> {
    let policy_history = read_policy_history(base, chan)?;
    let mut state = ModerationState::default();
    let mut previous: Option<String> = None;
    for event in events {
        if event.channel != chan.full_name || event.previous != previous {
            bail!("invalid moderation event chain at {}", event.id);
        }
        let policy_position = policy_history
            .iter()
            .position(|policy_event| policy_event.id == event.policy_head)
            .with_context(|| format!("unknown policy head {}", event.policy_head))?;
        let policy = derive_policy(chan, &policy_history[..=policy_position])?;
        let authorized = policy.owner.as_deref() == Some(&event.actor)
            || policy.moderators.iter().any(|key| key == &event.actor);
        if !authorized {
            bail!(
                "actor {} is not allowed to moderate {}",
                event.actor,
                chan.full_name
            );
        }
        let payload = serde_json::to_vec(&ModerationEventPayload {
            channel: &event.channel,
            actor: &event.actor,
            ts: event.ts,
            previous: &event.previous,
            policy_head: &event.policy_head,
            action: &event.action,
        })?;
        if event.id != hex::encode(blake3::hash(&payload).as_bytes()) {
            bail!("moderation event {} has an invalid id", event.id);
        }
        let mut signed = b"embernet-moderation-v1\n".to_vec();
        signed.extend_from_slice(&payload);
        verify_bytes(&event.actor, &event.sig, &signed)
            .with_context(|| format!("verify moderation event {}", event.id))?;
        match &event.action {
            ModerationAction::Tombstone { target, reason } => {
                validate_public_key(target).context("invalid tombstone target")?;
                state.tombstoned.insert(target.clone(), reason.clone());
            }
            ModerationAction::Restore { target } => {
                validate_public_key(target).context("invalid restore target")?;
                state.tombstoned.remove(target);
            }
        }
        previous = Some(event.id.clone());
    }
    Ok(state)
}

pub fn append_remote_moderation_history(
    base: &Path,
    chan: &ChannelRef,
    remote: &[ModerationEvent],
) -> Result<ModerationState> {
    let log_path = channel_to_path(base, &chan.full_name).join("log.ndjson");
    let log = OpenOptions::new().read(true).open(&log_path)?;
    FileExt::lock_exclusive(&log).with_context(|| format!("lock {}", log_path.display()))?;
    let local = read_moderation_history(base, chan)?;
    validate_moderation_history(base, chan, remote)?;
    if local.len() > remote.len()
        || !local
            .iter()
            .zip(remote)
            .all(|(left, right)| left.id == right.id)
    {
        bail!("remote moderation history does not extend the local history");
    }
    if remote.len() > local.len() {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(moderation_log_path(base, chan))?;
        for event in &remote[local.len()..] {
            serde_json::to_writer(&mut file, event)?;
            file.write_all(b"\n")?;
        }
        file.flush()?;
        file.sync_data()?;
    }
    let state = derive_moderation(base, chan, remote)?;
    write_moderation_cache(base, chan, &state)?;
    Ok(state)
}

fn moderation_conflict_dir(base: &Path, chan: &ChannelRef) -> PathBuf {
    channel_to_path(base, &chan.full_name).join("moderation-conflicts")
}

pub fn save_moderation_conflict(
    base: &Path,
    chan: &ChannelRef,
    events: &[ModerationEvent],
) -> Result<String> {
    validate_moderation_history(base, chan, events)?;
    let head = events
        .last()
        .context("cannot save an empty moderation conflict")?
        .id
        .clone();
    let dir = moderation_conflict_dir(base, chan);
    ensure_dir(&dir)?;
    let path = dir.join(format!("{head}.ndjson"));
    let mut bytes = Vec::new();
    for event in events {
        serde_json::to_writer(&mut bytes, event)?;
        bytes.push(b'\n');
    }
    std::fs::write(path, bytes)?;
    Ok(head)
}

pub fn list_moderation_conflicts(base: &Path, chan: &ChannelRef) -> Result<Vec<String>> {
    let dir = moderation_conflict_dir(base, chan);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut heads = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file()
            && let Some(name) = entry.path().file_stem().and_then(|name| name.to_str())
        {
            heads.push(name.to_string());
        }
    }
    heads.sort();
    Ok(heads)
}

pub fn resolve_moderation_conflict(
    base: &Path,
    chan: &ChannelRef,
    head: &str,
) -> Result<ModerationState> {
    validate_public_key(head).context("moderation head must be a 32-byte hex ID")?;
    let path = moderation_conflict_dir(base, chan).join(format!("{head}.ndjson"));
    let events: Vec<ModerationEvent> = std::fs::read_to_string(&path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    if events.last().map(|event| event.id.as_str()) != Some(head) {
        bail!("saved moderation conflict does not match requested head");
    }
    let state = validate_moderation_history(base, chan, &events)?;
    let channel_log_path = channel_to_path(base, &chan.full_name).join("log.ndjson");
    let channel_log = OpenOptions::new().read(true).open(&channel_log_path)?;
    FileExt::lock_exclusive(&channel_log)
        .with_context(|| format!("lock {}", channel_log_path.display()))?;
    let history_path = moderation_log_path(base, chan);
    let temp = history_path.with_extension("ndjson.tmp");
    let mut data = Vec::new();
    for event in &events {
        serde_json::to_writer(&mut data, event)?;
        data.push(b'\n');
    }
    std::fs::write(&temp, data)?;
    std::fs::rename(temp, history_path)?;
    write_moderation_cache(base, chan, &state)?;
    Ok(state)
}

fn write_moderation_cache(base: &Path, chan: &ChannelRef, state: &ModerationState) -> Result<()> {
    let path = moderation_cache_path(base, chan);
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, serde_json::to_vec_pretty(state)?)?;
    std::fs::rename(temp, path)?;
    Ok(())
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
    read_channel_tail_with_options(base, chan, n, false)
}

pub fn read_channel_tail_with_options(
    base: &Path,
    chan: &ChannelRef,
    n: usize,
    include_tombstoned: bool,
) -> Result<Vec<Envelope>> {
    let p = channel_to_path(base, &chan.full_name).join("log.ndjson");
    let mut envelopes = read_verified_log(&p)?;
    if !include_tombstoned {
        let moderation = moderation_state(base, chan)?;
        envelopes.retain(|env| !moderation.tombstoned.contains_key(&env.id));
    }
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

    #[test]
    fn restricted_policy_enforces_roles_and_revocation() {
        let base = temp_dir();
        init_layout(&base).unwrap();
        let chan = ChannelRef::parse("test/private").unwrap();
        create_channel(&base, &chan).unwrap();
        let owner = KeypairFile::generate(Some("owner".into()));
        let writer = KeypairFile::generate(Some("writer".into()));
        let outsider = KeypairFile::generate(Some("outsider".into()));
        restrict_channel(&base, &chan, &owner).unwrap();

        let sign = |key: KeypairFile, body: &str| {
            Envelope::sign(
                key,
                &chan.full_name,
                Message::new_text(None, vec![], body.into(), vec![]),
            )
            .unwrap()
        };
        append_message(&base, &chan, &sign(owner.clone(), "owner")).unwrap();
        assert!(append_message(&base, &chan, &sign(outsider, "denied")).is_err());

        grant_role(&base, &chan, &owner, PolicyRole::Writer, &writer.public_key).unwrap();
        append_message(&base, &chan, &sign(writer.clone(), "allowed")).unwrap();
        revoke_role(&base, &chan, &owner, PolicyRole::Writer, &writer.public_key).unwrap();
        assert!(append_message(&base, &chan, &sign(writer, "revoked")).is_err());
        assert_eq!(count_messages(&base, &chan).unwrap(), 2);
    }

    #[test]
    fn moderator_can_manage_writers_but_not_moderators() {
        let base = temp_dir();
        init_layout(&base).unwrap();
        let chan = ChannelRef::parse("test/private").unwrap();
        create_channel(&base, &chan).unwrap();
        let owner = KeypairFile::generate(None);
        let moderator = KeypairFile::generate(None);
        let writer = KeypairFile::generate(None);
        restrict_channel(&base, &chan, &owner).unwrap();
        grant_role(
            &base,
            &chan,
            &owner,
            PolicyRole::Moderator,
            &moderator.public_key,
        )
        .unwrap();
        grant_role(
            &base,
            &chan,
            &moderator,
            PolicyRole::Writer,
            &writer.public_key,
        )
        .unwrap();
        assert!(
            grant_role(
                &base,
                &chan,
                &moderator,
                PolicyRole::Moderator,
                &writer.public_key,
            )
            .is_err()
        );
    }

    #[test]
    fn legacy_channel_without_policy_remains_open() {
        let base = temp_dir();
        init_layout(&base).unwrap();
        let chan = ChannelRef::parse("test/open").unwrap();
        create_channel(&base, &chan).unwrap();
        let env = Envelope::sign(
            KeypairFile::generate(None),
            &chan.full_name,
            Message::new_text(None, vec![], "open".into(), vec![]),
        )
        .unwrap();
        append_message(&base, &chan, &env).unwrap();
        assert_eq!(
            read_channel_policy(&base, &chan).unwrap().mode,
            PolicyMode::Open
        );
    }

    #[test]
    fn signed_policy_history_chains_and_rebuilds_cache() {
        let base = temp_dir();
        init_layout(&base).unwrap();
        let chan = ChannelRef::parse("test/policy-history").unwrap();
        create_channel(&base, &chan).unwrap();
        let owner = KeypairFile::generate(None);
        let writer = KeypairFile::generate(None);
        restrict_channel(&base, &chan, &owner).unwrap();
        grant_role(&base, &chan, &owner, PolicyRole::Writer, &writer.public_key).unwrap();

        let history = read_policy_history(&base, &chan).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[1].previous.as_deref(), Some(history[0].id.as_str()));
        std::fs::remove_file(policy_path(&base, &chan)).unwrap();
        let rebuilt = rebuild_policy_cache(&base, &chan).unwrap();
        assert!(rebuilt.writers.contains(&writer.public_key));
    }

    #[test]
    fn ownership_transfer_requires_current_owner() {
        let base = temp_dir();
        init_layout(&base).unwrap();
        let chan = ChannelRef::parse("test/policy-transfer").unwrap();
        create_channel(&base, &chan).unwrap();
        let owner = KeypairFile::generate(None);
        let successor = KeypairFile::generate(None);
        restrict_channel(&base, &chan, &owner).unwrap();
        let policy = transfer_ownership(&base, &chan, &owner, &successor.public_key).unwrap();
        assert_eq!(policy.owner.as_deref(), Some(successor.public_key.as_str()));
        assert!(transfer_ownership(&base, &chan, &owner, &owner.public_key).is_err());
    }

    #[test]
    fn tampered_policy_event_is_rejected() {
        let base = temp_dir();
        init_layout(&base).unwrap();
        let chan = ChannelRef::parse("test/policy-history").unwrap();
        create_channel(&base, &chan).unwrap();
        let owner = KeypairFile::generate(None);
        restrict_channel(&base, &chan, &owner).unwrap();
        let path = policy_log_path(&base, &chan);
        let mut event: PolicyEvent =
            serde_json::from_str(std::fs::read_to_string(&path).unwrap().trim()).unwrap();
        event.sig = "00".repeat(64);
        let mut bytes = serde_json::to_vec(&event).unwrap();
        bytes.push(b'\n');
        std::fs::write(path, bytes).unwrap();
        assert!(read_policy_history(&base, &chan).is_err());
    }

    #[test]
    fn legacy_restricted_policy_is_adopted_by_owner() {
        let base = temp_dir();
        init_layout(&base).unwrap();
        let chan = ChannelRef::parse("test/policy-history").unwrap();
        create_channel(&base, &chan).unwrap();
        let owner = KeypairFile::generate(None);
        let writer = KeypairFile::generate(None);
        let legacy = ChannelPolicy {
            version: 1,
            mode: PolicyMode::Restricted,
            owner: Some(owner.public_key.clone()),
            moderators: Vec::new(),
            writers: Vec::new(),
        };
        std::fs::write(
            policy_path(&base, &chan),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        grant_role(&base, &chan, &owner, PolicyRole::Writer, &writer.public_key).unwrap();
        let history = read_policy_history(&base, &chan).unwrap();
        assert_eq!(history.len(), 2);
        assert!(matches!(history[0].action, PolicyAction::Adopt { .. }));
    }

    #[test]
    fn moderation_tombstones_filter_views_and_restore() {
        let base = temp_dir();
        init_layout(&base).unwrap();
        let chan = ChannelRef::parse("test/moderation").unwrap();
        create_channel(&base, &chan).unwrap();
        let owner = KeypairFile::generate(None);
        let writer = KeypairFile::generate(None);
        restrict_channel(&base, &chan, &owner).unwrap();
        grant_role(&base, &chan, &owner, PolicyRole::Writer, &writer.public_key).unwrap();
        let env = Envelope::sign(
            writer.clone(),
            &chan.full_name,
            Message::new_text(None, vec![], "hide me".into(), vec![]),
        )
        .unwrap();
        append_message(&base, &chan, &env).unwrap();

        assert!(tombstone_message(&base, &chan, &writer, &env.id, None).is_err());
        tombstone_message(&base, &chan, &owner, &env.id, Some("spam".into())).unwrap();
        assert!(read_channel_tail(&base, &chan, 10).unwrap().is_empty());
        assert_eq!(
            read_channel_tail_with_options(&base, &chan, 10, true)
                .unwrap()
                .len(),
            1
        );
        restore_message(&base, &chan, &owner, &env.id).unwrap();
        assert_eq!(read_channel_tail(&base, &chan, 10).unwrap().len(), 1);
        let history = read_moderation_history(&base, &chan).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[1].previous.as_deref(), Some(history[0].id.as_str()));
    }

    #[test]
    fn tampered_moderation_event_is_rejected() {
        let base = temp_dir();
        init_layout(&base).unwrap();
        let chan = ChannelRef::parse("test/moderation").unwrap();
        create_channel(&base, &chan).unwrap();
        let owner = KeypairFile::generate(None);
        restrict_channel(&base, &chan, &owner).unwrap();
        let env = Envelope::sign(
            owner.clone(),
            &chan.full_name,
            Message::new_text(None, vec![], "target".into(), vec![]),
        )
        .unwrap();
        append_message(&base, &chan, &env).unwrap();
        tombstone_message(&base, &chan, &owner, &env.id, None).unwrap();
        let path = moderation_log_path(&base, &chan);
        let mut event: ModerationEvent =
            serde_json::from_str(std::fs::read_to_string(&path).unwrap().trim()).unwrap();
        event.sig = "00".repeat(64);
        let mut record = serde_json::to_vec(&event).unwrap();
        record.push(b'\n');
        std::fs::write(path, record).unwrap();
        assert!(read_moderation_history(&base, &chan).is_err());
    }

    #[test]
    fn moderation_uses_policy_at_event_time() {
        let base = temp_dir();
        init_layout(&base).unwrap();
        let chan = ChannelRef::parse("test/moderation-transfer").unwrap();
        create_channel(&base, &chan).unwrap();
        let owner = KeypairFile::generate(None);
        let successor = KeypairFile::generate(None);
        restrict_channel(&base, &chan, &owner).unwrap();
        let env = Envelope::sign(
            owner.clone(),
            &chan.full_name,
            Message::new_text(None, vec![], "target".into(), vec![]),
        )
        .unwrap();
        append_message(&base, &chan, &env).unwrap();
        tombstone_message(&base, &chan, &owner, &env.id, None).unwrap();
        transfer_ownership(&base, &chan, &owner, &successor.public_key).unwrap();

        assert!(
            moderation_state(&base, &chan)
                .unwrap()
                .tombstoned
                .contains_key(&env.id)
        );
        assert!(restore_message(&base, &chan, &owner, &env.id).is_err());
        restore_message(&base, &chan, &successor, &env.id).unwrap();
    }
}
