mod crypto;
mod mcp;
mod peers;
mod proto;
mod server;
mod store;
mod sync;
mod tui;
mod util;

use crate::proto::{KeypairFile, Message};
use crate::store::{
    ChannelRef, ChannelVisibility, PolicyRole, append_message, init_layout,
    read_channel_tail_decrypted_with_options,
};
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "embernet",
    version,
    about = "Signed, federated coordination logs"
)]
struct Cli {
    /// Data directory
    #[arg(long, global = true, default_value = "./data")]
    data: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate an identity keypair
    Keygen {
        #[arg(long, default_value = "identity.json")]
        out: PathBuf,
        #[arg(long)]
        alias: Option<String>,
    },

    /// Initialize data layout and create or import its identity
    Init {
        /// Import an existing identity instead of generating one
        #[arg(long, conflicts_with = "alias")]
        key: Option<PathBuf>,
        /// Alias for a newly generated identity
        #[arg(long, conflicts_with = "key")]
        alias: Option<String>,
    },

    /// Show the local node identity used for peer pinning
    Identity,

    /// Create a channel (e.g. tech/discuss)
    ChannelCreate { name: String },

    /// Show a channel's local write policy
    ChannelPolicy { channel: String },

    /// Show the verified signed policy-event history
    ChannelPolicyHistory { channel: String },

    /// Rebuild policy.json from the verified signed history
    ChannelPolicyRebuild { channel: String },

    /// List saved valid policy-history forks
    ChannelPolicyConflicts { channel: String },

    /// Select a saved valid policy-history head
    ChannelPolicyResolve {
        channel: String,
        #[arg(long)]
        head: String,
    },

    /// Restrict channel writes and make the local identity its owner
    ChannelRestrict { channel: String },

    /// Grant a moderator, writer, or reader role by Ed25519 public key
    ChannelGrant {
        channel: String,
        role: RoleArg,
        public_key: String,
    },

    /// Revoke a moderator, writer, or reader role by Ed25519 public key
    ChannelRevoke {
        channel: String,
        role: RoleArg,
        public_key: String,
    },

    /// Transfer channel ownership to an Ed25519 public key
    ChannelTransferOwner { channel: String, public_key: String },

    /// Set a restricted channel's discovery visibility
    ChannelVisibility {
        channel: String,
        visibility: VisibilityArg,
    },

    /// Tombstone a message in normal channel views
    ModerateTombstone {
        channel: String,
        message_id: String,
        #[arg(long)]
        reason: Option<String>,
    },

    /// Restore a tombstoned message
    ModerateRestore { channel: String, message_id: String },

    /// Show the verified moderation event history
    ModerationHistory { channel: String },

    /// List saved moderation-history forks
    ModerationConflicts { channel: String },

    /// Select a saved moderation-history head
    ModerationResolve {
        channel: String,
        #[arg(long)]
        head: String,
    },

    /// Post a text message into a channel
    Post {
        channel: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long, num_args = 1..)]
        tags: Vec<String>,
        #[arg(long)]
        body: String,
        #[arg(long, num_args = 1..)]
        refs: Vec<String>,
    },

    /// Tail last N messages from a channel
    Tail {
        channel: String,
        #[arg(long, default_value_t = 20)]
        n: usize,
        #[arg(long)]
        include_tombstoned: bool,
    },

    /// Run the HTTP status and WebSocket sync server
    Serve {
        #[arg(long, default_value = "127.0.0.1:4444")]
        listen: String,
    },

    /// Run an MCP server over stdio for local AI clients
    Mcp,

    /// Save a peer for automatic synchronization
    PeerAdd {
        url: String,
        /// Expected Ed25519 identity of the peer
        #[arg(long)]
        public_key: String,
    },

    /// List saved peers
    PeerList,

    /// Remove a saved peer
    PeerRemove { url: String },

    /// Run the interactive terminal user interface
    Tui {
        /// Also accept HTTP/WebSocket connections on this address
        #[arg(long)]
        listen: Option<String>,
    },

    /// Sync messages from a remote peer via WebSocket Have/Want protocol
    Sync {
        /// Remote peer URL (e.g. ws://127.0.0.1:4444/sync)
        #[arg(long)]
        peer: String,
        /// Expected peer identity; saves or verifies the pin before syncing
        #[arg(long)]
        public_key: Option<String>,
        /// Channel to sync
        channel: String,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RoleArg {
    Moderator,
    Writer,
    Reader,
}

impl From<RoleArg> for PolicyRole {
    fn from(role: RoleArg) -> Self {
        match role {
            RoleArg::Moderator => Self::Moderator,
            RoleArg::Writer => Self::Writer,
            RoleArg::Reader => Self::Reader,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum VisibilityArg {
    Public,
    Private,
}

impl From<VisibilityArg> for ChannelVisibility {
    fn from(visibility: VisibilityArg) -> Self {
        match visibility {
            VisibilityArg::Public => Self::Public,
            VisibilityArg::Private => Self::Private,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let datadir = cli.data;

    match cli.command {
        Commands::Keygen { out, alias } => {
            let kp = KeypairFile::generate(alias);
            kp.save(&out)?;
            println!("wrote {}", out.display());
        }
        Commands::Init { key, alias } => {
            initialize_identity(&datadir, key.as_deref(), alias)?;
            println!("initialized {}", datadir.display());
        }
        Commands::Identity => {
            let identity = KeypairFile::load_secure(&datadir.join("keys/identity.json"))?;
            println!("public key: {}", identity.public_key);
            if let Some(alias) = &identity.alias {
                println!("alias: {alias}");
            }
        }
        Commands::ChannelCreate { name } => {
            let chan = ChannelRef::parse(&name)?;
            store::create_channel(&datadir, &chan)?;
            println!("channel created: {}", name);
        }
        Commands::ChannelPolicy { channel } => {
            let chan = ChannelRef::parse(&channel)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&store::read_channel_policy(&datadir, &chan)?)?
            );
        }
        Commands::ChannelPolicyHistory { channel } => {
            let chan = ChannelRef::parse(&channel)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&store::read_policy_history(&datadir, &chan)?)?
            );
        }
        Commands::ChannelPolicyRebuild { channel } => {
            let chan = ChannelRef::parse(&channel)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&store::rebuild_policy_cache(&datadir, &chan)?)?
            );
        }
        Commands::ChannelPolicyConflicts { channel } => {
            let chan = ChannelRef::parse(&channel)?;
            for head in store::list_policy_conflicts(&datadir, &chan)? {
                println!("{head}");
            }
        }
        Commands::ChannelPolicyResolve { channel, head } => {
            let chan = ChannelRef::parse(&channel)?;
            let policy = store::resolve_policy_conflict(&datadir, &chan, &head)?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
        }
        Commands::ChannelRestrict { channel } => {
            let chan = ChannelRef::parse(&channel)?;
            let identity = KeypairFile::load_secure(&datadir.join("keys/identity.json"))?;
            let policy = store::restrict_channel(&datadir, &chan, &identity)?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
        }
        Commands::ChannelGrant {
            channel,
            role,
            public_key,
        } => {
            let chan = ChannelRef::parse(&channel)?;
            let identity = KeypairFile::load_secure(&datadir.join("keys/identity.json"))?;
            let policy = store::grant_role(&datadir, &chan, &identity, role.into(), &public_key)?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
        }
        Commands::ChannelRevoke {
            channel,
            role,
            public_key,
        } => {
            let chan = ChannelRef::parse(&channel)?;
            let identity = KeypairFile::load_secure(&datadir.join("keys/identity.json"))?;
            let policy = store::revoke_role(&datadir, &chan, &identity, role.into(), &public_key)?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
        }
        Commands::ChannelTransferOwner {
            channel,
            public_key,
        } => {
            let chan = ChannelRef::parse(&channel)?;
            let identity = KeypairFile::load_secure(&datadir.join("keys/identity.json"))?;
            let policy = store::transfer_ownership(&datadir, &chan, &identity, &public_key)?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
        }
        Commands::ChannelVisibility {
            channel,
            visibility,
        } => {
            let chan = ChannelRef::parse(&channel)?;
            let identity = KeypairFile::load_secure(&datadir.join("keys/identity.json"))?;
            let policy =
                store::set_channel_visibility(&datadir, &chan, &identity, visibility.into())?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
        }
        Commands::ModerateTombstone {
            channel,
            message_id,
            reason,
        } => {
            let chan = ChannelRef::parse(&channel)?;
            let identity = KeypairFile::load_secure(&datadir.join("keys/identity.json"))?;
            let state = store::tombstone_message(&datadir, &chan, &identity, &message_id, reason)?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        Commands::ModerateRestore {
            channel,
            message_id,
        } => {
            let chan = ChannelRef::parse(&channel)?;
            let identity = KeypairFile::load_secure(&datadir.join("keys/identity.json"))?;
            let state = store::restore_message(&datadir, &chan, &identity, &message_id)?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        Commands::ModerationHistory { channel } => {
            let chan = ChannelRef::parse(&channel)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&store::read_moderation_history(&datadir, &chan)?)?
            );
        }
        Commands::ModerationConflicts { channel } => {
            let chan = ChannelRef::parse(&channel)?;
            for head in store::list_moderation_conflicts(&datadir, &chan)? {
                println!("{head}");
            }
        }
        Commands::ModerationResolve { channel, head } => {
            let chan = ChannelRef::parse(&channel)?;
            let state = store::resolve_moderation_conflict(&datadir, &chan, &head)?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        Commands::Post {
            channel,
            title,
            tags,
            body,
            refs,
        } => {
            let chan = ChannelRef::parse(&channel)?;
            let kp = KeypairFile::load_secure(&datadir.join("keys/identity.json"))?;
            let msg = Message::new_text(title, tags, body, refs);
            let env = store::sign_message_for_channel(&datadir, &chan, kp, msg)?;
            let id = append_message(&datadir, &chan, &env)?;
            println!("posted {} -> {}", channel, id);
        }
        Commands::Tail {
            channel,
            n,
            include_tombstoned,
        } => {
            let chan = ChannelRef::parse(&channel)?;
            let identity = KeypairFile::load_secure(&datadir.join("keys/identity.json"))?;
            store::authorize_read(&datadir, &chan, &identity.public_key)?;
            let msgs =
                read_channel_tail_decrypted_with_options(&datadir, &chan, n, include_tombstoned)?;
            for e in msgs {
                println!(
                    "{} | {} | {}\n{}\n",
                    e.ts,
                    e.from_alias.clone().unwrap_or_default(),
                    e.id,
                    e.body_text().unwrap_or_default()
                );
            }
        }
        Commands::Serve { listen } => {
            server::run(datadir, listen).await?;
        }
        Commands::Mcp => {
            mcp::run_stdio(datadir)?;
        }
        Commands::PeerAdd { url, public_key } => {
            let peer = peers::add_peer(&datadir, &url, Some(&public_key))?;
            println!(
                "peer pinned: {} -> {}",
                peer.url,
                peer.public_key.expect("peer-add requires a public key")
            );
        }
        Commands::PeerList => {
            for peer in peers::list_peer_records(&datadir)? {
                println!(
                    "{} | {}",
                    peer.url,
                    peer.public_key.as_deref().unwrap_or("UNPINNED")
                );
            }
        }
        Commands::PeerRemove { url } => {
            let removed = peers::remove_peer(&datadir, &url)?;
            if removed {
                println!("peer removed: {}", peers::normalize_peer_url(&url)?);
            } else {
                println!("peer not found: {}", peers::normalize_peer_url(&url)?);
            }
        }
        Commands::Tui { listen } => {
            tui::run(datadir, listen).await?;
        }
        Commands::Sync {
            peer,
            public_key,
            channel,
        } => {
            if let Some(public_key) = public_key {
                peers::add_peer(&datadir, &peer, Some(&public_key))?;
            } else if peers::expected_peer_key(&datadir, &peer)?.is_none() {
                bail!("direct sync requires --public-key or an existing pinned peer");
            }
            let received = sync::sync_from_peer(&datadir, &peer, &channel).await?;
            println!(
                "synced {} messages from {} for channel '{}'",
                received, peer, channel
            );
        }
    }

    Ok(())
}

fn initialize_identity(
    datadir: &Path,
    import_path: Option<&Path>,
    alias: Option<String>,
) -> Result<KeypairFile> {
    let identity_path = datadir.join("keys/identity.json");
    if identity_path.exists() {
        bail!(
            "identity already exists at {}; refusing to overwrite it",
            identity_path.display()
        );
    }

    let identity = match import_path {
        Some(path) => KeypairFile::load(path)
            .with_context(|| format!("failed to read identity {}", path.display()))?,
        None => KeypairFile::generate(alias),
    };
    init_layout(datadir)?;
    identity.save(&identity_path)?;
    Ok(identity)
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "embernet_init_{label}_{}",
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn init_generates_only_the_canonical_identity() {
        let datadir = temp_dir("generate");
        let generated = initialize_identity(&datadir, None, Some("Alice".into())).unwrap();

        assert_eq!(generated.alias.as_deref(), Some("Alice"));
        assert!(datadir.join("keys/identity.json").is_file());
        assert!(!datadir.join("identity.json").exists());
    }

    #[test]
    fn init_imports_an_existing_identity_without_modifying_source() {
        let source_dir = temp_dir("source");
        std::fs::create_dir_all(&source_dir).unwrap();
        let source_path = source_dir.join("identity.json");
        let source = KeypairFile::generate(Some("Imported".into()));
        source.save(&source_path).unwrap();
        let datadir = temp_dir("import");

        let imported = initialize_identity(&datadir, Some(&source_path), None).unwrap();

        assert_eq!(imported.public_key, source.public_key);
        assert_eq!(imported.secret_key, source.secret_key);
        assert!(source_path.is_file());
    }

    #[test]
    fn init_refuses_to_overwrite_an_existing_identity() {
        let datadir = temp_dir("overwrite");
        let original = initialize_identity(&datadir, None, Some("Original".into())).unwrap();

        assert!(initialize_identity(&datadir, None, Some("Replacement".into())).is_err());
        let stored = KeypairFile::load(&datadir.join("keys/identity.json")).unwrap();
        assert_eq!(stored.public_key, original.public_key);
    }

    #[test]
    fn init_rejects_key_and_alias_together() {
        assert!(
            Cli::try_parse_from([
                "embernet",
                "init",
                "--key",
                "identity.json",
                "--alias",
                "Alice",
            ])
            .is_err()
        );
    }

    #[test]
    fn tui_accepts_an_optional_listen_address() {
        let cli = Cli::try_parse_from([
            "embernet",
            "--data",
            "node",
            "tui",
            "--listen",
            "127.0.0.1:4444",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Tui {
                listen: Some(ref address)
            } if address == "127.0.0.1:4444"
        ));
    }

    #[test]
    fn peer_add_requires_an_identity_pin() {
        assert!(Cli::try_parse_from(["embernet", "peer-add", "ws://127.0.0.1:4444/sync"]).is_err());
        let cli = Cli::try_parse_from([
            "embernet",
            "peer-add",
            "ws://127.0.0.1:4444/sync",
            "--public-key",
            &"01".repeat(32),
        ])
        .unwrap();
        assert!(matches!(cli.command, Commands::PeerAdd { .. }));
    }
}
