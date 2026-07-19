mod mcp;
mod proto;
mod server;
mod store;
mod sync;
mod util;

use crate::proto::{Envelope, KeypairFile, Message};
use crate::store::{
    ChannelRef, PolicyRole, append_message, init_layout, read_channel_tail_with_options,
};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

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

    /// Initialize data layout and copy key
    Init {
        #[arg(long, default_value = "identity.json")]
        key: PathBuf,
    },

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

    /// Grant a moderator or writer role by Ed25519 public key
    ChannelGrant {
        channel: String,
        role: RoleArg,
        public_key: String,
    },

    /// Revoke a moderator or writer role by Ed25519 public key
    ChannelRevoke {
        channel: String,
        role: RoleArg,
        public_key: String,
    },

    /// Transfer channel ownership to an Ed25519 public key
    ChannelTransferOwner { channel: String, public_key: String },

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

    /// Sync messages from a remote peer via WebSocket Have/Want protocol
    Sync {
        /// Remote peer URL (e.g. ws://127.0.0.1:4444/sync)
        #[arg(long)]
        peer: String,
        /// Channel to sync
        channel: String,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RoleArg {
    Moderator,
    Writer,
}

impl From<RoleArg> for PolicyRole {
    fn from(role: RoleArg) -> Self {
        match role {
            RoleArg::Moderator => Self::Moderator,
            RoleArg::Writer => Self::Writer,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let datadir = cli.data;

    match cli.command {
        Commands::Keygen { out, alias } => {
            let kp = KeypairFile::generate(alias);
            kp.save(&out)?;
            println!("wrote {}", out.display());
        }
        Commands::Init { key } => {
            init_layout(&datadir)?;
            let kp = KeypairFile::load(&key).context("failed to read key file")?;
            kp.save(&datadir.join("keys/identity.json"))?;
            println!("initialized {}", datadir.display());
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
            let identity = KeypairFile::load(&datadir.join("keys/identity.json"))?;
            let policy = store::restrict_channel(&datadir, &chan, &identity)?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
        }
        Commands::ChannelGrant {
            channel,
            role,
            public_key,
        } => {
            let chan = ChannelRef::parse(&channel)?;
            let identity = KeypairFile::load(&datadir.join("keys/identity.json"))?;
            let policy = store::grant_role(&datadir, &chan, &identity, role.into(), &public_key)?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
        }
        Commands::ChannelRevoke {
            channel,
            role,
            public_key,
        } => {
            let chan = ChannelRef::parse(&channel)?;
            let identity = KeypairFile::load(&datadir.join("keys/identity.json"))?;
            let policy = store::revoke_role(&datadir, &chan, &identity, role.into(), &public_key)?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
        }
        Commands::ChannelTransferOwner {
            channel,
            public_key,
        } => {
            let chan = ChannelRef::parse(&channel)?;
            let identity = KeypairFile::load(&datadir.join("keys/identity.json"))?;
            let policy = store::transfer_ownership(&datadir, &chan, &identity, &public_key)?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
        }
        Commands::ModerateTombstone {
            channel,
            message_id,
            reason,
        } => {
            let chan = ChannelRef::parse(&channel)?;
            let identity = KeypairFile::load(&datadir.join("keys/identity.json"))?;
            let state = store::tombstone_message(&datadir, &chan, &identity, &message_id, reason)?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        Commands::ModerateRestore {
            channel,
            message_id,
        } => {
            let chan = ChannelRef::parse(&channel)?;
            let identity = KeypairFile::load(&datadir.join("keys/identity.json"))?;
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
            let kp = KeypairFile::load(&datadir.join("keys/identity.json"))?;
            let msg = Message::new_text(title, tags, body, refs);
            let env = Envelope::sign(kp, &chan.full_name, msg)?;
            let id = append_message(&datadir, &chan, &env)?;
            println!("posted {} -> {}", channel, id);
        }
        Commands::Tail {
            channel,
            n,
            include_tombstoned,
        } => {
            let chan = ChannelRef::parse(&channel)?;
            let msgs = read_channel_tail_with_options(&datadir, &chan, n, include_tombstoned)?;
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
        Commands::Sync { peer, channel } => {
            let received = sync::sync_from_peer(&datadir, &peer, &channel).await?;
            println!(
                "synced {} messages from {} for channel '{}'",
                received, peer, channel
            );
        }
    }

    Ok(())
}
