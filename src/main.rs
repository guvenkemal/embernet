mod proto;
mod server;
mod store;
mod util;

use crate::proto::{Envelope, KeypairFile, Message};
use crate::store::{ChannelRef, append_message, init_layout, read_channel_tail};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "embernet",
    version,
    about = "Underground chat/forum daemon (Phase 0)"
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

    /// Post a text message into a channel
    Post {
        channel: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        tags: Vec<String>,
        #[arg(long)]
        body: String,
        #[arg(long)]
        refs: Vec<String>,
    },

    /// Tail last N messages from a channel
    Tail {
        channel: String,
        #[arg(long, default_value_t = 20)]
        n: usize,
    },

    /// Run local HTTP server (status + placeholder)
    Serve {
        #[arg(long, default_value = "127.0.0.1:4444")]
        listen: String,
    },
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
        Commands::Tail { channel, n } => {
            let chan = ChannelRef::parse(&channel)?;
            let msgs = read_channel_tail(&datadir, &chan, n)?;
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
    }

    Ok(())
}
