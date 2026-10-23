use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use lemonwire_proto::keys::fingerprint;
use lemonwire_server::db::{Db, InitParams, now};
use lemonwire_server::{Listeners, ServeOptions, open_data_dir, serve, shutdown_signal};

/// Lemon Wire index server.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Data directory (holds index.db and the server's secret key, server.key).
    #[arg(long, env = "LEMONWIRE_DATA", default_value = "./data", global = true)]
    data: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new index. Runs once per data directory.
    Init {
        /// Name of this index, shown to members.
        #[arg(long)]
        index_name: String,
        /// The admin's public key, from `lemonwire keys generate`.
        #[arg(long)]
        admin_pubkey: String,
        /// The admin's member name.
        #[arg(long, default_value = "admin")]
        admin_name: String,
        /// Public URL of the API, e.g. https://index.example.
        #[arg(long)]
        public_url: String,
        /// Public URL of the tracker, e.g. https://index.example or http://host:6969.
        #[arg(long)]
        tracker_url: String,
    },
    /// Show this server's public key and fingerprint, for members to pin.
    Info,
    /// Change the public or tracker URL after init.
    Config {
        #[arg(long)]
        public_url: Option<String>,
        #[arg(long)]
        tracker_url: Option<String>,
    },
    /// Manage members.
    Members {
        #[command(subcommand)]
        command: MembersCommand,
    },
    /// Manage single-use invites.
    Invite {
        #[command(subcommand)]
        command: InviteCommand,
    },
    /// Manage indexed torrents.
    Torrents {
        #[command(subcommand)]
        command: TorrentsCommand,
    },
    /// Run the HTTP API and the tracker.
    Serve {
        #[arg(long, env = "LEMONWIRE_BIND", default_value = "0.0.0.0:8080")]
        bind: String,
        #[arg(long, env = "LEMONWIRE_TRACKER_BIND", default_value = "0.0.0.0:6969")]
        tracker_bind: String,
        /// Take client IPs from X-Real-IP / X-Forwarded-For. Only use this behind a
        /// reverse proxy that sets those headers.
        #[arg(long, env = "LEMONWIRE_TRUST_PROXY")]
        trust_proxy: bool,
        /// When the index shares a LAN with some members (e.g. an always-on seeder on
        /// the same host), give outside members this public IP or hostname for peers
        /// that announced from a private address. Needs a router port forward.
        #[arg(long, env = "LEMONWIRE_NAT_PUBLIC_ADDR")]
        nat_public_addr: Option<String>,
        /// Most entries one member may have in the index (0 = no limit).
        #[arg(long, env = "LEMONWIRE_MAX_SHARES_PER_MEMBER", default_value_t = 1000)]
        max_shares_per_member: u64,
    },
}

#[derive(Subcommand)]
enum MembersCommand {
    List,
    Add {
        #[arg(long)]
        pubkey: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        admin: bool,
    },
    /// Remove a member and end their sessions. Accepts a public key, a unique key
    /// prefix, or a name.
    Revoke {
        member: String,
    },
    /// Issue a new tracker passkey; the member's old .torrent files stop working.
    RotatePasskey {
        member: String,
    },
}

#[derive(Subcommand)]
enum InviteCommand {
    /// Print a single-use invite token.
    Create {
        #[arg(long)]
        admin: bool,
        #[arg(long, default_value_t = 24)]
        ttl_hours: u32,
    },
    List,
}

#[derive(Subcommand)]
enum TorrentsCommand {
    List {
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    Remove {
        infohash: String,
    },
}

fn open_initialised(dir: &std::path::Path) -> anyhow::Result<Db> {
    let db = open_data_dir(dir)?;
    if !db.is_initialized()? {
        bail!(
            "{} is not initialised: run `lemonwire-server init` first",
            dir.display()
        );
    }
    Ok(db)
}

fn ago(ts: i64) -> String {
    let d = now() - ts;
    match d {
        d if d < 0 => format!("in {}", ago_span(-d)),
        d => format!("{} ago", ago_span(d)),
    }
}

fn ago_span(s: i64) -> String {
    match s {
        s if s < 120 => format!("{s}s"),
        s if s < 7200 => format!("{}m", s / 60),
        s if s < 172_800 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86400),
    }
}

fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lemonwire_server=info".into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();
    let cli = Cli::parse();

    match cli.command {
        Command::Init {
            index_name,
            admin_pubkey,
            admin_name,
            public_url,
            tracker_url,
        } => {
            let mut db = open_data_dir(&cli.data)?;
            let server = db.init(&InitParams {
                name: &index_name,
                admin_pubkey: &admin_pubkey,
                admin_name: &admin_name,
                public_url: &public_url,
                tracker_url: &tracker_url,
            })?;
            let pk = server.public().to_b64();
            println!("Initialised index {index_name:?} in {}", cli.data.display());
            println!("Admin:              {admin_name}");
            println!("Server public key:  {pk}");
            println!("Fingerprint:        {}", fingerprint(&pk));
            println!();
            println!(
                "Its secret key is in {} (keep it private and back it up).",
                cli.data.join(lemonwire_server::db::KEY_FILE).display()
            );
            println!("This is the index's identity. Start it with `lemonwire-server serve`, then");
            println!("on the admin's machine add the profile, pinning this key:");
            println!("  lemonwire profile add <profile> {public_url} --server-key {pk}");
        }
        Command::Info => {
            let db = open_initialised(&cli.data)?;
            let pk = db.meta("server_pub")?.context("missing server key")?;
            println!("Name:         {}", db.meta("name")?.unwrap_or_default());
            println!("Public key:   {pk}");
            println!("Fingerprint:  {}", fingerprint(&pk));
            println!(
                "Public URL:   {}",
                db.meta("public_url")?.unwrap_or_default()
            );
            println!(
                "Tracker URL:  {}",
                db.meta("tracker_url")?.unwrap_or_default()
            );
            println!("Members:      {}", db.members()?.len());
        }
        Command::Config {
            public_url,
            tracker_url,
        } => {
            let db = open_initialised(&cli.data)?;
            if let Some(u) = public_url {
                db.set_public_url(&u)?;
            }
            if let Some(u) = tracker_url {
                db.set_tracker_url(&u)?;
            }
            println!(
                "Public URL:   {}",
                db.meta("public_url")?.unwrap_or_default()
            );
            println!(
                "Tracker URL:  {}",
                db.meta("tracker_url")?.unwrap_or_default()
            );
            println!("Restart `serve` for changes to take effect.");
        }
        Command::Members { command } => {
            let mut db = open_initialised(&cli.data)?;
            match command {
                MembersCommand::List => {
                    println!("{:<20} {:<6} {:<10} PUBLIC KEY", "NAME", "ADMIN", "JOINED");
                    for u in db.members()? {
                        println!(
                            "{:<20} {:<6} {:<10} {}",
                            u.name,
                            if u.is_admin { "yes" } else { "" },
                            ago(u.created_at),
                            u.pubkey
                        );
                    }
                }
                MembersCommand::Add {
                    pubkey,
                    name,
                    admin,
                } => {
                    let u = db.add_member(&pubkey, &name, admin)?;
                    println!(
                        "Added {}{}",
                        u.name,
                        if u.is_admin { " (admin)" } else { "" }
                    );
                }
                MembersCommand::Revoke { member } => {
                    let u = db.resolve_member(&member)?;
                    db.revoke(&u.pubkey)?;
                    println!("Revoked {} and ended their sessions.", u.name);
                    println!("A running server forgets their peers within a minute.");
                }
                MembersCommand::RotatePasskey { member } => {
                    let u = db.resolve_member(&member)?;
                    db.rotate_passkey(&u.pubkey)?;
                    println!(
                        "New passkey issued for {}. They need to log in again to get it.",
                        u.name
                    );
                }
            }
        }
        Command::Invite { command } => {
            let db = open_initialised(&cli.data)?;
            match command {
                InviteCommand::Create { admin, ttl_hours } => {
                    let inv = db.create_invite(admin, ttl_hours)?;
                    println!("{}", inv.code.as_deref().unwrap_or_default());
                    eprintln!(
                        "Single-use{} invite {}, expires {}. It includes this index's key, so the\n\
                         member's client checks it's talking to the right server. They run:",
                        if admin { " admin" } else { "" },
                        inv.id,
                        ago(inv.expires_at)
                    );
                    let url = db.meta("public_url")?.unwrap_or_default();
                    eprintln!(
                        "  lemonwire profile add <profile> {url} --invite <code> --name <their name>"
                    );
                    eprintln!("This is the only time the code is shown.");
                }
                InviteCommand::List => {
                    println!("{:<14} {:<6} {:<12} USED BY", "INVITE", "ADMIN", "EXPIRES");
                    for i in db.invites()? {
                        println!(
                            "{:<14} {:<6} {:<12} {}",
                            i.id,
                            if i.is_admin { "yes" } else { "" },
                            ago(i.expires_at),
                            i.used_by.as_deref().unwrap_or("-")
                        );
                    }
                }
            }
        }
        Command::Torrents { command } => {
            let mut db = open_initialised(&cli.data)?;
            match command {
                TorrentsCommand::List { limit } => {
                    println!(
                        "{:<40}  {:>10}  {:<12} {:<10} NAME",
                        "INFOHASH", "SIZE", "UPLOADER", "ADDED"
                    );
                    for t in db.recent(limit)? {
                        println!(
                            "{:<40}  {:>10}  {:<12} {:<10} {}",
                            t.infohash,
                            human_size(t.size),
                            t.uploader,
                            ago(t.created_at),
                            t.name
                        );
                    }
                }
                TorrentsCommand::Remove { infohash } => {
                    db.delete_torrent(&infohash.to_ascii_lowercase())?;
                    println!("Removed {infohash}.");
                }
            }
        }
        Command::Serve {
            bind,
            tracker_bind,
            trust_proxy,
            nat_public_addr,
            max_shares_per_member,
        } => {
            let listeners = Listeners::bind(&bind, &tracker_bind).await?;
            serve(
                ServeOptions {
                    data_dir: cli.data,
                    trust_proxy,
                    nat_public_addr,
                    max_shares_per_member,
                },
                listeners,
                shutdown_signal(),
            )
            .await?;
        }
    }
    Ok(())
}
