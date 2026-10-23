//! `lemonwire`: a thin, one-shot front-end over `lemonwire-client-core`, which a GUI
//! shares. This file only maps arguments to [`Command`]s, renders [`Output`]s and
//! [`Event`]s, and cancels on Ctrl-C. All transfer behaviour lives in the core.

mod render;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use futures::StreamExt;
use lemonwire_client_core::*;
use serde::{Deserialize, Serialize};

/// Lemon Wire: private file sharing for friends.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Print machine-readable JSON instead of tables.
    #[arg(long, global = true)]
    json: bool,
    /// Config directory (profiles, keys, transfers).
    #[arg(long, global = true, env = "LEMONWIRE_CONFIG_DIR")]
    config_dir: Option<PathBuf>,
    /// Profile (index) to use. Defaults to the only or default profile.
    #[arg(short, long, global = true)]
    profile: Option<String>,
    /// TCP port for incoming peers while transferring.
    #[arg(long, global = true, env = "LEMONWIRE_PORT", default_value_t = 6881)]
    port: u16,
    /// Don't ask the router to open --port via UPnP (then forward it by hand, or
    /// rely on the other peer being reachable).
    #[arg(long, global = true, env = "LEMONWIRE_NO_UPNP")]
    no_upnp: bool,
    /// Upload limit in KiB/s while transferring.
    #[arg(long, global = true, env = "LEMONWIRE_MAX_UP", value_name = "KIB")]
    max_up: Option<u32>,
    /// Download limit in KiB/s while transferring.
    #[arg(long, global = true, env = "LEMONWIRE_MAX_DOWN", value_name = "KIB")]
    max_down: Option<u32>,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a key pair before adding a profile (prints the public key).
    Keys {
        #[command(subcommand)]
        command: KeysCmd,
    },
    /// Manage profiles: one per index, each with its own key pair.
    Profile {
        #[command(subcommand)]
        command: ProfileCmd,
    },
    /// Show the index and your membership.
    Info,
    /// Your name on the index and whether you're an admin.
    Whoami,
    /// Search the index. An empty query lists the newest entries.
    Search {
        query: Vec<String>,
        #[arg(long)]
        limit: Option<u32>,
        /// Show the next page of your last search.
        #[arg(long, conflicts_with = "offset")]
        more: bool,
        #[arg(long)]
        offset: Option<u32>,
        /// Only things you've shared.
        #[arg(long)]
        mine: bool,
    },
    /// Show an entry and its numbered file list (for `download --files`).
    Show { target: String },
    /// Publish a file or folder, then seed it until a friend has a full copy.
    Share {
        path: PathBuf,
        /// Tag to attach (repeatable).
        #[arg(long = "tag")]
        tags: Vec<String>,
        /// Keep seeding until this many other members have a full copy.
        #[arg(long, default_value_t = 1, conflicts_with = "forever")]
        copies: u64,
        /// Keep seeding until Ctrl-C.
        #[arg(long)]
        forever: bool,
        /// Publish and exit without seeding (serve it later with `lemonwire seed`).
        #[arg(long, conflicts_with_all = ["copies", "forever"])]
        publish_only: bool,
    },
    /// Download by result number from your last search (e.g. 2 or #2) or infohash,
    /// then seed back briefly. Running it again resumes an interrupted download.
    Download {
        target: String,
        /// Destination folder (default: ~/Downloads/lemonwire).
        #[arg(long)]
        dest: Option<PathBuf>,
        /// Only these files, by number from `lemonwire show` (e.g. 1,3,4).
        #[arg(long, value_delimiter = ',')]
        files: Option<Vec<usize>>,
        /// After finishing, seed until you've uploaded this many times the size...
        #[arg(long, default_value_t = 1.0)]
        seed_ratio: f64,
        /// ...or for at most this long (e.g. 30s, 15m, 2h; 0 to skip).
        #[arg(long, default_value = "15m", value_parser = parse_duration)]
        seed_time: Duration,
        /// Exit as soon as the download completes.
        #[arg(long)]
        no_seed: bool,
    },
    /// Serve everything you've shared or downloaded, until Ctrl-C.
    Seed,
    /// Remove something you shared from the index (admins can remove anything).
    Unpublish { infohash: String },
    /// Who has a torrent right now: seeders, downloaders and members with a full copy.
    Swarm { target: String },
    /// List saved transfers (what `seed` would serve).
    Transfers,
    /// Pause a transfer (infohash or unique prefix); `seed` skips it.
    Pause { infohash: String },
    /// Resume a paused transfer.
    Resume { infohash: String },
    /// Forget a transfer.
    Cancel {
        infohash: String,
        /// Also delete downloaded data. Never deletes the originals you shared.
        #[arg(long)]
        delete_data: bool,
    },
    /// Administer the index remotely (admin profiles only).
    Admin {
        #[command(subcommand)]
        command: AdminCmd,
    },
    /// Execute a JSON command, e.g. '{"cmd":"search","query":"photos"}'.
    Run {
        #[arg(value_name = "JSON")]
        command: String,
    },
}

#[derive(Subcommand)]
enum KeysCmd {
    /// Make a key pair for the profile named by --profile (default "default").
    Generate,
    /// Protect --profile's secret key with a passphrase (asked for twice). Commands then
    /// ask for it, or read LEMONWIRE_PASSPHRASE.
    Protect,
    /// Remove the passphrase from --profile's secret key.
    Unprotect,
}

#[derive(Subcommand)]
enum ProfileCmd {
    /// Add an index. Pins its server key (or checks --server-key) and logs in.
    Add {
        /// Your local label for this index (e.g. "grove").
        #[arg(value_name = "PROFILE")]
        profile_name: String,
        url: String,
        /// The server's public key from the admin, to pin instead of trusting first use.
        #[arg(long)]
        server_key: Option<String>,
        /// A single-use invite code from an admin (`lw1.…`). It includes the index's
        /// key, which is checked like --server-key.
        #[arg(long)]
        invite: Option<String>,
        /// Your member name on the index, when joining with --invite (default: the
        /// profile name). With a direct add, the admin picks it.
        #[arg(long)]
        name: Option<String>,
        /// Allow a plain http:// URL to a public address (your session token and
        /// passkey would travel unencrypted). Not needed for local, private-network or
        /// Tailscale addresses.
        #[arg(long)]
        insecure: bool,
    },
    List,
    /// Remove a profile and delete its secret key.
    Remove {
        name: String,
    },
    /// Make a profile the default.
    Default {
        name: String,
    },
}

#[derive(Subcommand)]
enum AdminCmd {
    Members {
        #[command(subcommand)]
        command: MembersCmd,
    },
    Invite {
        #[command(subcommand)]
        command: InviteCmd,
    },
}

#[derive(Subcommand)]
enum MembersCmd {
    List,
    Add {
        #[arg(long)]
        pubkey: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        admin: bool,
    },
    /// Revoke by name, public key or unique key prefix.
    Revoke {
        member: String,
    },
}

#[derive(Subcommand)]
enum InviteCmd {
    Create {
        #[arg(long)]
        admin: bool,
        #[arg(long)]
        ttl_hours: Option<u32>,
    },
    List,
}

/// Remembered so `download 2` and `search --more` can refer to the last search.
#[derive(Serialize, Deserialize, Default)]
struct LastSearch {
    profile: String,
    query: String,
    mine: bool,
    limit: Option<u32>,
    offset: u32,
    next_offset: Option<u32>,
    infohashes: Vec<String>,
}

fn parse_duration(s: &str) -> std::result::Result<Duration, String> {
    let s = s.trim();
    if s == "0" {
        return Ok(Duration::ZERO);
    }
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: u64 = num.parse().map_err(|_| format!("bad duration {s:?}"))?;
    let secs = match unit {
        "" | "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        _ => return Err(format!("bad duration {s:?}: use e.g. 30s, 15m or 2h")),
    };
    Ok(Duration::from_secs(secs))
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let json = cli.json;
    if let Err(e) = real_main(cli).await {
        if json {
            let err = match e.downcast_ref::<ClientError>() {
                Some(ce) => serde_json::to_value(ce).expect("serialisable"),
                None => serde_json::json!({ "kind": "cli", "message": format!("{e:#}") }),
            };
            println!("{}", serde_json::json!({ "error": err }));
        } else {
            eprintln!("error: {e:#}");
        }
        std::process::exit(1);
    }
}

/// Log filter. librqbit's tracker code and the HTTP stack log full tracker URLs, and
/// its session dumps whole torrents (announce URL included) at trace. Those URLs
/// contain your passkey, so these stay quieter whatever LEMONWIRE_LOG says (unless
/// LEMONWIRE_LOG_SECRETS=1).
/// `LEMONWIRE_LOG` (default "warn"), capped so logs never carry passkeys unless
/// `LEMONWIRE_LOG_SECRETS=1`.
fn init_logging() {
    use tracing_subscriber::filter::{LevelFilter, Targets};
    use tracing_subscriber::prelude::*;
    let base = std::env::var("LEMONWIRE_LOG").unwrap_or_else(|_| "warn".into());
    let base = tracing_subscriber::EnvFilter::try_new(base)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let caps = (std::env::var("LEMONWIRE_LOG_SECRETS").as_deref() != Ok("1")).then(|| {
        Targets::new()
            .with_default(LevelFilter::TRACE)
            .with_targets(lemonwire_client_core::LOG_REDACT_CAPS.iter().copied())
    });
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_ansi(std::io::stderr().is_terminal())
                .with_filter(base)
                .with_filter(caps),
        )
        .init();
}

fn prompt_passphrase(label: &str, env: &str) -> anyhow::Result<String> {
    if !std::io::stdin().is_terminal() {
        bail!("a passphrase is needed: run this in a terminal, or set {env}");
    }
    Ok(rpassword::prompt_password(label)?)
}

async fn real_main(cli: Cli) -> anyhow::Result<()> {
    init_logging();

    let config = match &cli.config_dir {
        Some(d) => ConfigDir::new(d),
        None => ConfigDir::default_location()?,
    };
    config.ensure()?;
    let json = cli.json;
    let cmd = build_command(&cli, &config)?;

    // A protected key needs its passphrase: from the environment, or asked for (up to
    // three tries) the first time a command needs the key.
    let mut passphrase = std::env::var("LEMONWIRE_PASSPHRASE").ok();
    let mut tries = 0;
    let (client, out) = loop {
        let (client, out) = run_once(&cli, &config, &cmd, passphrase.clone()).await?;
        match out {
            Err(ClientError::PassphraseRequired | ClientError::WrongPassphrase)
                if tries < 3 && !json && std::io::stdin().is_terminal() =>
            {
                if tries > 0 {
                    eprintln!("Wrong passphrase.");
                }
                client.shutdown().await;
                drop(client);
                passphrase = Some(prompt_passphrase(
                    "Passphrase for your key: ",
                    "LEMONWIRE_PASSPHRASE",
                )?);
                tries += 1;
            }
            out => break (client, out),
        }
    };
    client.shutdown().await;
    let out = match out {
        Err(ClientError::Cancelled) => bail!(
            "stopped. Anything unfinished is saved: run the same command again, or \
             `lemonwire seed`, to carry on"
        ),
        other => other?,
    };

    if let Output::Results {
        profile,
        offset,
        results,
        next_offset,
    } = &out
    {
        let mut last = pending_search(&cli, &config);
        last.profile = profile.clone();
        last.offset = *offset;
        last.next_offset = *next_offset;
        last.infohashes = results.iter().map(|r| r.infohash.clone()).collect();
        save_last_search(&config, &last);
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&out).expect("serialisable")
        );
    } else {
        render::print(&out);
    }
    Ok(())
}

/// The search being run, remembered for `download <#>` and `search --more`.
fn pending_search(cli: &Cli, config: &ConfigDir) -> LastSearch {
    match &cli.command {
        Cmd::Search { more: true, .. } => load_last_search(config).unwrap_or_default(),
        Cmd::Search {
            query, limit, mine, ..
        } => LastSearch {
            query: query.join(" "),
            mine: *mine,
            limit: *limit,
            ..Default::default()
        },
        _ => LastSearch::default(),
    }
}

fn build_command(cli: &Cli, config: &ConfigDir) -> anyhow::Result<Command> {
    let profile = cli.profile.clone();
    Ok(match &cli.command {
        Cmd::Keys {
            command: KeysCmd::Generate,
        } => Command::KeysGenerate {
            profile: profile.unwrap_or_else(|| "default".into()),
        },
        Cmd::Keys {
            command: KeysCmd::Protect,
        } => {
            // Scripts can pass it in the environment; people are asked twice.
            let first = match std::env::var("LEMONWIRE_NEW_PASSPHRASE") {
                Ok(p) => p,
                Err(_) => {
                    let p = prompt_passphrase("New passphrase: ", "LEMONWIRE_NEW_PASSPHRASE")?;
                    if prompt_passphrase("Again: ", "LEMONWIRE_NEW_PASSPHRASE")? != p {
                        bail!("the passphrases don't match");
                    }
                    p
                }
            };
            if first.is_empty() {
                bail!("the passphrase is empty");
            }
            Command::KeysProtect {
                profile: profile.unwrap_or_else(|| "default".into()),
                new_passphrase: Some(first),
            }
        }
        Cmd::Keys {
            command: KeysCmd::Unprotect,
        } => Command::KeysProtect {
            profile: profile.unwrap_or_else(|| "default".into()),
            new_passphrase: None,
        },
        Cmd::Profile { command } => match command {
            ProfileCmd::Add {
                profile_name,
                url,
                server_key,
                invite,
                name,
                insecure,
            } => Command::ProfileAdd {
                profile: profile_name.clone(),
                url: url.clone(),
                server_key: server_key.clone(),
                invite: invite.clone(),
                member_name: name.clone(),
                allow_insecure: *insecure,
            },
            ProfileCmd::List => Command::ProfileList,
            ProfileCmd::Remove { name } => Command::ProfileRemove { name: name.clone() },
            ProfileCmd::Default { name } => Command::ProfileSetDefault { name: name.clone() },
        },
        Cmd::Info => Command::Info { profile },
        Cmd::Whoami => Command::Whoami { profile },
        Cmd::Search {
            query,
            limit,
            more,
            offset,
            mine,
        } => {
            if *more {
                let last = load_last_search(config)?;
                let Some(next) = last.next_offset else {
                    bail!("that was the last page");
                };
                Command::Search {
                    profile: profile.or(Some(last.profile)),
                    query: last.query,
                    limit: last.limit,
                    offset: Some(next),
                    mine: last.mine,
                }
            } else {
                Command::Search {
                    profile,
                    query: query.join(" "),
                    limit: *limit,
                    offset: *offset,
                    mine: *mine,
                }
            }
        }
        Cmd::Show { target } => {
            let (infohash, from_search) = resolve_target(config, target)?;
            Command::Details {
                profile: profile.or(from_search),
                infohash,
            }
        }
        Cmd::Share {
            path,
            tags,
            copies,
            forever,
            publish_only,
        } => Command::Share {
            profile,
            path: path.clone(),
            tags: tags.clone(),
            until: if *publish_only {
                SeedUntil::PublishOnly
            } else if *forever {
                SeedUntil::Cancelled
            } else {
                SeedUntil::Copies { count: *copies }
            },
        },
        Cmd::Download {
            target,
            dest,
            files,
            seed_ratio,
            seed_time,
            no_seed,
        } => {
            let (infohash, from_search) = resolve_target(config, target)?;
            // People number files from 1; the core indexes from 0.
            let files = files
                .as_ref()
                .map(|f| {
                    f.iter()
                        .map(|&n| n.checked_sub(1).context("file numbers start at 1"))
                        .collect::<anyhow::Result<Vec<_>>>()
                })
                .transpose()?;
            Command::Download {
                profile: profile.or(from_search),
                infohash,
                dest: dest.clone(),
                files,
                seed_back: (!no_seed && !seed_time.is_zero() && *seed_ratio > 0.0).then_some(
                    SeedBack {
                        ratio: *seed_ratio,
                        max_secs: seed_time.as_secs(),
                    },
                ),
            }
        }
        Cmd::Seed => Command::Seed,
        Cmd::Unpublish { infohash } => Command::Unpublish {
            profile,
            infohash: infohash.clone(),
        },
        Cmd::Swarm { target } => {
            let (infohash, from_search) = resolve_target(config, target)?;
            Command::Swarm {
                profile: profile.or(from_search),
                infohash,
            }
        }
        Cmd::Transfers => Command::Transfers,
        Cmd::Pause { infohash } => Command::Pause {
            infohash: expand_prefix(config, infohash)?,
        },
        Cmd::Resume { infohash } => Command::Resume {
            infohash: expand_prefix(config, infohash)?,
        },
        Cmd::Cancel {
            infohash,
            delete_data,
        } => Command::Cancel {
            infohash: expand_prefix(config, infohash)?,
            delete_data: *delete_data,
        },
        Cmd::Admin { command } => match command {
            AdminCmd::Members { command } => match command {
                MembersCmd::List => Command::MembersList { profile },
                MembersCmd::Add {
                    pubkey,
                    name,
                    admin,
                } => Command::MembersAdd {
                    profile,
                    pubkey: pubkey.clone(),
                    name: name.clone(),
                    admin: *admin,
                },
                MembersCmd::Revoke { member } => Command::MembersRevoke {
                    profile,
                    member: member.clone(),
                },
            },
            AdminCmd::Invite { command } => match command {
                InviteCmd::Create { admin, ttl_hours } => Command::InviteCreate {
                    profile,
                    admin: *admin,
                    ttl_hours: *ttl_hours,
                },
                InviteCmd::List => Command::InviteList { profile },
            },
        },
        Cmd::Run { command } => {
            serde_json::from_str(command).context("parsing the JSON command")?
        }
    })
}

fn last_search_path(config: &ConfigDir) -> PathBuf {
    config.root().join("last_search.json")
}

fn save_last_search(config: &ConfigDir, s: &LastSearch) {
    if let Ok(bytes) = serde_json::to_vec(s) {
        let _ = std::fs::write(last_search_path(config), bytes);
    }
}

fn load_last_search(config: &ConfigDir) -> anyhow::Result<LastSearch> {
    let bytes = std::fs::read(last_search_path(config))
        .context("no previous search; run `lemonwire search` first")?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// `2`, `#2` → result 2 of the last search (and its profile); otherwise an infohash.
fn resolve_target(config: &ConfigDir, target: &str) -> anyhow::Result<(String, Option<String>)> {
    let t = target.trim().trim_start_matches('#');
    if t.len() <= 5
        && let Ok(n) = t.parse::<usize>()
    {
        let last = load_last_search(config)?;
        let first = last.offset as usize + 1;
        let infohash = n
            .checked_sub(first)
            .and_then(|i| last.infohashes.get(i))
            .with_context(|| {
                format!(
                    "the last search showed results {first} to {}",
                    first + last.infohashes.len().saturating_sub(1)
                )
            })?;
        return Ok((infohash.clone(), Some(last.profile)));
    }
    Ok((target.trim().to_owned(), None))
}

/// Transfer commands accept a unique infohash prefix.
fn expand_prefix(config: &ConfigDir, prefix: &str) -> anyhow::Result<String> {
    if prefix.len() == 40 {
        return Ok(prefix.to_owned());
    }
    let p = prefix.to_ascii_lowercase();
    let matches: Vec<_> = config
        .load_transfers()?
        .into_iter()
        .filter(|t| t.infohash.starts_with(&p))
        .collect();
    match matches.len() {
        1 => Ok(matches[0].infohash.clone()),
        0 => bail!("no transfer matches {prefix:?}"),
        n => bail!("{prefix:?} matches {n} transfers; use more characters"),
    }
}

/// Open a client and run the command once, rendering progress while it runs.
async fn run_once(
    cli: &Cli,
    config: &ConfigDir,
    cmd: &Command,
    passphrase: Option<String>,
) -> anyhow::Result<(Client, Result<Output>)> {
    let json = cli.json;
    let engine = cmd.needs_engine().then_some(EngineSettings {
        port: cli.port,
        upnp: !cli.no_upnp,
        upload_kib: cli.max_up,
        download_kib: cli.max_down,
    });
    let client = Client::open(OpenOptions {
        config: config.clone(),
        engine,
        download_dir: None,
        passphrase,
    })
    .await?;

    // Render progress events on a terminal while the command runs.
    let renderer = (!json && std::io::stderr().is_terminal()).then(|| {
        let mut events = Box::pin(client.subscribe());
        tokio::spawn(async move {
            let mut line = render::ProgressLine::default();
            while let Some(e) = events.next().await {
                line.event(&e);
            }
        })
    });
    if !json && let Command::Seed = cmd {
        println!(
            "Serving your saved transfers on port {}. Ctrl-C to stop.",
            cli.port
        );
    }
    if !json
        && let Command::Share {
            until: SeedUntil::Copies { count },
            ..
        } = cmd
    {
        eprintln!(
            "Will seed until {count} friend{} {} a full copy. Ctrl-C to stop early.",
            if *count == 1 { "" } else { "s" },
            if *count == 1 { "has" } else { "have" }
        );
    }

    let cancel = CancellationToken::new();
    let ctrl_c = {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                cancel.cancel();
            }
        })
    };
    let out = client.execute_cancellable(cmd.clone(), &cancel).await;
    ctrl_c.abort();
    if let Some(r) = renderer {
        r.abort();
        render::clear_progress();
    }
    Ok((client, out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("0"), Ok(Duration::ZERO));
        assert_eq!(parse_duration("45"), Ok(Duration::from_secs(45)));
        assert_eq!(parse_duration("15m"), Ok(Duration::from_secs(900)));
        assert_eq!(parse_duration("2h"), Ok(Duration::from_secs(7200)));
        assert!(parse_duration("soon").is_err());
        assert!(parse_duration("5d").is_err());
    }

    #[test]
    fn result_numbers_follow_pages() {
        let dir = tempfile::tempdir().unwrap();
        let config = ConfigDir::new(dir.path());
        config.ensure().unwrap();
        save_last_search(
            &config,
            &LastSearch {
                profile: "home".into(),
                offset: 25,
                infohashes: vec!["a".repeat(40), "b".repeat(40)],
                ..Default::default()
            },
        );
        assert_eq!(resolve_target(&config, "#27").unwrap().0, "b".repeat(40));
        assert!(resolve_target(&config, "1").is_err());
        assert!(resolve_target(&config, "28").is_err());
    }
}
