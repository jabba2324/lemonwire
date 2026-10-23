//! Human-readable rendering of [`Output`]s. `--json` bypasses all of this.

use lemonwire_client_core::{Event, Output, StopReason, TransferState, TransferView};
use lemonwire_proto::api::TorrentEntry;

pub fn size(n: u64) -> String {
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

pub fn rate(bps: u64) -> String {
    format!("{}/s", size(bps))
}

pub fn ago(ts: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let s = (now - ts).max(0);
    match s {
        s if s < 120 => "just now".into(),
        s if s < 7200 => format!("{}m ago", s / 60),
        s if s < 172_800 => format!("{}h ago", s / 3600),
        s => format!("{}d ago", s / 86400),
    }
}

fn until(ts: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let s = ts - now;
    match s {
        s if s <= 0 => "expired".into(),
        s if s < 7200 => format!("in {}m", s / 60),
        s if s < 172_800 => format!("in {}h", s / 3600),
        s => format!("in {}d", s / 86400),
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_owned()
    } else {
        let mut t: String = s.chars().take(n - 1).collect();
        t.push('…');
        t
    }
}

pub fn state(t: &TransferView) -> String {
    match &t.status {
        None if t.paused => "paused".into(),
        None => "saved".into(),
        Some(s) => match &s.state {
            TransferState::Checking => "checking".into(),
            TransferState::Downloading => "downloading".into(),
            TransferState::Seeding => "seeding".into(),
            TransferState::Paused => "paused".into(),
            TransferState::Error(e) => format!("error: {}", truncate(e, 40)),
        },
    }
}

fn results(profile: &str, offset: u32, results: &[TorrentEntry], next: Option<u32>) {
    if results.is_empty() {
        println!("No results on {profile}.");
        return;
    }
    println!(
        "{:>4}  {:<44} {:>10}  {:<12} {:<10} INFOHASH",
        "#", "NAME", "SIZE", "UPLOADER", "ADDED"
    );
    for (i, r) in results.iter().enumerate() {
        println!(
            "{:>4}  {:<44} {:>10}  {:<12} {:<10} {}",
            offset as usize + i + 1,
            truncate(&r.name, 44),
            size(r.size),
            truncate(&r.uploader, 12),
            ago(r.created_at),
            &r.infohash[..12]
        );
    }
    eprintln!();
    if next.is_some() {
        eprintln!("More results: `lemonwire search --more`.");
    }
    eprintln!(
        "Download one with `lemonwire download <#>`; see its files with `lemonwire show <#>`."
    );
}

fn stop_reason(r: &StopReason) -> String {
    match r {
        StopReason::NotSeeded => "not seeded".into(),
        StopReason::CopiesReached { copies } => format!(
            "{copies} other member{} {} a full copy",
            if *copies == 1 { "" } else { "s" },
            if *copies == 1 { "has" } else { "have" }
        ),
        StopReason::RatioReached => "uploaded as much as you downloaded".into(),
        StopReason::TimeLimit => "time limit reached".into(),
        StopReason::NobodyDownloading => "nobody else is downloading".into(),
        StopReason::Cancelled => "stopped".into(),
    }
}

/// One updating status line on stderr, driven by core events.
#[derive(Default)]
pub struct ProgressLine {
    hashing_done: bool,
}

pub fn clear_progress() {
    eprint!("\r\x1b[2K");
}

fn status_line(s: &str) {
    eprint!("\r\x1b[2K{s}");
}

impl ProgressLine {
    pub fn event(&mut self, e: &Event) {
        match e {
            Event::Hashing { done, total, .. } => {
                if self.hashing_done {
                    return;
                }
                let pct = if *total == 0 {
                    100.0
                } else {
                    *done as f64 * 100.0 / *total as f64
                };
                status_line(&format!("Hashing… {pct:>5.1}% of {}", size(*total)));
                if done == total {
                    self.hashing_done = true;
                    eprintln!();
                }
            }
            Event::Progress { status: s } if !s.finished => {
                let pct = if s.total_bytes == 0 {
                    100.0
                } else {
                    s.progress_bytes as f64 * 100.0 / s.total_bytes as f64
                };
                status_line(&format!(
                    "{:<12} {pct:>5.1}% of {}  ↓ {}  {} peer{}",
                    match &s.state {
                        TransferState::Checking => "checking",
                        TransferState::Paused => "paused",
                        _ => "downloading",
                    },
                    size(s.total_bytes),
                    rate(s.download_bps),
                    s.peers,
                    if s.peers == 1 { "" } else { "s" }
                ));
            }
            Event::DownloadFinished { name, .. } => {
                clear_progress();
                eprintln!("Downloaded {name}.");
            }
            Event::Waiting {
                copies,
                wanted,
                leechers,
                ..
            } => status_line(&format!(
                "Seeding… {copies}/{wanted} copies, {leechers} downloading"
            )),
            Event::SeedingBack {
                uploaded,
                total,
                peers,
                ..
            } => status_line(&format!(
                "Seeding back… uploaded {} ({:.2}x), {} peer{}",
                size(*uploaded),
                *uploaded as f64 / (*total).max(1) as f64,
                peers,
                if *peers == 1 { "" } else { "s" }
            )),
            Event::Serving {
                transfers,
                downloading,
                upload_bps,
                download_bps,
                peers,
            } => status_line(&format!(
                "{transfers} transfers ({downloading} downloading)  ↑ {}  ↓ {}  {peers} peers",
                rate(*upload_bps),
                rate(*download_bps)
            )),
            _ => {}
        }
    }
}

pub fn print(out: &Output) {
    match out {
        Output::PublicKey {
            profile,
            public_key,
        } => {
            println!("{public_key}");
            eprintln!(
                "Your public key for profile {profile:?} (fingerprint {}). Send it to the index\n\
                 admin, who adds it with `admin members add --pubkey <key> --name <you>`; then\n\
                 run `lemonwire profile add {profile} <url>`. The secret half stays in your\n\
                 config folder: never share it.",
                lemonwire_proto::keys::fingerprint(public_key)
            );
        }
        Output::Profiles { profiles } => {
            if profiles.is_empty() {
                println!("No profiles. Add one with `lemonwire profile add <profile> <url>`.");
                return;
            }
            println!(
                "{:<14} {:<8} {:<14} {:<32} {:<25} YOUR KEY",
                "PROFILE", "DEFAULT", "MEMBER NAME", "URL", "INDEX KEY"
            );
            for p in profiles {
                println!(
                    "{:<14} {:<8} {:<14} {:<32} {:<25} {}",
                    p.name,
                    if p.default { "yes" } else { "" },
                    truncate(p.member_name.as_deref().unwrap_or("-"), 14),
                    truncate(&p.url, 32),
                    p.server_fingerprint,
                    p.public_key_fingerprint
                );
            }
        }
        Output::ProfileAdded {
            profile,
            pinned_out_of_band,
            joined_with_invite,
            member,
        } => {
            println!("Added profile {:?} for {}.", profile.name, profile.url);
            println!();
            println!(
                "  Index key:  {}  {}",
                profile.server_fingerprint,
                if *pinned_out_of_band {
                    "(matches the key you were given)"
                } else {
                    "(pinned now: check it with your admin)"
                }
            );
            println!(
                "  Your key:   {}  (made for this profile only)",
                profile.public_key_fingerprint
            );
            println!();
            if *member {
                println!(
                    "You're a member{}{}.",
                    profile
                        .member_name
                        .as_deref()
                        .map(|n| format!(" as {n:?}"))
                        .unwrap_or_default(),
                    if *joined_with_invite {
                        ", via your invite"
                    } else {
                        ""
                    }
                );
            } else {
                println!(
                    "Not a member yet. Send this public key to the admin:\n  {}",
                    profile.public_key
                );
            }
        }
        Output::Info {
            profile,
            server,
            member,
        } => {
            println!("Index:        {} ({})", server.name, profile.url);
            println!(
                "Index key:    {} (matches your pin)",
                profile.server_fingerprint
            );
            println!("Profile:      {}", profile.name);
            println!(
                "Your key:     {} ({})",
                profile.public_key_fingerprint, profile.public_key
            );
            println!("Member:       {}", if *member { "yes" } else { "no" });
        }
        Output::Me { profile, member } => {
            println!(
                "{}{} on {} (profile {:?}), joined {}",
                member.name,
                if member.is_admin { " (admin)" } else { "" },
                profile.url,
                profile.name,
                ago(member.created_at)
            );
            println!(
                "  Your key:   {}  {}",
                profile.public_key_fingerprint, member.pubkey
            );
            println!("  Index key:  {}", profile.server_fingerprint);
        }
        Output::Results {
            profile,
            offset,
            results: r,
            next_offset,
        } => results(profile, *offset, r, *next_offset),
        Output::Details { entry } => {
            println!("{}", entry.name);
            println!(
                "  {} · {} · shared by {} {}",
                size(entry.size),
                entry.infohash,
                entry.uploader,
                ago(entry.created_at)
            );
            if !entry.tags.is_empty() {
                println!("  tags: {}", entry.tags.join(", "));
            }
            println!();
            println!("{:>4}  {:>10}  PATH", "#", "SIZE");
            for (i, f) in entry.files.iter().enumerate() {
                println!("{:>4}  {:>10}  {}", i + 1, size(f.size), f.path);
            }
            if entry.files.len() > 1 {
                eprintln!("\nDownload some files with `lemonwire download <#> --files 1,3`.");
            }
        }
        Output::Shared {
            entry,
            already_indexed,
            stopped,
        } => {
            println!(
                "{} {} ({}, {}).",
                if *already_indexed {
                    "Already in the index:"
                } else {
                    "Published"
                },
                entry.name,
                size(entry.size),
                entry.infohash
            );
            match stopped {
                StopReason::NotSeeded => {
                    println!("Not seeding. Friends can download it while you run `lemonwire seed`.")
                }
                StopReason::Cancelled => println!(
                    "Stopped seeding. It's still listed; `lemonwire seed` makes it available again."
                ),
                r => println!("Stopped seeding: {}.", stop_reason(r)),
            }
        }
        Output::Downloaded {
            entry,
            dest,
            seed_back,
        } => {
            println!(
                "Saved {} ({}) to {}",
                entry.name,
                size(entry.size),
                dest.display()
            );
            if let Some(r) = seed_back {
                println!(
                    "Stopped seeding back ({}). `lemonwire seed` shares it again any time.",
                    stop_reason(r)
                );
            }
        }
        Output::Served { transfers } => {
            println!(
                "Stopped serving {transfers} transfer{}.",
                if *transfers == 1 { "" } else { "s" }
            );
        }
        Output::Transfers { transfers } => {
            if transfers.is_empty() {
                println!("No transfers.");
                return;
            }
            println!(
                "{:<36} {:<9} {:<12} {:>7} {:>11} {:>11} {:>5}  INFOHASH",
                "NAME", "KIND", "STATE", "DONE", "DOWN", "UP", "PEERS"
            );
            for t in transfers {
                let (pct, down, up, peers) = match &t.status {
                    Some(s) => (
                        format!(
                            "{:.1}%",
                            if s.total_bytes == 0 {
                                100.0
                            } else {
                                s.progress_bytes as f64 * 100.0 / s.total_bytes as f64
                            }
                        ),
                        rate(s.download_bps),
                        rate(s.upload_bps),
                        s.peers.to_string(),
                    ),
                    None => ("-".into(), "-".into(), "-".into(), "-".into()),
                };
                println!(
                    "{:<36} {:<9} {:<12} {:>7} {:>11} {:>11} {:>5}  {}",
                    truncate(&t.name, 36),
                    format!("{:?}", t.kind).to_lowercase(),
                    state(t),
                    pct,
                    down,
                    up,
                    peers,
                    &t.infohash[..12]
                );
            }
            if transfers.iter().all(|t| t.status.is_none()) {
                eprintln!("\n`lemonwire seed` serves these until you stop it.");
            }
        }
        Output::Swarm {
            infohash,
            seeders,
            leechers,
            complete_members,
        } => {
            println!("Swarm for {infohash}:");
            println!("  seeders:              {seeders}");
            println!("  downloading:          {leechers}");
            println!("  members with a copy:  {complete_members}");
        }
        Output::Members { members } => {
            println!("{:<20} {:<6} {:<10} PUBLIC KEY", "NAME", "ADMIN", "JOINED");
            for m in members {
                println!(
                    "{:<20} {:<6} {:<10} {}",
                    truncate(&m.name, 20),
                    if m.is_admin { "yes" } else { "" },
                    ago(m.created_at),
                    m.pubkey
                );
            }
        }
        Output::Member { member } => {
            println!(
                "Added {}{}.",
                member.name,
                if member.is_admin { " (admin)" } else { "" }
            );
        }
        Output::Invite { invite } => {
            println!("{}", invite.code.as_deref().unwrap_or_default());
            eprintln!(
                "Single-use{} invite {}, expires {}. It includes the index's key, so your\n\
                 friend's client checks it's the right server. They run:\n  \
                 lemonwire profile add <profile> <index url> --invite <code> --name <their name>\n\
                 This is the only time the code is shown.",
                if invite.is_admin { " admin" } else { "" },
                invite.id,
                until(invite.expires_at)
            );
        }
        Output::Invites { invites } => {
            println!("{:<14} {:<6} {:<12} USED BY", "INVITE", "ADMIN", "EXPIRES");
            for i in invites {
                println!(
                    "{:<14} {:<6} {:<12} {}",
                    i.id,
                    if i.is_admin { "yes" } else { "" },
                    until(i.expires_at),
                    i.used_by.as_deref().map(|k| &k[..12]).unwrap_or("-")
                );
            }
        }
        Output::Done { message } => println!("{message}"),
    }
}
