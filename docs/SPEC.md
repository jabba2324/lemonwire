# Lemon Wire — Spec

A small, private file-sharing system for a group of friends. Files move over the
BitTorrent protocol. A central **index server** stores searchable torrent metadata,
runs a members-only tracker, and authenticates members with **Ed25519 key pairs**. A
one-shot **client** (Rust, command-driven) searches any index you have a profile for,
then shares and downloads through an embedded torrent engine. Written entirely in Rust.

Name: **Lemon Wire** (crate/binary prefix `lemonwire`).

This document describes the system as built (v0.1). Section 8 lists what's done and
what's next.

## 1. Goals / non-goals

**Goals**
- Server is configured and administered entirely from a CLI (and, for admins, remotely
  through the API).
- Server is initialised with an **admin public key**; only keys the server knows
  (admin + members the admin adds) can connect.
- Client can hold many **profiles** (one per index), each with its own key pair.
- Client is built on a **command architecture**: every action is a serialisable
  `Command` executed by a core library. The CLI and a future UI are thin front-ends.
- Client is **one-shot**: each command runs and exits. Nothing runs in the background.
- **The index never holds or seeds file data.** It stores metadata and tracks peers.
- Reuse an existing torrent engine; don't implement the BitTorrent wire protocol.
- Few dependencies and the same behaviour on Linux, macOS and Windows.

**Non-goals (v1)**
- Public/open indexes, anonymity, DHT/PEX, web UI, mobile.
- Moderation, ratings, comments.
- Relaying file traffic through the index, or an always-on seeder run by the index.
- OS keychain integration (keys are files; see §5.3).

## 2. Workspace layout

```
lemonwire/
  Cargo.toml                 # workspace (edition 2024, version shared by all crates)
  crates/
    proto/                   # API types, keys/sign/verify, bencode, torrent metainfo
    server/                  # bin `lemonwire-server`: CLI + HTTP API + SQLite + tracker
    client-core/             # lib shared by every front-end: commands, transfers, engine
    client-cli/              # bin `lemonwire`: clap front-end over client-core
    client-gui/              # bin `lemonwire-gui`: egui desktop app over client-core
  docs/                      # SPEC.md (this file), DEPLOY.md
  contrib/                   # example docker-compose.yml, systemd unit for the server
  Dockerfile                 # server image
  .github/workflows/         # ci.yml, release.yml
```

Main dependencies: `tokio`, `axum` (server HTTP), `reqwest` with rustls (client HTTP),
`rusqlite` with `bundled` (SQLite + FTS5), `clap` (derive), `serde`/`serde_json`,
`ed25519-dalek` 2.x, `getrandom`, `sha1`/`sha2`, `base64`, `hex`, `thiserror`/`anyhow`,
`tracing`, `directories`, `tokio-util` (cancellation), and `librqbit` (torrent engine,
behind a cargo feature).
Bencode and `.torrent` building are in-house (`proto::bencode`, `proto::metainfo`).

## 3. Identity and authentication

Terms: an **index key pair** (made at `init`; members pin its public key) and a
**member key pair** per client profile (its public key is the member's identity on
that index). A **profile** is the client's local label for an index. A **member name**
is a member's unique display label on an index, used for "uploader" and for revoking;
it plays no part in authentication. An **invite token** is a single-use ticket that
lets its holder add their own public key to the members list.

- Keys: **Ed25519**, encoded as URL-safe base64 without padding. Public keys are
  validated as curve points; small-order (weak) keys are rejected.
- Every client profile has its **own key pair**, so indexes can't correlate users.
- The server has its own key pair, generated at `init`, so clients can pin it.
- **The server is given an admin public key at init.** That key is the first member
  and is flagged `admin`. The admin generates their key pair with the client
  (`lemonwire keys generate`) and passes only the *public* key to the server.
- Further members are added by an admin, either:
  1. directly: `members add --pubkey <key> --name <name>` (server CLI or remote API), or
  2. via a single-use **invite token** the member redeems with their own public key.
- Member names are unique (case-insensitive), so they can be used to revoke.
- Revoking a member deletes their key, sessions, pending challenges and passkey. The
  last admin can't be revoked.

### Login handshake (mutual auth)

1. Client → `POST /v1/auth/challenge {pubkey}`. The server issues a challenge for any
   well-formed key, member or not, so this endpoint doesn't reveal membership.
2. Server → `{nonce, server_sig}`; `server_sig` signs
   `"lemonwire-v1|server-challenge|{client_pub}|{nonce}"`. The client verifies it
   against the **pinned server key** and aborts on mismatch, before signing anything.
3. Client → `POST /v1/auth/login {pubkey, nonce, signature}`; signature covers
   `"lemonwire-v1|client-login|{server_pub}|{client_pub}|{nonce}"`.
4. Server consumes the nonce first (single-use even if the rest fails), then checks:
   nonce existed, unexpired (120 s), bound to that pubkey; pubkey is a current member;
   signature valid. Returns `{token, expires_at, announce_url}`. Session TTL 12 h.

Domain-separation tags and both public keys in each message prevent replay across
indexes and across steps. Every auth failure returns `401 {"error":"authentication
failed"}`.

Nonces and tokens are 32 random bytes. Session tokens are stored as SHA-256 hashes, so
a copy of the database can't be used to log in.

### Invite codes

An invite is shown once, as a code `lw1.<token>.<index public key>`. The server stores
only `sha256(token)`. Redeeming the code checks the index key it carries exactly like
`--server-key`, so joining with an invite involves no trust on first use. A tampered
key (or a URL pointing at another server) fails with `ServerKeyMismatch`, without
spending the invite.

### Pinning the index key

`profile add` fetches `GET /v1/info` and pins the server key, showing its fingerprint
(`sha256(pubkey_b64)`, first 10 bytes as hex in groups of four, e.g.
`9fbc:eb17:5058:222d:2424`). With `--server-key <key>`, or an invite code, the client
checks the presented key against that value and refuses to add the profile on
mismatch. Without either, it trusts the key on first use and says so. Every later
login verifies the server against the pin.

### Transport

The client refuses plain `http://` index URLs, and plain-http announce URLs, unless the
host is local, on a private network, link-local, in Tailscale's `100.64.0.0/10` or
`fd7a:115c:a1e0::/48`, or named `localhost`, `*.local` or `*.ts.net`; `--insecure`
(`allow_insecure`) overrides this per profile. Otherwise session tokens and passkeys
would cross the internet unencrypted.

## 4. Server

### 4.1 CLI

```
lemonwire-server [--data <dir>] <command>      # --data / LEMONWIRE_DATA, default ./data

init   --index-name <name>
       --admin-pubkey <base64>                # REQUIRED: first member, flagged admin
       --admin-name <member name>             # default "admin"
       --public-url <https://index.example>
       --tracker-url <https://index.example>  # public base URL of the tracker
info                                          # name, server pubkey + fingerprint, URLs
config [--public-url U] [--tracker-url U]     # change URLs after init
members list
members add    --pubkey <key> --name <name> [--admin]
members revoke <pubkey | unique prefix (6+ chars) | name>
members rotate-passkey <member>
invite create  [--admin] [--ttl-hours 24]     # prints a single-use token (1 h – 30 days)
invite list
torrents list  [--limit 50]
torrents remove <infohash>
serve  [--bind 0.0.0.0:8080] [--tracker-bind 0.0.0.0:6969]
       [--trust-proxy]                         # LEMONWIRE_TRUST_PROXY
       [--nat-public-addr <ip|hostname>]       # LEMONWIRE_NAT_PUBLIC_ADDR, see §4.4
       [--max-shares-per-member 1000]          # 0 = no limit
```

`init` refuses to run twice on the same data dir and validates the admin key. The data
dir is created `0700` and contains `index.db` (`0600`) and `server.key` (`0600`, the
server's secret key). Admin commands work on the database directly and are safe to run
while `serve` is running.

### 4.2 Storage (SQLite, WAL mode)

```
meta(key PK, value)            -- name, server_pub, tracker_url, public_url
users(pubkey PK, name UNIQUE NOCASE, is_admin, passkey_hash UNIQUE, passkey_gen,
      created_at)
invites(token_hash PK, is_admin, created_at, expires_at, used_by NULL)
challenges(nonce PK, pubkey, expires_at)
sessions(token PK  -- sha256 of the token --, pubkey, expires_at)
torrents(infohash PK, name, size, files_json, tags_json, uploader_pubkey,
         uploader_name, created_at, torrent_blob)          -- announce stripped
torrents_fts  FTS5(infohash UNINDEXED, name, tags, files)  -- unicode61, no diacritics
```

Search: split the query on non-alphanumerics (at most 16 tokens), lowercase, build
quoted prefix terms `"tok"*` ANDed together (no FTS syntax can get through), order by
FTS `rank`. An empty query returns the most recent entries. Either can be limited to
one uploader (`mine`), and paged with `offset`; the server fetches one extra row to
decide `next_offset`. Every minute the server
purges expired challenges, sessions and unused invites.

Invite redemption is atomic: the invite is marked used and the member created in one
transaction, so a failed redemption (e.g. name taken) doesn't burn the invite.

**Secrets at rest.** The database holds nothing that lets someone in on its own:
- session and invite tokens are stored as `sha256` hashes;
- passkeys are derived, never stored: `passkey = HMAC-SHA256(server secret key,
  "lemonwire-v1|passkey|<member pubkey>|<passkey_gen>")`. Only `sha256(passkey)` is
  stored, which is what the tracker looks up. `rotate-passkey` bumps `passkey_gen`;
- the server's secret key lives in `server.key`, not the database.

Databases from v0.1 (secret key in `meta`, plaintext passkeys and invite tokens) are
migrated on open: the key moves to `server.key`, invites are re-keyed by hash, and every
member gets a new derived passkey at their next login.

Each member may have at most `--max-shares-per-member` entries (default 1,000);
publishing beyond that is a `403`.

### 4.3 HTTP API (JSON, `/v1`)

Public: `GET /info`, `POST /join`, `POST /auth/challenge`, `POST /auth/login`.
Everything else needs `Authorization: Bearer <token>`.

| Method | Path | Notes |
|---|---|---|
| GET | `/info` | `{protocol, name, server_pubkey}` |
| POST | `/join` | `{invite, pubkey, name}` → `201 Member` (`display_name` accepted as an alias) |
| POST | `/auth/challenge` | see §3 |
| POST | `/auth/login` | see §3 |
| GET | `/me` | the caller's `Member` (name, admin flag) |
| GET | `/search?q=&limit=&offset=&mine=` | `{results: [TorrentEntry], next_offset?}`; limit default 25, max 100; offset max 10,000; `mine=true` = caller's uploads only |
| POST | `/torrents` | `{tags, torrent_b64}` → `201 TorrentEntry`; `409` if already indexed |
| GET | `/torrents/{infohash}` | `{entry, torrent_b64}` with the **caller's** announce URL injected |
| DELETE | `/torrents/{infohash}` | uploader or admin → `204` |
| GET | `/admin/members` | admin only → `{members: [Member]}` |
| POST | `/admin/members` | admin only, `{pubkey, name, is_admin}` → `201 Member` |
| DELETE | `/admin/members/{selector}` | admin only; name, key or unique prefix → `204` |
| POST | `/admin/members/{selector}/rotate-passkey` | admin only → `204` |
| GET | `/admin/invites` | admin only → `{invites: [Invite]}` |
| POST | `/admin/invites` | admin only, `{is_admin, ttl_hours}` → `201 Invite` |

```
TorrentEntry = {infohash, name, size, files: [{path, size}], tags, uploader, created_at}
Member       = {pubkey, name, is_admin, created_at}
Invite       = {id, code?, is_admin, created_at, expires_at, used_by}
               -- `code` only in the create response; `id` is a hash prefix
```

Errors are `{"error": "message"}` with a matching status (400, 401, 403, 404, 409, 429,
500). Request bodies are limited to 16 MB. `torrent_b64` uses the same URL-safe,
unpadded base64 as keys.

Tags are trimmed, lowercased and de-duplicated: at most 16, each up to 32 letters,
digits, `-`, `_` or `.`. Display names are 1–64 characters with no control characters.

### 4.4 Torrent handling and tracker

- **The server parses every published `.torrent` itself** and derives infohash (SHA-1 of
  the exact `info` bytes), name, size and file list. Client metadata is never trusted.
- **Rejected:** torrents without `info.private = 1`; v2-only torrents; unsafe names or
  path components (empty, `.`, `..`, `/`, `\`, control characters, over 255 bytes);
  piece counts that don't match the size; torrents over 10 MB or 10,000 files.
- **Stored stripped:** only `info` (byte for byte) and `creation date` are kept.
  `announce`, `announce-list`, `comment`, `created by`, `url-list` and anything else are
  dropped, so no member's passkey ends up in shared metadata.
- **On fetch**, `announce = <tracker_url>/announce?passkey=<caller's passkey>` is
  injected. The infohash is unaffected because `info` is copied verbatim.
- **Embedded HTTP tracker** on `--tracker-bind`:
  - `GET /announce` (info_hash, peer_id, port, uploaded, downloaded, left, event,
    numwant) returns bencoded compact `peers` (IPv4) and `peers6` (IPv6), plus
    `complete`/`incomplete`. Failures are a 200 with `failure reason`.
  - **Requires a current member's `passkey`** and **only tracks infohashes in the index**.
  - Interval 120 s, min interval 30 s; peers that stop announcing expire after 5 min.
    The timings are short because one-shot clients come and go.
  - The caller is never in its own peer list, and seeders aren't sent other seeders.
    numwant defaults to 50 (max 200); at most 5,000 peers per torrent.
  - A peer announcing `lw_partial=1` (a selective download) never counts as a seeder
    or a full copy, even with `left=0`.
  - `event=stopped` removes the peer. Peers of revoked members and removed torrents are
    dropped immediately (API) or within a minute (CLI).
  - `GET /scrape` (passkey required, registered infohashes only) returns `complete`,
    `incomplete`, `downloaded` (always 0) and the extension **`complete_members`**: the
    number of *distinct members* holding a full copy. Clients use it to tell when a
    friend, rather than an earlier session of their own, has the whole file.
  - Peers are kept in memory only.
- **LAN members** (`--nat-public-addr`): when the index shares a LAN with some members
  (say, the admin's desktop is the index host), they announce from private addresses
  that outside members can't reach. With this option set to the LAN's public IP or a
  DDNS hostname (re-resolved every minute), outside callers are given that public
  address for private-address peers, while LAN callers still get the private one.

### 4.5 Operational

- `tracing` logs to stderr: method, path, status and latency only. Tokens, passkeys,
  query strings, headers and secret keys are never logged.
- Graceful shutdown on Ctrl-C or SIGTERM.
- Per-IP rate limit on `/auth/*` and `/join`: 30 requests a minute.
- Runs behind a TLS reverse proxy on one hostname: `/v1/*` to the API port, `/announce`
  and `/scrape` to the tracker port, and the same URL for `--public-url` and
  `--tracker-url`. With `--trust-proxy`, client IPs come from `X-Real-IP` or the last
  `X-Forwarded-For` hop; without a proxy, leave it off. The proxy must not keep access
  logs with query strings (they contain passkeys). See `docs/DEPLOY.md`.
- Ships a two-stage `Dockerfile` (Debian slim, non-root uid 10001, `/data` volume) and
  a hardened `DynamicUser` systemd unit in `contrib/systemd/`.

## 5. Client

### 5.1 Command architecture and the shared core

`client-core` is **the** client: the `lemonwire` CLI and the GUI are thin front-ends
over it and share all behaviour, including how long to seed, resuming, file
selection, and following the saved transfer list. A front-end builds `Command`s,
runs them, renders `Output`s and `Event`s, and cancels.

```rust
// Making a client. `open` builds the librqbit engine (cargo feature `librqbit`) after
// taking the config dir's engine lock; `new` takes an engine you supply (tests: MockEngine).
Client::open(OpenOptions { config, engine: Option<EngineSettings>, download_dir }).await?;
Client::new(ClientOptions { config, engine: Option<Arc<dyn TorrentEngine>>, download_dir })?;
EngineSettings { port: 6881, upnp: true, upload_kib: None, download_kib: None }

impl Client {
    pub async fn execute(&self, cmd: Command) -> Result<Output, ClientError>;
    pub async fn execute_cancellable(&self, cmd: Command, cancel: &CancellationToken)
        -> Result<Output, ClientError>;
    pub fn subscribe(&self) -> impl Stream<Item = Event>;   // progress for front-ends
    pub async fn transfers(&self) -> Result<Vec<TransferView>>;
    pub async fn sync(&self) -> Result<usize>;               // align engine with the list
    pub async fn shutdown(&self);
}

#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {                       // `profile: None` = the default/only profile
    KeysGenerate { profile }, ProfileList, ProfileAdd { profile, url, server_key, invite,
    member_name }, ProfileRemove { name }, ProfileSetDefault { name },
    Info { profile }, Whoami { profile },
    Search { profile, query, limit, offset, mine },
    Details { profile, infohash },                       // entry + file list
    Share { profile, path, tags, until: SeedUntil },     // long-running
    Download { profile, infohash, dest, files: Option<Vec<usize>>,
               seed_back: Option<SeedBack> },            // long-running
    Seed,                                                // long-running, until cancelled
    Unpublish { profile, infohash }, Swarm { profile, infohash },
    Transfers, Pause { infohash }, Resume { infohash }, Cancel { infohash, delete_data },
    SetLimits { upload_kib, download_kib },              // KiB/s, None = unlimited
    MembersList { profile }, MembersAdd { profile, pubkey, name, admin },
    MembersRevoke { profile, member },
    InviteCreate { profile, admin, ttl_hours }, InviteList { profile },
}

#[serde(tag = "mode")] enum SeedUntil { PublishOnly, Copies { count }, Cancelled }
struct SeedBack { ratio: f64, max_secs: u64 }    // default 1.0 and 900
#[serde(tag = "reason")] enum StopReason { NotSeeded, CopiesReached { copies },
    RatioReached, TimeLimit, NobodyDownloading, Cancelled }

#[serde(tag = "type", rename_all = "snake_case")]
pub enum Output {
    PublicKey { profile, public_key }, Profiles { profiles },
    ProfileAdded { profile, pinned_out_of_band, joined_with_invite, member },
    Info { profile, server, member }, Me { profile, member },
    Results { profile, offset, results, next_offset }, Details { entry },
    Shared { entry, already_indexed, stopped: StopReason },
    Downloaded { entry, dest, seed_back: Option<StopReason> }, Served { transfers },
    Swarm { infohash, seeders, leechers, complete_members },
    Transfers { transfers }, Members { members }, Member { member },
    Invite { invite }, Invites { invites }, Done { message },
}

#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Hashing { path, done, total },              // after each piece while sharing
    Published { infohash, name },
    TransferAdded { infohash, name }, TransferRemoved { infohash },
    Progress { status: TransferStatus },        // ~1/s for transfers a command watches
    Waiting { infohash, copies, wanted, leechers },   // share waiting for copies
    DownloadFinished { infohash, name },
    SeedingBack { infohash, uploaded, total, peers },
    Serving { transfers, downloading, upload_bps, download_bps, peers },  // `Seed`
}
```

Rules:
- No printing or prompting inside core. Commands in; `Output`, `Event` and
  `ClientError` out.
- Everything is serde-able: `lemonwire run '<json>'` executes a raw `Command`, and a
  GUI (e.g. Tauri) can pass commands, outputs, events and errors straight through.
  `ClientError` serialises as `{"kind": "...", "message": "..."}` with stable kinds
  (`not_a_member`, `server_key_mismatch`, `engine_busy`, `cancelled`, …).
- **Cancellation**: cancelling a share while it hashes stops hashing; while it seeds,
  it returns `Shared { stopped: Cancelled }`. Cancelling a download returns
  `ClientError::Cancelled` and keeps the saved transfer to resume. `Seed` only ends
  when cancelled.
- **One engine per config dir**: `open`/`new` with an engine take an exclusive lock on
  `<config>/engine.lock` and fail with `EngineBusy` if another process (the CLI or
  the GUI) holds it. Clients without an engine (search, admin, profiles…) can run
  alongside.
- Sessions are cached per profile; on a `401` with a cached session the client drops
  its sessions and retries once (after revocation that reports "not a member").

### 5.2 CLI

```
lemonwire [-p profile] [--json] [--config-dir D] [--port 6881] [--no-upnp]
          [--max-up KIB] [--max-down KIB] <command>

keys generate                                   # key for --profile (default "default")
profile add <profile> <url> [--server-key K] [--invite CODE] [--name <member name>]
            [--insecure]
keys protect | unprotect                        # passphrase on --profile's key
profile list | remove <name> | default <name>
info | whoami
search [query…] [--limit N] [--offset N] [--mine]   # remembers results for <#>
search --more                                   # next page of the last search
show <#|infohash>                               # entry and numbered file list
share <path> [--tag t]… [--copies 1 | --forever | --publish-only]
download <#|infohash> [--dest dir] [--files 1,3] [--seed-ratio 1.0] [--seed-time 15m]
                      [--no-seed]
seed
unpublish <infohash>
swarm <#|infohash>
transfers | pause <ih> | resume <ih> | cancel <ih> [--delete-data]   # prefixes OK
admin members list | add --pubkey K --name N [--admin] | revoke <member>
admin invite create [--admin] [--ttl-hours H] | list
run '<json command>'
```

Result numbers continue across pages (page two starts at 26 with the default limit).
File numbers in `show` and `--files` start at 1. Ctrl-C cancels the running command.
With `--json`, errors print as `{"error": {"kind", "message"}}`. The environment
variables `LEMONWIRE_CONFIG_DIR`, `LEMONWIRE_PORT`, `LEMONWIRE_NO_UPNP`,
`LEMONWIRE_MAX_UP`, `LEMONWIRE_MAX_DOWN` and `LEMONWIRE_LOG` are also read.

### 5.2a Desktop app

`lemonwire-gui` (egui/eframe, glow renderer; no GTK or web view) embeds `client-core`
like the CLI, with its own torrent engine while open:

- **Serving while open.** It runs `Seed` for as long as the window is open, so every
  saved transfer is shared, and transfers that `Share` and `Download` start stay in
  the engine after those commands return. It shares with `SeedUntil::PublishOnly` (the
  running `Seed` picks the share up) and downloads with `seed_back: None`. Closing the
  window while anything is shared asks first ("Quit" or "Keep running", which
  minimises). If another process holds the engine lock, the app opens without an
  engine: browsing and admin work, transfers wait, and "Try again" retries.
- **Pages:** join (invite code, or create a key for the admin to add), browse/search
  with a details pane (tags, file checklist for selective downloads, live swarm
  counts, remove for the uploader or an admin), transfers (progress, speeds, pause,
  resume, open folder, remove), members (admins: invites, add by key, revoke) and
  settings (profile and fingerprints, download folder, speed limits, port, UPnP, key
  passphrase, theme). A protected key prompts for its passphrase when first needed
  (`Client::set_passphrase`).
- **State:** profiles, keys and transfers are shared with the CLI (same config dir,
  `LEMONWIRE_CONFIG_DIR` honoured); the app's own preferences live in `gui.json`.
- **Dependencies:** eframe/egui 0.36, `egui_extras` (tables), `egui-phosphor` (icons),
  `egui-notify` (toasts), `rfd` (native file dialogs; xdg-desktop-portal on Linux).
- **Tests:** `egui_kittest` drives the real app headlessly against an in-process index
  (join screen, unlock, browse, share with tags).

### 5.3 Profiles, keys and local state

All client state is in the OS config dir (`directories`; `~/.config/lemonwire` on
Linux), created `0700` on Unix:

| File | Contents |
|---|---|
| `profiles.json` | `[{name, url, server_pubkey (pinned), member_name, public_key, default}]` |
| `keys/<profile>.key` | the profile's secret key (`0600` on Unix; on Windows the user profile's default ACL, which only the user, SYSTEM and Administrators can read); optionally passphrase-protected |
| `transfers.json` | saved transfers, each with its `.torrent` including the member's announce URL (`0600`) |
| `last_search.json` | the last search (query, page, infohashes), for `<#>` and `search --more` (CLI only) |
| `engine.lock` | held while a process runs the torrent engine (see §5.1) |
| `engine/` | torrent engine scratch space |

Files are written atomically (temp file and rename). Secret keys never go in
`profiles.json` or logs. Profile names are letters, digits, `-` and `_`, up to 64.

**Passphrases (optional).** `keys protect` encrypts a key file: Argon2id (default
parameters) derives a 32-byte key from the passphrase and a random 16-byte salt, and
ChaCha20-Poly1305 seals the secret key (`lwenc1:<salt>:<nonce>:<ciphertext>`). The
client's passphrase (`OpenOptions::passphrase`; the CLI reads `LEMONWIRE_PASSPHRASE` or
asks, up to three times) opens protected keys and protects new ones. Errors are
`PassphraseRequired` and `WrongPassphrase`.

`keys generate` is idempotent: run again for the same profile, it prints the existing
public key rather than replacing a key that may already be with an admin.

`ProfileAdd` flow:
1. reuse the key from `keys generate`, or make one;
2. `GET /info` and pin the key (or verify `--server-key`, refusing on mismatch);
3. with `--invite`, `POST /join` (member name defaults to the profile name);
4. try a login: success means the key is already a member, and the client records the
   member name the index has for it (`GET /me`); `401` means the user should send their
   public key to an admin. The profile is saved either way. `Whoami` refreshes the
   recorded member name.

### 5.4 Transfers

Nothing runs in the background. Commands that move data run a torrent engine for as
long as they run. A file is downloadable while at least one member who has it is
running `Share`, `Download` or `Seed` (the CLI or the GUI).

**Share:** canonicalise the path; hash the file or folder into SHA-1 pieces (piece
length a power of two from 16 KiB to 16 MiB, aiming for at most ~1,500 pieces;
symlinks and special files skipped), emitting `Hashing`; build a `.torrent` with
`private=1` and the member's announce URL; `POST /torrents` (a `409` means it's
already indexed, which is fine); save it to `transfers.json`; then by `until`:
- `PublishOnly`: return (`stopped: NotSeeded`); serve it later with `Seed`;
- `Copies { count }` (the default, count 1): seed, emitting `Progress` and, every
  5 s, `Waiting` from the tracker's scrape, until `complete_members - 1 >= count`;
- `Cancelled`: seed until cancelled (e.g. while a GUI window stays open).

The engine stops seeding it when the command returns; the record stays.

**Download:** fetch the torrent; check it locally too (same infohash, private, every
path inside the destination via `safe_join`); refuse if the target already exists,
unless this resumes a saved download (same folder only; downloading something you're
sharing is refused); save to `transfers.json`; download, emitting `Progress`, then
`DownloadFinished`. Optionally only some files (`files`, indexes into the entry's file
list; kept when resuming). Then, with `seed_back`, keep seeding (emitting
`SeedingBack`) until the upload reaches `ratio` × the size, `max_secs` pass, or the
tracker reports nobody else downloading twice in a row 15 s apart. Either way a
finished download stays up long enough for one announce (the engine's
`completion_grace`), so sharers waiting for copies hear about it. Cancelling keeps the
record; running `Download` again (or `Seed`) resumes it. Downloads are never opened or
executed. With file selection, librqbit leaves unselected files as sparse placeholders
(full apparent size, almost no disk use).

**Selective downloads aren't copies.** The core adds `lw_partial=1` to the announce URL
of a download with `files` (outside `info`, so the infohash is unchanged); the tracker
never counts such a peer as a seeder or full copy.

**Seed:** start every saved transfer, then every 5 s re-read `transfers.json` (other
commands and processes may change it) and apply new transfers, cancellations and
pause/resume; emit `Serving` and `Progress`; until cancelled.

**Transfers, Pause, Resume, Cancel** edit `transfers.json` and apply to this client's
engine if it's running them. `Cancel { delete_data }` deletes downloaded data, never
the original of something you shared. **Unpublish** removes the entry from the index
(uploader or admin) and the local record.

### 5.5 Torrent engine

```rust
#[async_trait]
pub trait TorrentEngine: Send + Sync {
    async fn add_seed(&self, torrent: &[u8], data_path: &Path) -> Result<TransferId>;
    async fn add_download(&self, torrent: &[u8], dest: &Path,
                          only_files: Option<&[usize]>) -> Result<TransferId>;
    async fn status(&self) -> Result<Vec<TransferStatus>>;
    async fn pause(&self, id: TransferId) -> Result<()>;
    async fn resume(&self, id: TransferId) -> Result<()>;
    async fn remove(&self, id: TransferId, delete_data: bool) -> Result<()>;
    async fn set_limits(&self, upload_bps: Option<u32>, download_bps: Option<u32>)
        -> Result<()>;                                  // default: no-op
    fn completion_grace(&self) -> Duration;             // default: zero
    async fn shutdown(&self);
}
```

`TransferStatus` has id, infohash, name, state (checking, downloading, seeding, paused,
error), progress/total/uploaded bytes, up/down rates, peer count and `finished` (for a
selective download, finished means the selected files are complete).

- **`RqbitEngine`** (cargo feature `librqbit`, on by default in the CLI): librqbit 9
  with `rust-tls`. DHT, local service discovery and session persistence are off
  (`transfers.json` is the source of truth); librqbit also skips PEX for private
  torrents. It announces every 10 s (`completion_grace` is 12 s). Data is checked and
  resumed in place (`overwrite: true`); client-core has already refused to clobber
  unrelated files. TCP listener on the configured port, falling back to a random port
  if it's busy; optional UPnP and speed limits (changeable while running).
- **`MockEngine`**: records calls and lets tests complete transfers.
- `.torrent` files are built in-house, because librqbit's builder can't make private
  torrents.

### 5.6 Networking / NAT

Private swarms are small (often two people) and there is no DHT, PEX or relay, so in
each pair at least one peer must accept incoming connections.

- While `share`, `download` or `seed` runs, the client asks the router to open `--port`
  via **UPnP** (on by default; `--no-upnp` to disable). The mapping is temporary.
- The local firewall must allow the port, and must let UPnP discovery replies in (on
  firewalld: the `upnp-client` service). Without that, discovery finds no router.
- Without UPnP: forward the port by hand.
- Members behind a VPN without port forwarding, or on mobile data, can't accept
  connections but can still swap with anyone who can. For groups where that's common,
  run everyone on Tailscale/WireGuard.
- When members share a LAN with the index, see `--nat-public-addr` (§4.4).

## 6. Security checklist

**Identity and login**
- Ed25519 keys; weak keys rejected; one key pair per profile.
- Mutual auth with a pinned index key; domain-separated signatures binding both keys.
- Invite codes carry the index key, so joining needs no trust on first use.
- Nonces single-use (consumed before checking), 120 s; session tokens random 32 bytes,
  12 h TTL, deleted on revoke.
- Same `401` body for every auth failure; challenges issued for any well-formed key.
- Per-IP rate limit on `/auth/*` and `/join`.

**Secrets**
- Server: secret key only in `server.key` (`0600`); session tokens, invite tokens and
  passkeys stored only as hashes; passkeys derived per member and rotatable.
- Client: secret keys in `0600` files, optionally passphrase-encrypted (Argon2id +
  ChaCha20-Poly1305); `transfers.json` (which holds announce URLs) is `0600`.
- Plain `http://` to public hosts refused unless the user opts in per profile.
- Never logged: server logs carry method, path and status only. The CLI caps
  librqbit's tracker and session logging and the HTTP stack at info/debug, because they
  print tracker URLs (and so passkeys) at trace, unless `LEMONWIRE_LOG_SECRETS=1`.
  Scrape errors are reported without their URL.
- `Debug` for key pairs, login responses and invites redacts secrets.

**Torrents**
- Server derives all metadata; enforces `private=1`; sanitises names and paths; strips
  everything outside `info` except `creation date`.
- Passkeys never stored in shared `.torrent` data; injected per requester; the tracker
  enforces them and only serves indexed torrents.
- Clients re-check paths against the destination, refuse to overwrite existing files,
  and never execute or open downloaded content.

**Limits**
- Request body 16 MB, torrent 10 MB, 10,000 files, 16 tags × 32 chars, names 64,
  5,000 peers per torrent, 1,000 shares per member (configurable).

**Supply chain and deployment**
- CI runs `cargo deny` (RustSec advisories, licences, sources; exceptions explained in
  `deny.toml`); Dependabot proposes updates weekly.
- Releases ship `SHA256SUMS` signed with minisign (`minisign.pub` in the repo).
- The server image runs as a non-root user with a read-only root filesystem, no Linux
  capabilities and `no-new-privileges` (example compose file).

**Known limits (BitTorrent itself)**
- Peers don't authenticate each other: anyone who knows an infohash and a sharing
  member's address can connect to that member directly. The tracker only controls who
  *finds* whom; revoking someone stops them finding peers, not connecting to ones they
  already know. Only an encrypted private network (Tailscale/WireGuard) closes this.
- Members see each other's IP addresses.
- File names, sizes and tags are visible to every member.

## 7. Testing and CI

- `proto`: key encode/decode and weak-key rejection; sign/verify round-trips;
  wrong-server, wrong-client, wrong-nonce and cross-step rejection; bencode strictness;
  torrent parse/strip/inject keeping the infohash; builder piece hashes; `safe_join`.
- `server`: unit tests for init-once, FTS query sanitising, single-use invites, revoke
  killing sessions and protecting the last admin, tags, IP extraction, LAN address
  advertising, tracker query parsing. Integration tests run a real server on ephemeral
  ports with a temp data dir: handshake and failure bodies, nonce reuse, publish/search/
  fetch/delete permissions, admin endpoints, invites, revocation, and the tracker
  (passkeys, registration, peer lists, scrape, stop).
- `client-core`: command tests against a real index with `MockEngine`: bootstrap with
  `keys generate`, pinning and mismatch, changed server key, serialised errors,
  invites and direct add, whoami, paging and `mine`, details, publish-only,
  selective downloads (kept on resume), seed-back stopping on ratio, refusing other
  destinations and your own shares, cancelling downloads and shares, `Seed` following
  pause/cancel from other commands, speed limits, the engine lock, existing
  destinations. `server::testing::TestIndex` provides the throwaway index.
- End to end (`client-core/tests/e2e.rs`, needs `librqbit`): init an index with an admin
  key, add a member, share a multi-file folder with `Copies { count: 1 }`, search,
  download over localhost through the embedded tracker with two real engines, compare
  bytes, and check the share stops by itself with `CopiesReached`.
- Security: the server's database file contains no usable secret after init, invites,
  sessions and logins (`server.key` holds the key, `0600`); passkey rotation retires the
  old passkey; v0.1 databases migrate; share quotas; tampered invite codes are refused
  without spending the invite; plain-http rules; passphrase-protected keys (wrong,
  missing, removed); and a smoke test confirming trace-level client logs contain no
  passkey.
- `client-cli`: clap definition check, duration parsing, result numbering across pages.
- **CI** (`.github/workflows/ci.yml`): `cargo deny check`, `cargo fmt --check` and
  `cargo clippy --all-targets --all-features -D warnings` on Linux;
  `cargo test --workspace --all-features` on Linux, macOS and Windows.
- **Releases** (`.github/workflows/release.yml`): pushing a tag `vX.Y.Z` matching the
  workspace version builds `lemonwire` and `lemonwire-server` for x86_64 and arm64
  Linux, Apple Silicon macOS and x86_64 Windows, packages each with README and
  LICENSE (`.tar.gz`, `.zip` on Windows), and publishes a GitHub release with
  `SHA256SUMS`. Running the workflow by hand builds everything without publishing.

## 8. Milestones

1. ✅ `proto` crate + auth tests.
2. ✅ Server: `init` with `--admin-pubkey`, `info`, `members`, DB, `/info`, challenge/login.
3. ✅ Server: publish/search/fetch with torrent parse/strip/inject, FTS.
4. ✅ Server: embedded passkey-enforcing tracker.
5. ✅ Client-core: profiles, keys, pinning, login, search, share, download with a mock
   engine; CLI front-end.
6. ✅ librqbit engine; end-to-end test; one-shot transfers and `seed`.
7. ✅ Admin commands over the API; invites; docs, Dockerfile, systemd unit; CI on three
   platforms; release builds.
7½. ✅ GUI-ready core: all transfer behaviour in client-core, cancellation, events,
   engine lock, serialisable errors, paging, `mine`, `/me`, details, selective
   downloads, speed limits; Linux arm64 builds.
8. ✅ Desktop app (egui) driving the same `Command`s, sharing while open (§5.2a).
9. ⬜ Tray icon (keep sharing with the window closed); macOS app bundle; install
   packages.

## 9. Decisions and open questions

**Decided**
- Tracker: embedded in the server, because only it can enforce passkeys.
- Commands run in-process; the client is one-shot with no daemon or socket. A UI would
  embed `client-core` and run its own engine while open.
- Sharing works for single files and folders; piece size is automatic (§5.4).
- Secret keys are files on every platform, for fewer dependencies and identical
  behaviour.
- The index never seeds or relays.
- UPnP is on by default so most home networks need no router setup.
- GUI toolkit: egui, for a pure-Rust, single-binary app with no web view or GTK.
- The app shares while open (`Seed` runs the whole time), rather than the CLI's
  "until one copy" default.

**Open**
- musl (static) Linux builds.
- Signed and notarised macOS binaries; Windows code signing (release checksums are
  already minisign-signed).
- A tray icon so the app keeps sharing with its window closed. Linux tray support
  differs by desktop (GNOME needs an extension), so this needs care to keep the app
  free of GTK.
