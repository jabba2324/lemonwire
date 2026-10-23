# Lemon Wire

Private file sharing for a group of friends. Files move over BitTorrent; a small
**index server** keeps searchable metadata and only lets in members whose Ed25519
public keys it knows. Everything is Rust.

```
  friend A ── lemonwire ─┐    HTTPS /v1 (search, publish, fetch)    ┌─ lemonwire ── friend B
                         ├──────────────►  index server  ◄──────────┤
                         │    /announce?passkey=… (tracker)         │
                         └───────── BitTorrent, peer to peer ───────┘
```

- **Members only.** The server is initialised with an admin's public key; the admin adds
  friends by key or with single-use invites. Login is a signed challenge in both
  directions, so clients also check they're talking to the right server.
- **Private swarms.** Every torrent must be `private=1` (no DHT or PEX). The embedded
  tracker only answers members' personal passkeys, and only for torrents in the index.
- **Server-derived metadata.** The server parses each `.torrent` itself, rejects unsafe
  paths, strips announce URLs and comments, and injects the downloader's own announce
  URL on fetch.
- **One key pair per index.** Each client profile has its own key, so indexes can't link
  you across groups.

- **A desktop app and a CLI.** The app shares everything while it's open. The CLI is
  one-shot: each command runs and exits, nothing runs in the background. Either way
  the index never holds or seeds file data.

The full specification is [docs/SPEC.md](docs/SPEC.md); deployment notes are in
[docs/DEPLOY.md](docs/DEPLOY.md).

## Install

Download a build for Linux (x86_64 or arm64), macOS (Apple Silicon) or Windows (x86_64)
from the [releases page](../../releases): `lemonwire-gui-*` is the desktop app,
`lemonwire-*` the command-line client, and `lemonwire-server-*` is only needed on the
index host. Check downloads against `SHA256SUMS`. On macOS, the binaries aren't signed,
so clear the quarantine flag once: `xattr -d com.apple.quarantine ./lemonwire-gui`.

Or build from source:

```sh
cargo install --path crates/client-gui      # `lemonwire-gui`, the desktop app
cargo install --path crates/client-cli      # `lemonwire`, the command-line client
cargo install --path crates/server          # `lemonwire-server`, only on the index host
```

or build the server image: `docker build -t lemonwire-server .`

### Releasing

Bump `version` in the root `Cargo.toml` (and run `cargo update -w` to refresh
`Cargo.lock`), commit, then tag and push: `git tag -a v0.2.0 -m v0.2.0 && git push
origin v0.2.0`. The release workflow checks the tag matches the version, builds every
platform, and publishes the archives with `SHA256SUMS`.

## How membership works

Like SSH, there are two kinds of key pair, and only public halves ever travel:

| | The index's key pair | Your key pair |
|---|---|---|
| Proves | "this really is your index" | "this really is you" |
| Like SSH's | host key (`known_hosts`) | user key (`authorized_keys`) |
| Made by | `lemonwire-server init`, once | `lemonwire profile add` (or `keys generate` first) |
| Public half goes | to every member, who **pin** it | onto the index's **members list** |

Every login is checked both ways: the index signs a challenge that your client checks
against the pinned key, and your client signs it back with your key. You get a separate
key pair for each index you join, so two indexes can't tell you're the same person.
Fingerprints (like `9fbc:eb17:5058:222d:2424`) are short forms of either key, for
comparing by eye.

A few words used throughout:

- **Profile:** your own local label for an index (`grove`). Only you see it.
- **Member name:** your name *on* an index (`sam`), shown as uploader and used by admins
  to revoke. It's a label, not a login. Set it with `--name`.
- **Invite code:** a single-use ticket (`lw1.…`) that lets someone add *their own* public
  key to the members list. It also carries the index's key, so the new member's client
  checks it's the right server. After joining, login is by key as usual.

There are two ways to join, and both end with your public key on the members list:

```sh
# A. With an invite: the admin sends you a token
admin$  lemonwire admin invite create
you$    lemonwire profile add grove https://index.example --invite <code> --name sam

# B. By key: you send the admin your public key
you$    lemonwire -p grove keys generate          # prints your public key
admin$  lemonwire admin members add --pubkey <key> --name sam
you$    lemonwire profile add grove https://index.example
```

With an invite code, the index's key is checked automatically. By key, `profile add`
pins the index's key on first use and shows both fingerprints: check the index's one
with your admin (`lemonwire-server info` shows it), or pass `--server-key <key>`. `lemonwire whoami`
shows your member name and both fingerprints at any time.

Two more secrets exist that you never handle: a 12-hour **session token** after each
login, and a **passkey** inside the `.torrent` files the index hands you, which the
tracker uses to check you're a member.

## The desktop app

`lemonwire-gui` does everything a member needs: join an index with an invite code,
browse and search, download (all files or some), share a file or folder, and watch
transfers. Admins also get a Members page for invites, adding members by key and
revoking them.

While the app is open it shares everything in Transfers, including finished
downloads, so friends can always get what you share; closing it asks first if anything
is being shared. It uses the same profile folder as the CLI, so both see the same
indexes and transfers (only one of them transfers at a time). Settings cover the
download folder, speed limits, the port and UPnP, a key passphrase and light/dark
mode.

## Quickstart

### 1. The admin makes a key and starts an index

```sh
lemonwire -p home keys generate                 # prints your PUBLIC key
lemonwire-server init --index-name "Lemon Grove" \
    --admin-pubkey <that key> --admin-name alice \
    --public-url https://index.example --tracker-url https://index.example
lemonwire-server serve --trust-proxy             # behind a TLS reverse proxy
```

`init` prints the index's public key. Add your profile, pinning that key:

```sh
lemonwire profile add home https://index.example --server-key <index key>
```

### 2. Friends join

Invite them (route A above): `lemonwire admin invite create`, send the code, and they
run `lemonwire profile add <profile> https://index.example --invite <code> --name <name>`.

### 3. Share, search, download

Every command is one-shot: it runs, then exits. Nothing runs in the background.

```sh
lemonwire share ~/Videos/holiday --tag video    # seeds until a friend has a full copy
lemonwire search holiday
lemonwire download 1                            # result number, or an infohash
```

How files stay available without a server copy:

- `share` publishes, then keeps seeding until at least one other member has the whole
  thing (`--copies N` to wait for more, `--publish-only` to skip). Ctrl-C stops early;
  the entry stays listed.
- `download` finishes, then seeds back until you've uploaded as much as you downloaded,
  15 minutes pass, or nobody else is downloading (`--seed-ratio`, `--seed-time`,
  `--no-seed`).
- `seed` serves everything you've shared or downloaded until Ctrl-C, for when you want
  to keep files available longer. It picks up changes other commands make while it runs.

An interrupted download is saved: run the same `download` again (or `seed`) to resume it
where it stopped. Downloads go to `~/Downloads/lemonwire` unless you pass `--dest`.

The index never holds or seeds files. A file is available while at least one member who
has it is running `share`, `download` or `seed`.

## Commands

| | |
|---|---|
| `-p PROFILE keys generate` | Make your key pair first, to send to an admin (route B) |
| `profile add PROFILE URL [--server-key K] [--invite CODE] [--name N] [--insecure]` | Add an index |
| `-p PROFILE keys protect` / `unprotect` | Add or remove a passphrase on your key |
| `profile list` / `remove NAME` / `default NAME` | Manage profiles |
| `info` / `whoami` | The index and its fingerprint / your name and admin status |
| `search [QUERY…] [--limit N] [--mine]` | Prefix search over names, tags and file paths |
| `search --more` | Next page of the last search |
| `show TARGET` | An entry and its numbered file list |
| `share PATH [--tag T]… [--copies N \| --forever \| --publish-only]` | Publish a file or folder, seed until N friends have it |
| `download TARGET [--dest DIR] [--files 1,3] [--seed-ratio R] [--seed-time T] [--no-seed]` | By result number or infohash, optionally only some files |
| `seed` | Serve all your saved transfers until Ctrl-C |
| `swarm TARGET` | Seeders, downloaders and members with a full copy |
| `unpublish INFOHASH` | Remove your entry (admins: any entry) |
| `transfers` / `pause` / `resume` / `cancel [--delete-data]` | Saved transfers (prefixes OK) |
| `admin members list` / `add` / `revoke` | Remote administration |
| `admin invite create [--admin] [--ttl-hours H]` / `list` | Invites |
| `run '<json>'` | Execute a raw command, e.g. `{"cmd":"search","query":"x"}` |

Global flags: `-p/--profile`, `--json`, `--config-dir`, `--port` (default 6881),
`--no-upnp`, `--max-up` / `--max-down` (KiB/s). Ctrl-C stops a running command; anything
unfinished is saved and resumes next time.

The server has its own CLI, which works on the data directory directly (also while
`serve` runs): `lemonwire-server init | info | config | members list|add|revoke|rotate-passkey
| invite create|list | torrents list|remove | serve`. See [docs/SPEC.md](docs/SPEC.md#41-cli).

## Networking

Peers connect to each other directly, and private swarms are small (often just two
people), so in each pair at least one side must accept incoming connections. There is
no DHT, peer exchange or relay to fall back on, and the index never carries file data.

While `share`, `download` or `seed` runs, the client asks your router to open its peer
port (`--port`, default 6881) via UPnP, and the mapping goes away when it exits. On most
home routers that's all you need. If your router has UPnP turned off, either turn it on
or forward the port by hand (and use `--no-upnp`). A local firewall on your computer
also needs to allow that port, and to let the router's UPnP replies in: on Fedora and
other firewalld systems, `sudo firewall-cmd --permanent --add-port=6881/tcp
--add-service=upnp-client && sudo firewall-cmd --reload`.

Members behind a VPN without port forwarding, or on mobile data, can't accept
connections; they can still swap files with anyone who can. When most of a group is in
that position, run everyone on [Tailscale](https://tailscale.com) or WireGuard, which
connects through any NAT.

## Security notes

- **Joining:** invite codes include the index's key, so your client checks it's talking
  to the right server from the first connection. Without an invite, pass `--server-key`
  or compare the fingerprint `profile add` shows with your admin.
- **Your secret key** lives in `keys/<profile>.key` in the config folder, never in
  `profiles.json`. On Linux and macOS it's `0600` in a `0700` folder; on Windows your
  user profile's permissions keep it private. To also protect it with a passphrase, run
  `lemonwire -p <profile> keys protect`; commands then ask for it, or read
  `LEMONWIRE_PASSPHRASE`. Back up the config folder to keep your identity.
- **Encryption in transit:** the client refuses plain `http://` to public addresses
  (fine for localhost, private networks and Tailscale). `--insecure` overrides that.
- **On the server**, `server.key` is the index's identity: keep it private and backed
  up. `index.db` holds no usable secrets: session and invite tokens and passkeys are
  stored only as hashes.
- **Revoking** a member deletes their key, sessions and passkey; the tracker stops
  serving them at once. `lemonwire-server members rotate-passkey` re-issues a passkey.
- **Logs** never contain tokens or passkeys, even with `LEMONWIRE_LOG=trace` (the CLI
  quietens the libraries that would print them).
- **Downloads** are never opened or executed, and every path is checked to stay inside
  the destination.

**What BitTorrent can't protect.** Peers connect directly and don't check each other's
membership. Anyone who knows a torrent's infohash and a sharing member's address can
download from that member, and revoking someone stops them *finding* peers, not
connecting to ones they already know. Members also see each other's IP addresses. If
that matters for your group, run everyone on [Tailscale](https://tailscale.com) or
WireGuard.

### Verifying a download

Releases come with `SHA256SUMS` and its minisign signature. With
[minisign](https://jedisct1.github.io/minisign/) and this repo's `minisign.pub`:

```sh
minisign -Vm SHA256SUMS -p minisign.pub      # the checksums are genuine
sha256sum --ignore-missing -c SHA256SUMS     # and so is your download
```

## Development

```sh
cargo test --workspace --all-features     # unit, integration and end-to-end tests
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

The end-to-end test runs a real index and two librqbit engines over localhost. CI runs
formatting and clippy on Linux and the full test suite on Linux, macOS and Windows;
tagged versions are built and published by the release workflow.

| Crate | |
|---|---|
| `crates/proto` | API types, keys and signatures, bencode and torrent metainfo |
| `crates/server` | `lemonwire-server`: CLI, HTTP API, SQLite (FTS5), tracker |
| `crates/client-core` | The client, shared by every front-end: commands, transfers, engine |
| `crates/client-cli` | `lemonwire`: clap front-end over client-core |

### Building a front-end

The desktop app (`crates/client-gui`, egui) is one: its UI tests run the real app
against an in-process index with egui's test harness, no window needed.


`lemonwire-client-core` holds all client behaviour, so the CLI and a GUI act the same.
A front-end opens a `Client`, runs `Command`s with `execute_cancellable`, renders the
`Output` and the `Event` stream from `subscribe()`, and cancels with a
`CancellationToken`. Commands, outputs, events and errors all serialise to JSON (see
[docs/SPEC.md §5.1](docs/SPEC.md#51-command-architecture-and-the-shared-core)).

```rust
let client = Client::open(OpenOptions {
    config: ConfigDir::default_location()?,
    engine: Some(EngineSettings::default()),   // port 6881, UPnP on
    download_dir: None,
}).await?;
let mut events = client.subscribe();            // Progress, Waiting, SeedingBack, …
let out = client.execute_cancellable(Command::Download {
    profile: None, infohash, dest: None, files: None,
    seed_back: Some(SeedBack::default()),
}, &cancel).await?;
```

Only one process per config directory runs a torrent engine at a time (the CLI and the
GUI take turns), and quick commands like search work alongside it.

## Licence

MIT
