# Deploying an index

The server speaks plain HTTP on two ports: the API (default 8080) and the tracker
(default 6969). Put both behind a TLS reverse proxy on one hostname:

| Path | Goes to |
|---|---|
| `/v1/*` | API port |
| `/announce`, `/scrape` | tracker port |

Then use the same URL for both at init: `--public-url https://index.example
--tracker-url https://index.example`. Run `serve` with `--trust-proxy` so the tracker
sees members' real IPs (from `X-Real-IP` / `X-Forwarded-For`); without a proxy, leave it
off or members could spoof addresses.

If the index shares a LAN with some members (for example, the admin's own desktop is the
index host), those members announce from a private address that outside members can't
reach. Pass `--nat-public-addr <public IP or DDNS hostname>` and forward the seeder's
port on the router: outside members are then given the public address for LAN peers,
while LAN members still see each other's private addresses.

Make sure the proxy doesn't keep access logs with query strings: tracker URLs contain
members' passkeys.

## Docker

```sh
docker build -t lemonwire-server .
docker run --rm -v ./data:/data lemonwire-server init --index-name "Lemon Grove" \
    --admin-pubkey <key> --public-url https://index.example --tracker-url https://index.example
docker run -d --name lemonwire -v ./data:/data -e LEMONWIRE_TRUST_PROXY=true \
    -p 127.0.0.1:8080:8080 -p 127.0.0.1:6969:6969 lemonwire-server
docker exec lemonwire lemonwire-server members list
```

The image runs as uid 10001 and works with a read-only root filesystem, every Linux
capability dropped and `no-new-privileges` (the example compose file sets all three):
add `--read-only --cap-drop ALL --security-opt no-new-privileges:true` to `docker run`. With a bind mount, either `chown 10001 ./data` or run the
container as your own user (`--user "$(id -u):$(id -g)"`). On SELinux hosts add `:Z`
to the volume.

See [contrib/docker-compose.yml](../contrib/docker-compose.yml).

## systemd

See [contrib/systemd/lemonwire-server.service](../contrib/systemd/lemonwire-server.service),
a hardened `DynamicUser` unit.

## Caddy

```
index.example {
    @tracker path /announce /scrape
    reverse_proxy @tracker 127.0.0.1:6969
    reverse_proxy 127.0.0.1:8080
    log {
        output discard
    }
}
```

## Traefik (file provider)

```yaml
http:
  routers:
    lemonwire:
      rule: "Host(`index.example`)"
      service: lemonwire-api
      tls: { certResolver: letsencrypt }
    lemonwire-tracker:
      rule: "Host(`index.example`) && (Path(`/announce`) || Path(`/scrape`))"
      service: lemonwire-tracker
      tls: { certResolver: letsencrypt }
  services:
    lemonwire-api:
      loadBalancer: { servers: [{ url: "http://127.0.0.1:8080" }] }
    lemonwire-tracker:
      loadBalancer: { servers: [{ url: "http://127.0.0.1:6969" }] }
```

The tracker router's longer rule gives it priority.

## Backups

Back up the whole data directory: `index.db` (plus its `-wal` file) and `server.key`.

- `server.key` is the index's identity, and passkeys are derived from it. If you lose
  it, every member has to re-pin a new server key. Keep it private: with it, someone
  could impersonate the index.
- `index.db` on its own holds no usable secrets (session tokens, invite tokens and
  passkeys are stored only as hashes), but it does list members, names and file
  metadata, so keep it private too.

## Upgrading the tracker URL

`lemonwire-server config --tracker-url <url>` then restart `serve`. Members get the new
announce URL at their next login; torrents already in their clients keep the old one
until re-fetched.
