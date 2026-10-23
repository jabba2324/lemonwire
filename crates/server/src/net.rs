//! Client IP extraction and a small per-IP rate limiter.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;

/// The client's IP. Behind a reverse proxy (`trust_proxy`), use `X-Real-IP`, or the
/// last `X-Forwarded-For` hop, which is what the proxy itself saw.
pub fn client_ip(peer: SocketAddr, headers: &HeaderMap, trust_proxy: bool) -> IpAddr {
    let ip = if trust_proxy {
        let real = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse().ok());
        let forwarded = || {
            headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|s| s.split(','))
                .filter_map(|s| s.trim().parse::<IpAddr>().ok())
                .next_back()
        };
        real.or_else(forwarded).unwrap_or(peer.ip())
    } else {
        peer.ip()
    };
    canonical(ip)
}

/// Treat IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) as IPv4.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// Addresses only reachable inside a LAN (or this host).
pub fn is_private(ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique local
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link local
        }
    }
}

/// The address to hand `requester` for `peer`. A peer that announced from a private
/// address is on the index's own LAN; members outside it reach that peer through the
/// LAN's public address (`nat_public`) and a router port forward.
pub fn advertised(peer: SocketAddr, requester: IpAddr, nat_public: Option<IpAddr>) -> SocketAddr {
    match nat_public {
        Some(public) if is_private(peer.ip()) && !is_private(requester) => {
            SocketAddr::new(public, peer.port())
        }
        _ => peer,
    }
}

/// Fixed-window limiter: at most `max` requests per IP per `window`.
pub struct RateLimiter {
    max: u32,
    window: Duration,
    hits: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl RateLimiter {
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            max,
            window,
            hits: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut hits = self.hits.lock().expect("rate limiter lock");
        let e = hits.entry(ip).or_insert((now, 0));
        if now.duration_since(e.0) >= self.window {
            *e = (now, 0);
        }
        e.1 += 1;
        e.1 <= self.max
    }

    pub fn purge(&self) {
        let now = Instant::now();
        self.hits
            .lock()
            .expect("rate limiter lock")
            .retain(|_, (start, _)| now.duration_since(*start) < self.window);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_per_ip() {
        let rl = RateLimiter::new(2, Duration::from_secs(60));
        let a: IpAddr = "1.2.3.4".parse().unwrap();
        let b: IpAddr = "5.6.7.8".parse().unwrap();
        assert!(rl.check(a) && rl.check(a));
        assert!(!rl.check(a));
        assert!(rl.check(b));
    }

    #[test]
    fn lan_peers_are_advertised_with_the_public_address() {
        let lan: SocketAddr = "192.168.1.10:6881".parse().unwrap();
        let outside: IpAddr = "198.51.100.4".parse().unwrap();
        let inside: IpAddr = "192.168.1.20".parse().unwrap();
        let public: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(
            advertised(lan, outside, Some(public)),
            "203.0.113.7:6881".parse().unwrap()
        );
        assert_eq!(advertised(lan, inside, Some(public)), lan);
        assert_eq!(advertised(lan, outside, None), lan);
        let remote: SocketAddr = "198.51.100.9:51413".parse().unwrap();
        assert_eq!(advertised(remote, inside, Some(public)), remote);
        assert!(is_private("::1".parse().unwrap()));
        assert!(is_private("fd7a:115c::1".parse().unwrap()));
        assert!(!is_private("100.64.0.1".parse().unwrap()));
    }

    #[test]
    fn proxy_headers_only_when_trusted() {
        let peer: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "9.9.9.9, 8.8.8.8".parse().unwrap());
        assert_eq!(client_ip(peer, &h, false), peer.ip());
        assert_eq!(
            client_ip(peer, &h, true),
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
        let mapped: SocketAddr = "[::ffff:10.0.0.1]:1".parse().unwrap();
        assert_eq!(
            client_ip(mapped, &HeaderMap::new(), false),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
    }
}
