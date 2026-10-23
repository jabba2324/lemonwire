//! Human-friendly sizes, speeds and dates.

pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1000.0 && unit < UNITS.len() - 1 {
        v /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else if v < 10.0 {
        format!("{v:.1} {}", UNITS[unit])
    } else {
        format!("{v:.0} {}", UNITS[unit])
    }
}

pub fn speed(bps: u64) -> String {
    if bps == 0 {
        "–".into()
    } else {
        format!("{}/s", bytes(bps))
    }
}

/// "today", "yesterday", "3 days ago", … from unix seconds.
pub fn ago(then: i64, now: i64) -> String {
    let days = (now - then).max(0) / 86_400;
    match days {
        0 => "today".into(),
        1 => "yesterday".into(),
        2..=13 => format!("{days} days ago"),
        14..=59 => format!("{} weeks ago", days / 7),
        60..=729 => format!("{} months ago", days / 30),
        _ => format!("{} years ago", days / 365),
    }
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(999), "999 B");
        assert_eq!(bytes(1_500), "1.5 KB");
        assert_eq!(bytes(25_000_000), "25 MB");
        assert_eq!(bytes(4_700_000_000), "4.7 GB");
        assert_eq!(speed(0), "–");
        assert_eq!(speed(2_000_000), "2.0 MB/s");
    }

    #[test]
    fn dates() {
        let now = 1_000_000_000;
        assert_eq!(ago(now - 60, now), "today");
        assert_eq!(ago(now - 86_400, now), "yesterday");
        assert_eq!(ago(now - 5 * 86_400, now), "5 days ago");
        assert_eq!(ago(now - 21 * 86_400, now), "3 weeks ago");
        assert_eq!(ago(now - 400 * 86_400, now), "13 months ago");
        assert_eq!(ago(now + 50, now), "today");
    }
}
