//! Loopback guard.
//!
//! Every outbound socket the engine opens must pass through this module first. Matching is
//! exact against `127.0.0.1`, `::1` and `localhost`: the wider `127.0.0.0/8` block,
//! IPv4-mapped IPv6 (`::ffff:127.0.0.1`), unspecified addresses and FQDN forms such as
//! `localhost.` are rejected on purpose, so the allowlist stays auditable.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use url::{Host, Url};

use super::error::{EngineError, EngineResult};
use super::types::HostKind;

pub const ALLOWLIST: [&str; 3] = ["127.0.0.1", "::1", "localhost"];

const ALLOWED_SCHEMES: [&str; 4] = ["http", "https", "ws", "wss"];

#[derive(Debug, Clone)]
pub struct GuardedTarget {
    pub url: Url,
    pub host: String,
    pub host_kind: HostKind,
    pub port: u16,
}

/// Validates a user-supplied target (full URL, `host:port`, or bare IP literal).
pub fn validate_url(input: &str) -> EngineResult<GuardedTarget> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(invalid(input, "empty target"));
    }

    let candidate = normalize_input(trimmed);
    let url = Url::parse(&candidate).map_err(|err| invalid(input, &err.to_string()))?;

    if !ALLOWED_SCHEMES.contains(&url.scheme()) {
        return Err(EngineError::UnsupportedScheme {
            scheme: url.scheme().to_owned(),
        });
    }

    let host_kind = match url.host() {
        Some(Host::Ipv4(ip)) if ip == Ipv4Addr::LOCALHOST => HostKind::Ipv4,
        Some(Host::Ipv6(ip)) if ip == Ipv6Addr::LOCALHOST => HostKind::Ipv6,
        Some(Host::Domain("localhost")) => HostKind::Localhost,
        Some(other) => {
            return Err(EngineError::NonLoopbackTargetRejected {
                host: other.to_string(),
            })
        }
        None => return Err(invalid(input, "missing host")),
    };

    // `http://evil.test@localhost` does target loopback, but it is a confusable that humans
    // misread as pointing at `evil.test`; refuse userinfo rather than rely on careful reading.
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid(input, "embedded credentials are not permitted"));
    }

    let port = url
        .port_or_known_default()
        .ok_or_else(|| invalid(input, "no port and no default for scheme"))?;

    let host = url.host_str().unwrap_or_default().to_owned();

    Ok(GuardedTarget {
        url,
        host,
        host_kind,
        port,
    })
}

/// Validates a resolved peer address. Applied to connected sockets as a second check,
/// independent of how the hostname was resolved.
pub fn validate_socket_addr(addr: &SocketAddr) -> EngineResult<()> {
    match addr.ip() {
        IpAddr::V4(ip) if ip == Ipv4Addr::LOCALHOST => Ok(()),
        IpAddr::V6(ip) if ip == Ipv6Addr::LOCALHOST => Ok(()),
        other => Err(EngineError::NonLoopbackTargetRejected {
            host: other.to_string(),
        }),
    }
}

fn normalize_input(trimmed: &str) -> String {
    if trimmed.contains("://") {
        return trimmed.to_owned();
    }
    // Bare IPv6 literals (`::1`) are not valid URL authorities without brackets.
    match trimmed.parse::<IpAddr>() {
        Ok(IpAddr::V6(ip)) => format!("http://[{ip}]"),
        Ok(IpAddr::V4(ip)) => format!("http://{ip}"),
        Err(_) => format!("http://{trimmed}"),
    }
}

fn invalid(input: &str, reason: &str) -> EngineError {
    EngineError::InvalidTarget {
        input: input.to_owned(),
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn accepted(input: &str) -> GuardedTarget {
        match validate_url(input) {
            Ok(target) => target,
            Err(err) => panic!("expected `{input}` to be accepted, got {err:?}"),
        }
    }

    fn rejected_code(input: &str) -> &'static str {
        match validate_url(input) {
            Ok(target) => panic!("expected `{input}` to be rejected, got {target:?}"),
            Err(err) => err.code(),
        }
    }

    #[test]
    fn accepts_exact_loopback_hosts() {
        let cases = [
            ("http://127.0.0.1:3000", HostKind::Ipv4, 3000),
            ("127.0.0.1:8080", HostKind::Ipv4, 8080),
            ("127.0.0.1", HostKind::Ipv4, 80),
            ("http://[::1]:9000/api", HostKind::Ipv6, 9000),
            ("[::1]:8080", HostKind::Ipv6, 8080),
            ("::1", HostKind::Ipv6, 80),
            ("localhost:5173", HostKind::Localhost, 5173),
            ("LOCALHOST:80", HostKind::Localhost, 80),
            ("https://localhost", HostKind::Localhost, 443),
            ("ws://localhost:4000/socket", HostKind::Localhost, 4000),
            ("wss://127.0.0.1:4443", HostKind::Ipv4, 4443),
        ];
        for (input, kind, port) in cases {
            let target = accepted(input);
            assert_eq!(target.host_kind, kind, "{input}");
            assert_eq!(target.port, port, "{input}");
        }
    }

    #[test]
    fn whatwg_canonical_forms_of_127_0_0_1_are_accepted() {
        for input in ["http://2130706433", "http://0x7f.0.0.1", "http://127.1"] {
            let target = accepted(input);
            assert_eq!(target.host, "127.0.0.1", "{input}");
        }
    }

    #[test]
    fn rejects_non_loopback_hosts() {
        let cases = [
            "http://10.0.0.1",
            "http://127.0.0.2",
            "http://0.0.0.0:3000",
            "http://[::]:3000",
            "http://[::ffff:127.0.0.1]",
            "::ffff:127.0.0.1",
            "http://localhost.",
            "http://localhost.evil.test",
            "http://evil.test/localhost",
            "http://localhost@evil.test",
            "192.168.1.10:8080",
            "example.com",
        ];
        for input in cases {
            assert_eq!(rejected_code(input), "NON_LOOPBACK_TARGET_REJECTED", "{input}");
        }
    }

    #[test]
    fn rejects_unsupported_schemes() {
        for input in ["file:///etc/passwd", "ftp://127.0.0.1", "gopher://localhost:70"] {
            assert_eq!(rejected_code(input), "UNSUPPORTED_SCHEME", "{input}");
        }
    }

    #[test]
    fn rejects_malformed_and_credentialed_input() {
        for input in ["", "   ", "http://", "http://evil.test@localhost", "http://u:p@127.0.0.1"] {
            assert_eq!(rejected_code(input), "INVALID_TARGET", "{input}");
        }
    }

    #[test]
    fn socket_addr_guard_is_exact() {
        let ok: [SocketAddr; 2] = ["127.0.0.1:80".parse().unwrap(), "[::1]:80".parse().unwrap()];
        for addr in ok {
            assert!(validate_socket_addr(&addr).is_ok(), "{addr}");
        }
        let bad: [SocketAddr; 4] = [
            "127.0.0.2:80".parse().unwrap(),
            "0.0.0.0:80".parse().unwrap(),
            "[::ffff:127.0.0.1]:80".parse().unwrap(),
            "10.0.0.1:80".parse().unwrap(),
        ];
        for addr in bad {
            assert!(validate_socket_addr(&addr).is_err(), "{addr}");
        }
    }
}
