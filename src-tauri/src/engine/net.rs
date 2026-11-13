//! Guarded network primitives.
//!
//! The guard validates user input, but a client can still be steered elsewhere by a system
//! proxy, a hosts-file entry for `localhost`, or an upstream redirect. Each of those paths is
//! closed here so the only sockets the engine opens are loopback sockets.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use reqwest::redirect::Policy;
use reqwest::{Client, ClientBuilder, Method};
use tokio::net::TcpStream;

use super::error::{EngineError, EngineResult};
use super::guard::{self, GuardedTarget};
use super::types::{HostKind, ProbeResult};

const PROBE_TIMEOUT: Duration = Duration::from_millis(750);
const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const PROXY_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: usize = 5;

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error(transparent)]
    Guard(#[from] EngineError),
    #[error("connect timed out after {0:?}")]
    Timeout(Duration),
    #[error("connection failed: {0}")]
    Io(#[from] std::io::Error),
}

fn base_builder() -> ClientBuilder {
    Client::builder()
        .no_proxy()
        // Port is ignored by reqwest for resolve overrides; the request URL's port is used.
        .resolve("localhost", SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
}

/// Client for HEAD probes: follows redirects, but only while each hop passes the guard.
pub fn probe_client() -> EngineResult<Client> {
    let redirect = Policy::custom(|attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.stop();
        }
        match guard::validate_url(attempt.url().as_str()) {
            Ok(_) => attempt.follow(),
            Err(err) => attempt.error(err),
        }
    });

    base_builder()
        .redirect(redirect)
        .timeout(PROBE_TIMEOUT)
        .connect_timeout(PROBE_TIMEOUT)
        .build()
        .map_err(|err| EngineError::ClientBuild(err.to_string()))
}

/// Client for proxied traffic. Redirects are passed through to the caller untouched: a
/// reverse proxy that followed them would hide the upstream's real behaviour.
pub fn proxy_client() -> EngineResult<Client> {
    base_builder()
        .redirect(Policy::none())
        .timeout(PROXY_TIMEOUT)
        .connect_timeout(PROXY_CONNECT_TIMEOUT)
        .build()
        .map_err(|err| EngineError::ClientBuild(err.to_string()))
}

/// The engine links no TLS backend, so only cleartext HTTP can be proxied or burst.
pub fn require_plaintext(target: &GuardedTarget) -> EngineResult<()> {
    match target.url.scheme() {
        "http" => Ok(()),
        other => Err(EngineError::PlaintextOnly {
            scheme: other.to_owned(),
        }),
    }
}

/// Maps a guarded target to its socket address without consulting the system resolver,
/// so a hosts-file entry for `localhost` cannot redirect the connection.
pub fn loopback_addr(target: &GuardedTarget) -> SocketAddr {
    match target.host_kind {
        HostKind::Ipv6 => SocketAddr::from((Ipv6Addr::LOCALHOST, target.port)),
        HostKind::Ipv4 | HostKind::Localhost => SocketAddr::from((Ipv4Addr::LOCALHOST, target.port)),
    }
}

/// Opens a raw TCP stream to a guarded target, re-validating the address before connect
/// and the peer after.
pub async fn connect_loopback(
    target: &GuardedTarget,
    timeout: Duration,
) -> Result<TcpStream, ConnectError> {
    let addr = loopback_addr(target);
    guard::validate_socket_addr(&addr)?;
    let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| ConnectError::Timeout(timeout))??;
    guard::validate_socket_addr(&stream.peer_addr()?)?;
    stream.set_nodelay(true)?;
    Ok(stream)
}

/// Issues a HEAD request against an already-guarded target.
pub async fn probe(client: &Client, target: &GuardedTarget) -> ProbeResult {
    let mut url = target.url.clone();
    // WebSocket upgrades start as plain HTTP; probe the same authority over HTTP(S).
    let http_scheme = match url.scheme() {
        "ws" => Some("http"),
        "wss" => Some("https"),
        _ => None,
    };
    if let Some(scheme) = http_scheme {
        if url.set_scheme(scheme).is_err() {
            return ProbeResult::Unreachable {
                reason: format!("cannot map scheme `{}` to http", target.url.scheme()),
                latency_us: 0,
            };
        }
    }

    let started = Instant::now();
    let outcome = client.request(Method::HEAD, url).send().await;
    let latency_us = elapsed_us(started);

    match outcome {
        Ok(response) => {
            if let Some(peer) = response.remote_addr() {
                if let Err(err) = guard::validate_socket_addr(&peer) {
                    return ProbeResult::Unreachable {
                        reason: err.to_string(),
                        latency_us,
                    };
                }
            }
            ProbeResult::Reachable {
                status: response.status().as_u16(),
                latency_us,
            }
        }
        Err(err) => ProbeResult::Unreachable {
            reason: describe(&err),
            latency_us,
        },
    }
}

pub fn describe(err: &reqwest::Error) -> String {
    if err.is_connect() && err.is_timeout() {
        "connect timed out".to_owned()
    } else if err.is_timeout() {
        "timed out".to_owned()
    } else if err.is_connect() {
        "connection refused".to_owned()
    } else if err.is_redirect() {
        "redirect blocked by loopback guard".to_owned()
    } else {
        err.to_string()
    }
}

pub fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Router;

    async fn serve(router: Router) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        addr
    }

    #[tokio::test]
    async fn probe_reports_status_from_loopback_server() {
        let addr = serve(Router::new().route("/", get(|| async { StatusCode::IM_A_TEAPOT }))).await;
        let client = probe_client().unwrap();

        for input in [format!("http://127.0.0.1:{}", addr.port()), format!("localhost:{}", addr.port())] {
            let target = guard::validate_url(&input).unwrap();
            match probe(&client, &target).await {
                ProbeResult::Reachable { status, .. } => assert_eq!(status, 418, "{input}"),
                other => panic!("expected reachable for {input}, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn redirect_to_non_loopback_is_blocked() {
        let router = Router::new().route(
            "/",
            get(|| async { (StatusCode::FOUND, [(header::LOCATION, "http://10.255.255.1/")]).into_response() }),
        );
        let addr = serve(router).await;
        let client = probe_client().unwrap();
        let target = guard::validate_url(&format!("http://127.0.0.1:{}", addr.port())).unwrap();

        match probe(&client, &target).await {
            ProbeResult::Unreachable { reason, .. } => {
                assert_eq!(reason, "redirect blocked by loopback guard")
            }
            other => panic!("expected redirect to be blocked, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn redirect_within_loopback_is_followed() {
        let router = Router::new()
            .route("/", get(|| async { (StatusCode::FOUND, [(header::LOCATION, "/ok")]).into_response() }))
            .route("/ok", get(|| async { StatusCode::NO_CONTENT }));
        let addr = serve(router).await;
        let client = probe_client().unwrap();
        let target = guard::validate_url(&format!("http://127.0.0.1:{}", addr.port())).unwrap();

        match probe(&client, &target).await {
            ProbeResult::Reachable { status, .. } => assert_eq!(status, 204),
            other => panic!("expected reachable, got {other:?}"),
        }
    }
}
