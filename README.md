# ChaosProxy

Desktop fault-injection and telemetry workbench for HTTP services running on the local machine.
Tauri v2 shell, Rust engine on the Tokio runtime, React 19 operator UI.

All engine egress is restricted to loopback. Non-loopback targets are rejected before a socket
is created.

## Status

Milestone 2: loopback reverse proxy with fault injection, barrier-synchronized concurrency burst
runner with anomaly detection.
Not implemented yet: WebSocket proxying, TLS upstreams, per-route fault rules, payload fuzzer,
route scanner.

## Layout

```
src/                       React operator UI
  lib/types.ts             TypeScript mirror of the Rust IPC contract
  lib/ipc.ts               Typed command wrappers, telemetry Channel subscription
  hooks/                   Engine status, guard validation, proxy and burst control
  components/              Inspector, topology canvas, chaos panel, telemetry table
src-tauri/
  capabilities/default.json
  src/lib.rs               Builder, state, command registration
  src/commands.rs          IPC command handlers
  src/telemetry.rs         broadcast hub -> per-webview tauri::ipc::Channel forwarders
  src/engine/guard.rs      Loopback allowlist (URL and SocketAddr level)
  src/engine/net.rs        Guarded reqwest clients, raw loopback connect
  src/engine/fault.rs      FaultProfile and the per-request fault decision
  src/engine/proxy.rs      Reverse proxy listener (hyper connections, axum routing)
  src/engine/concurrency.rs  Burst runner and report analysis
  src/engine/error.rs      EngineError, serialized as { code, message, ... }
  src/engine/types.rs      IPC DTOs and TelemetryEvent
```

## Loopback guard

Accepted hosts, exact match only:

| Input form            | Host kind  |
|-----------------------|------------|
| `127.0.0.1`           | ipv4       |
| `::1`                 | ipv6       |
| `localhost`           | localhost  |

Rejected with `NON_LOOPBACK_TARGET_REJECTED`: any other address, including `127.0.0.0/8`
beyond `.1`, `0.0.0.0`, `::`, IPv4-mapped IPv6 (`::ffff:127.0.0.1`) and `localhost.`.
Schemes other than `http`, `https`, `ws`, `wss` return `UNSUPPORTED_SCHEME`. URLs with
userinfo return `INVALID_TARGET`. The proxy and the burst runner accept `http` only and return
`PLAINTEXT_ONLY` otherwise; the engine links no TLS backend.

The HTTP clients add three further constraints:

- System proxy settings are ignored.
- `localhost` is pinned to `127.0.0.1`; the hosts file and DNS are not consulted.
- The connected peer address is re-validated. The probe client re-validates every redirect
  hop; the proxy client does not follow redirects and passes 3xx responses through.

## Reverse proxy

Binds `127.0.0.1:<port>` (`0` for ephemeral) and forwards every method and path to one
upstream. The upstream base path is prefixed: upstream `http://127.0.0.1:3000/api` receives
`/api/users` for inbound `/users`. Hop-by-hop headers (RFC 9110 7.6.1, plus fields named in
`Connection`) are stripped; `Via`, `X-Forwarded-For` and `X-Forwarded-Host` are added. Request
and response bodies are buffered up to 16 MiB. Starting with an upstream equal to the listener
returns `PROXY_LOOP`.

Fault profile, applied per request while armed, in this order:

| Field            | Range        | Effect                                                    |
|------------------|--------------|-----------------------------------------------------------|
| `latencyMs`      | 0-30000      | Base delay before any outcome                             |
| `jitterMs`       | 0-10000      | Uniform offset in `[-jitter, +jitter]`, clamped at 0      |
| `dropRate`       | 0-100 %      | Close the client connection with RST (`SO_LINGER=0`)      |
| `statusMutation` | 429/5xx      | Synthetic JSON response; upstream is not contacted        |
| `mutationRate`   | 0-100 %      | Probability of the status mutation                        |

Synthetic responses carry `x-chaosproxy-fault: status-<code>`; 429 adds `Retry-After: 1`.
Forwarded responses that were delayed carry `x-chaosproxy-injected-delay-us`. Upstream
failures return 502, response timeouts 504, both with `x-chaosproxy-error`. The profile can be
changed while the listener runs and survives listener restarts.

## Concurrency burst

Fires N identical requests (1-100) at one loopback `http` target. Each worker opens and
handshakes its own HTTP/1.1 connection, then waits on a `tokio::sync::Barrier`; after release
the only remaining work is writing the request. Workers that fail to connect still join the
barrier and report a transport error.

The report contains the status histogram, latency min/mean/p50/p95/p99/max (nearest rank,
responses only), response size range, distinct body fingerprints (SipHash-64), dispatch
spread (latest minus earliest release), and anomalies:

| Kind               | Severity   | Condition                                                       |
|--------------------|------------|-----------------------------------------------------------------|
| `raceWindow`       | fault      | More than one 2xx alongside 409/412/422/423/425/429 responses   |
| `statusDivergence` | warn/fault | Statuses outside the majority (fault when any is 5xx)           |
| `bodyDivergence`   | warn       | Differing bodies within one status                              |
| `transportErrors`  | warn/fault | Workers without a response (fault when all failed)              |

One 2xx plus conflicts is treated as correct serialization and is not reported.

## IPC

| Command                  | Arguments                                   | Returns            |
|--------------------------|---------------------------------------------|--------------------|
| `validate_target`        | `input: string`                             | `ValidatedTarget`  |
| `get_engine_status`      | none                                        | `EngineStatus`     |
| `subscribe_telemetry`    | `onEvent: Channel`                          | subscription id    |
| `unsubscribe_telemetry`  | `subscriptionId: number`                    | `boolean`          |
| `start_proxy`            | `config: ProxyConfig`                       | `ProxyStatus`      |
| `stop_proxy`             | none                                        | `ProxyStatus`      |
| `get_proxy_status`       | none                                        | `ProxyStatus`      |
| `set_fault_profile`      | `armed: boolean, profile: FaultProfile`     | `ProxyStatus`      |
| `run_concurrency_burst`  | `spec: BurstSpec`                           | `BurstReport`      |

Telemetry is pushed over `tauri::ipc::Channel<TelemetryEvent>`; the UI does not poll.
Event kinds: `engineHeartbeat` (1 Hz), `guardDecision`, `probeCompleted`,
`proxyStateChanged`, `proxyExchange`, `burstStarted`, `burstSample`, `burstCompleted`.

## Requirements

- Node.js 20+
- Rust 1.90+
- Windows: WebView2 runtime and MSVC build tools

## Commands

```
npm install
npm run tauri dev          # desktop app with HMR
npm run build              # tsc + vite build
cd src-tauri
cargo clippy --all-targets -- -D warnings
cargo test
```

`src-tauri/Cargo.toml` denies `unwrap_used`, `expect_used` and `panic` outside tests.
