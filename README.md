# ChaosProxy

Desktop fault-injection and telemetry workbench for HTTP services running on the local machine.
Tauri v2 shell, Rust engine on the Tokio runtime, React 19 operator UI.

All engine egress is restricted to loopback. Non-loopback targets are rejected before a socket
is created.

## Status

Milestone 3: loopback reverse proxy with fault injection, barrier-synchronized concurrency burst
runner with anomaly detection, filesystem route scanner, deterministic payload fuzzer.
Not implemented yet: WebSocket proxying, TLS upstreams, per-route fault rules, query-string and
header fuzzing.

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
  src/engine/http1.rs      Guarded HTTP/1.1 request template, connect and exchange
  src/engine/concurrency.rs  Burst runner and report analysis
  src/engine/fuzzer.rs     Mutation case generation, sequential runner, verdicts
  src/engine/error.rs      EngineError, serialized as { code, message, ... }
  src/engine/types.rs      IPC DTOs and TelemetryEvent
  src/scanner/routes.rs    Project walk, path normalization, scan report
  src/scanner/lex.rs       Comment masking, string spans, bracket matching
  src/scanner/{next,node,axum,go,openapi}.rs  Per-framework extractors
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

## Route scanner

Walks a local project root (absolute path; filesystem roots are refused) and extracts route
declarations lexically. Symlinks are not followed. Skipped directories: `node_modules`, `.git`,
`target`, `dist`, `.next`, `.turbo`, `.vercel`, `.svelte-kit`, `.output`, `coverage`,
`vendor`, `.venv`, `__tests__`, `__mocks__`. Skipped files: `*.d.ts`, `*.min.*`, `*.test.*`,
`*.spec.*`, `*_test.go`, lockfiles. Limits: 50 000 files, 1 MiB per source file, 8 MiB per
spec, 5 000 routes; hitting a limit sets `truncated`.

| Source            | Recognized                                                                   |
|-------------------|------------------------------------------------------------------------------|
| Next.js App Router| `app/**/route.{ts,tsx,js,jsx,mjs}` exporting `GET`/`POST`/... (function, const, export list) |
| Next.js Pages API | `pages/api/**`; methods from `req.method` comparisons and `case` labels, else `ANY` |
| Express           | `<server>.get/post/put/patch/delete/all(path, handler)`, `.route(path).get(..)` chains |
| Fastify           | Shorthand methods, `route({ method, url })`                                  |
| Hono              | Shorthand methods including chained `app.get(..).post(..)`                   |
| Axum              | `.route("/path", get(h).post(h))`, `routing::*`, `on(MethodFilter::X, h)`    |
| Go                | net/http (`"GET /path"` patterns), gorilla `.Methods(..)`, gin/echo, chi     |
| OpenAPI / Swagger | `paths` in `.json`/`.yaml`/`.yml`; `basePath` or `servers[0].url` path prefixed |

A JS/TS call counts only when its receiver is a server object: declared in the file from
`express()`, `Router()`, `Fastify()` or `new Hono()`, or named like one (`app`, `router`,
`server`, `fastify`, `*Router`, ...). Receivers initialized from HTTP clients (`axios`,
`ky`, `got`, `supertest`) are excluded, and the path argument must be followed by a handler.
Declarations inside comments, string literals and Rust `#[cfg(test)]` modules are ignored.

Paths are normalized to one template form: `:id`, `[id]` and `{id}` become `{id}`; catch-alls
(`*`, `[...slug]`, `{path...}`, `{*rest}`) become `{*name}`. Mount prefixes applied at runtime
(`app.use("/api", router)`, `Router::nest`, Hono `basePath`, gin groups) are not resolved; a
route is reported as written at its declaration.

Selecting a route loads its method and path into the Burst and Fuzzer panels and adds an
endpoint node to the topology. Requests stay blocked while the path contains unresolved
`{param}` segments.

The folder picker (`pick_project_root`) is opened from Rust through `tauri-plugin-dialog`; the
webview capability set remains `core:default`.

## Payload fuzzer

Expands a base JSON object (operator-supplied, or a built-in template) into an ordered list of
mutation cases and sends them to one loopback `http` target. Generation is deterministic: the
same base produces byte-identical requests, so a finding reproduces by case index. Fields are
addressed by RFC 6901 pointer, nested objects to depth 3, at most 48 fields.

| Class             | Cases                                                                        |
|-------------------|------------------------------------------------------------------------------|
| `nullInjection`   | Each field set to `null`                                                     |
| `emptyStrings`    | Each field set to `""`                                                       |
| `boundaryNumbers` | Each numeric field: `0`, `-1`, `i64::MAX`, `i64::MIN`, `2^53+1`, `"NaN"`, `"Infinity"`, `"-Infinity"` |
| `typeConfusion`   | Each field replaced by the four other JSON types; the whole body wrapped in an array |
| `oversizedField`  | Each string field set to 64 KiB; one extra 64 KiB field                      |
| `malformedJson`   | Truncated at 50 %, missing closing brace, trailing comma, single quotes, unquoted keys, bare `NaN`, empty body, invalid UTF-8 (`C3 28`) |
| `missingFields`   | Each field removed; empty object                                             |

The default template yields 86 cases. An unmutated baseline request runs first. Cases run
sequentially, one connection each, with `Connection: close` and
`x-chaosproxy-fuzz-case: <index>`; `Content-Type: application/json` is added unless the operator
sets one.

| Response                                   | Verdict            | Severity               |
|--------------------------------------------|--------------------|------------------------|
| 4xx                                        | `rejected`         | none                   |
| 1xx-3xx                                    | `accepted`         | warn for `malformedJson` |
| 5xx                                        | `serverError`      | fault                  |
| Reset, closed before a response, timeout   | `transportFailure` | fault                  |
| Connect failure                            | `unreachable`      | none                   |

Three consecutive connect failures abort the run; the remaining cases are `skipped` and the last
case that reached the service is marked as a fault. A baseline that was not accepted is reported
as a note. One suite runs at a time (`FUZZER_BUSY`); `cancel_fuzzer_suite` stops between cases.
Response bodies are fingerprinted in full and the first 512 bytes are kept as a preview, which
shows stack traces leaked by 5xx handlers.

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
| `run_fuzzer_suite`       | `spec: FuzzSpec`                            | `FuzzReport`       |
| `cancel_fuzzer_suite`    | none                                        | `boolean`          |
| `scan_project_routes`    | `root: string`                              | `RouteScanReport`  |
| `pick_project_root`      | none                                        | `string \| null`   |

Telemetry is pushed over `tauri::ipc::Channel<TelemetryEvent>`; the UI does not poll.
Event kinds: `engineHeartbeat` (1 Hz), `guardDecision`, `probeCompleted`,
`proxyStateChanged`, `proxyExchange`, `burstStarted`, `burstSample`, `burstCompleted`,
`fuzzerStarted`, `fuzzerCaseCompleted`, `fuzzerCompleted`, `routeScanCompleted`.

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
