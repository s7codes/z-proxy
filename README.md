# ChaosProxy

Desktop fault-injection and telemetry workbench for HTTP services running on the local machine.
Tauri v2 shell, Rust engine on the Tokio runtime, React 19 operator UI.

All engine egress is restricted to loopback. Non-loopback targets are rejected before a socket
is created.

## Status

Milestone 1: engine skeleton, loopback guard, IPC contract, telemetry stream, operator shell.
The reverse proxy, burst runner, payload fuzzer and route scanner are not implemented yet.

## Layout

```
src/                       React operator UI
  lib/types.ts             TypeScript mirror of the Rust IPC contract
  lib/ipc.ts               Typed command wrappers, telemetry Channel subscription
  components/              Inspector, topology canvas, fault controls, telemetry table
src-tauri/
  capabilities/default.json
  src/lib.rs               Builder, state, command registration
  src/commands.rs          IPC command handlers
  src/telemetry.rs         broadcast hub -> per-webview tauri::ipc::Channel forwarders
  src/engine/guard.rs      Loopback allowlist (URL and SocketAddr level)
  src/engine/net.rs        Guarded reqwest client
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
userinfo return `INVALID_TARGET`.

The HTTP client adds three further constraints:

- System proxy settings are ignored.
- `localhost` is pinned to `127.0.0.1`; the hosts file and DNS are not consulted.
- Every redirect hop is re-validated by the guard; the connected peer address is checked
  after the response arrives.

## IPC

| Command                  | Arguments                  | Returns            |
|--------------------------|----------------------------|--------------------|
| `validate_target`        | `input: string`            | `ValidatedTarget`  |
| `get_engine_status`      | none                       | `EngineStatus`     |
| `subscribe_telemetry`    | `onEvent: Channel`         | subscription id    |
| `unsubscribe_telemetry`  | `subscriptionId: number`   | `boolean`          |

Telemetry is pushed over `tauri::ipc::Channel<TelemetryEvent>`; the UI does not poll.
Event kinds: `engineHeartbeat` (1 Hz), `guardDecision`, `probeCompleted`.

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
