# z-proxy

Desktop fault-injection and telemetry workbench for HTTP services running on the local machine.
Tauri v2 shell, Rust engine on the Tokio runtime, React 19 operator UI.

All engine egress is restricted to loopback. Non-loopback targets are rejected before a socket
is created.

## Status

1.0.0: loopback reverse proxy with global and route-scoped fault injection (latency, RST,
status mutation, mid-body truncation), barrier-synchronized concurrency burst runner
(pre-connected or last-byte sync, both compared in one action) with TTFB/total latency split,
success quota, anomaly detection and contract drift under load, filesystem route scanner
with in-file mount prefix resolution and OpenAPI request body synthesis, deterministic
payload fuzzer (eleven vectors including schema contract bounds, path parameter boundaries,
delimiter escaping and query-string / header bounds) with stack trace, database error and
sensitive-field detection, mass-assignment echo detection and fuzz-to-burst replay, embedded
target lab service with switchable defects that can be chained behind the proxy, passive
audit of proxied traffic with gzip/deflate/brotli/zstd inflation (N+1 fan-outs, retry storms
including retries that ignore a 429/503 or its `Retry-After`, latency regressions with a
loopback rule, unpaginated collections, header misconfiguration, disclosures and leaked model
fields), OpenAPI response contract checks (types, required fields, value constraints) in the
proxy, the fuzzer and the burst runner, static audit of route handlers across relative
imports, `tsconfig` path aliases, `package.json` subpath imports, barrels, Next.js
re-exports and class controllers (unvalidated mutations, unbounded queries, floating async
calls, non-atomic, looped and transaction-bypassing writes, interpolated SQL, blocking calls
in event-loop handlers) with one-click targeting into Burst or Fuzzer, Idempotency-Key replay
bursts, Markdown/JSON audit report export, CI on Linux and Windows.
Not implemented yet: WebSocket proxying, TLS upstreams, mount prefixes across files.

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
  src/engine/http1.rs      Guarded HTTP/1.1 request template, connect and exchange (TTFB stamp),
                           wire encoding and split connections for last-byte sync
  src/engine/pathparam.rs  {param} placeholder resolution and path slot rewriting
  src/engine/concurrency.rs  Burst runner and report analysis
  src/engine/fuzzer.rs     Mutation case generation, sequential runner, verdicts
  src/engine/disclosure.rs Stack trace and database error signatures in response bodies;
                           byte-level JSON walk for sensitive model fields
  src/engine/linter.rs     Passive audit of proxied exchanges: N+1, retry storm, throttled
                           retry (Retry-After aware) and latency windows, capped
                           gzip/deflate/br/zstd inflation, JSON skimmer
  src/engine/contract.rs   Response contract checks, contract set matched by route template
  src/engine/lab.rs        Embedded target lab service (unprotected / hardened)
  src/engine/error.rs      EngineError, serialized as { code, message, ... }
  src/engine/types.rs      IPC DTOs and TelemetryEvent
  src/scanner/routes.rs    Project walk, path normalization, scan report
  src/scanner/lex.rs       Comment masking, string spans, bracket matching
  src/scanner/{next,node,axum,go,openapi}.rs  Per-framework extractors, mount prefixes
  src/scanner/schema.rs    OpenAPI request body samples and response contracts
  src/scanner/audit.rs     Static handler audit: validation, query bounds, dropped async calls,
                           unguarded, looped and handle-bypassing writes, interpolated SQL,
                           blocking calls; import, re-export, barrel and class member resolution
  src/scanner/tsconfig.rs  compilerOptions.paths / baseUrl through relative extends chains;
                           package.json subpath imports
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
| `partialDropRate`| 0-100 %      | Forward the upstream head with its full `Content-Length` and the leading body bytes, then reset (`SO_LINGER=0`) |
| `partialDropBytes` | 0-16 MiB   | Body bytes forwarded before the reset; `null` cuts at half the body |

Precedence is reset, status mutation, partial drop; each roll draws from the seeded RNG only
when its rate is non-zero, so seeded sequences do not change when a new field is added. A
partial drop keeps at least one byte of a non-empty body back (an empty body is forwarded
untouched) and waits 50 ms before the reset, because Windows discards received but unread
data when the RST arrives; the client therefore reads a 200 head and a JSON document that
stops mid-value, then a connection reset. `proxyExchange` reports `fault: partialBodyDrop`
with `responseBytes` set to the bytes actually written; contract and passive checks still
judge the full upstream body.

Synthetic responses carry `x-zproxy-fault: status-<code>`; 429 adds `Retry-After: 1`.
Truncated responses carry `x-zproxy-fault: partial-body-<bytes>`.
Forwarded responses that were delayed carry `x-zproxy-injected-delay-us`. Upstream
failures return 502, response timeouts 504, both with `x-zproxy-error`. The profile can be
changed while the listener runs and survives listener restarts.

Route rules (`set_fault_rules`) bind a profile to one route:
`FaultRule { method: RouteMethod | null, pathPattern, profile }`. Patterns use the scanner's
template syntax: literal segments, `{name}` for one segment (also embedded, as in
`{id}.json`), `{*name}` for the remainder as the final segment. Rules are matched in order
against the path the upstream receives, upstream base path included, so a scanned route
template applies as reported; empty segments are collapsed before matching. The first match
supplies the profile; unmatched requests use the global profile. Rules apply only while faults
are armed. A set is validated as a whole (at most 64 rules, each profile range-checked);
an invalid rule returns `INVALID_FAULT_RULE` with its `index` and leaves the active set in
place. `proxyExchange` events name the matching rule as `METHOD /pattern`. In the Faults tab,
"Bind profile to" snapshots the current sliders onto the selected route (or the Burst/Fuzzer
request target); binding the same route again replaces its rule.

### Passive traffic audit

Every proxied exchange is inspected (`engine/linter.rs`) and `proxyExchange` carries the
results as `findings: TrafficFinding[]` (`kind`, `severity`, `detail`, `evidence`):

| Kind                     | Severity   | Condition                                                         |
|--------------------------|------------|-------------------------------------------------------------------|
| `nPlusOneBurst`          | warn       | 8 distinct GET paths of one route template within 250 ms of arrival |
| `retryStorm`             | warn       | One exact request line (method, path and query) 10 times within 250 ms of arrival, any method; or retried 4 times in a row, each retry arriving within 100 ms of a 429 or 503 answer to it ("immediate retry storm after 429/503 without backoff") or before the `Retry-After` that answer set ("retry storm after 429/503 ignoring Retry-After", naming the interval and the longest gap) |
| `unboundedCollection`    | warn       | 2xx JSON with a top-level array, or a `data`/`items`/`results` array, above 250 items and no pagination key (`total`, `page`, `nextCursor`, `hasMore`, `meta`, `links`, ...) or header (`Link: rel="next"`, `X-Total-Count`, `Content-Range`, ...); JSON above 1 MiB, compressed or not |
| `headerMisconfiguration` | warn/fault | JSON body without a JSON `Content-Type`, markup served as JSON; `Content-Encoding: gzip`/`deflate`/`br`/`zstd` on a body that is not a valid stream of it; `Access-Control-Allow-Credentials: true` with origin `*` (warn) or `null` (fault); GET 2xx to a credentialed request, a cookie-setting response or an account/session route without `Cache-Control` or marked `public` |
| `passiveDisclosure`      | warn/fault | Disclosure signature (see the fuzzer) in the first 8 KiB of a textual body, fault on 5xx; a sensitive model field in a 2xx JSON body, fault for credential material (password, its hash or salt, private key, reset or two-factor secret, any password-hash value), warn for a client secret, API key or refresh token outside a route that issues one |
| `latencyRegression`      | warn       | 2xx upstream latency at least 4x the median of the route template's previous responses (8 to 32 kept) and at least 250 ms; or, when that median is at least 2 ms, at least 8x the median, at least 35 ms and above twice the window's p95 |

N+1 detection folds identifier segments (integers, UUIDs, hex keys of 12+ characters,
prefixed keys such as `ord-000123`, opaque tokens of 16+ characters with digits) into `{id}`;
a path without one is never a fan-out, and repeating one path is polling, not N+1. It counts
every GET, including dropped and injected ones. A burst is reported once, on the request that
reaches the threshold, and the template stays quiet until a full window passes without a new
path. Windows live in 16 shards behind short `std::sync::Mutex` sections (no await inside), at
most 64 templates per shard.

Retry storms use the same shape keyed by the exact request line, so `/cart?user=7` and
`/cart?user=8` are different requests; a polling client below 10 per 250 ms is not reported.
The throttled-retry trigger follows the same key through 429 and 503 answers: a retry that
arrives within 100 ms of the previous throttled answer ignored it (any real backoff, even the
first step of an exponential one, waits longer), and so did one that arrives before the
answer's `Retry-After` (delta-seconds; an HTTP-date is not read, `0` permits an immediate
retry) elapsed. The fourth such retry in a row is reported once, with the advertised interval
when one was set. A longer pause or any other answer ends the storm; a request that arrived
before the throttled answer went out ran concurrently and is not a retry. Status and
`Retry-After` are the ones the client received, so arming a 429 status mutation (which sends
`Retry-After: 1`) exposes a client's retry policy as well as an upstream's. Only a throttled
answer opens a slot, so unthrottled traffic costs one shard scan.
Latency regressions keep a fixed ring of the last 32 upstream latencies per method and route
template (identifier segments folded as above) and judge a response against the median of the
ones before it, once at least 8 exist. Upstream time excludes injected delay, so an armed
latency profile never reads as a service regression. The general rule's 250 ms floor keeps
scheduler jitter on millisecond loopback medians out; the loopback rule catches what that
floor hides on a fast local service (an N+1 or a blocking call that turns 3 ms into 40 ms)
by requiring a median of at least 2 ms (a handler doing real work), 8x that median, 35 ms
(above two ticks of the 15.6 ms Windows timer) and twice the window's p95, so a route whose
normal tail already reaches the sample stays quiet. Median and p95 come from one sort of a
stack copy, taken only for samples of 35 ms or more. Both detectors shard like the N+1 windows
and reuse an evicted slot's buffer, so a known key costs no allocation.

Response checks run on forwarded responses only, never on injected faults. A `gzip`,
`x-gzip`, `deflate` (zlib-wrapped or raw), `br` or `zstd` `Content-Encoding` is undone first,
last-applied coding first, into a buffer capped at 1 MiB: the inflaters (`flate2` on the
pure-Rust `miniz_oxide` backend, `brotli-decompressor`, `ruzstd`) are read through
`take(cap + 1)`, so a decompression bomb stops at the cap. A truncated brotli stream, bytes
after its end and a large-window stream are reported as an invalid encoding; the decoder's
ring buffer stays within the RFC 7932 window (16 MiB). A zstd stream is decoded frame by
frame (RFC 8878: concatenated frames, skippable frames skipped); each frame's window is read
from its header before the decoder allocates and one above the 8 MiB RFC 9659 allows a
`zstd` content coding is refused, as are a cut frame, trailing bytes and a declared content
checksum that does not match. The client still receives the encoded bytes. `compress` and
dictionary codings get the header checks only.
The checks borrow the decoded body and the header map; JSON is walked by a byte-level skimmer
that counts items and reads top-level keys without building values or recursing, and the
sensitive-field walk (`disclosure::field_leak`) tracks the path to each value on a fixed
stack, allocating only for the field it reports. Its evidence is the pointer and the value's
shape (hash parameters or length), never the value.

The UI folds findings and contract drift into counters that keep running while the telemetry
table is paused (the last 1 000 records are kept for the report). The telemetry toolbar shows
a `Findings` filter and one badge per category with findings; the Faults tab lists all seven
counters, and each opens the matching exchanges in telemetry.

### Response contracts

`set_proxy_contracts` installs `RouteContract { method, path, contract }` entries, matched
like route rules against the upstream path. The UI sends every OpenAPI route of the route list
in view whenever it changes (a project scan or the lab document), so contracts follow the
list. The set is held in a `watch` snapshot (an `Arc` clone per request), indexed by segment
count, with literal templates ahead of parameterized ones (`/orders/recent` before
`/orders/{id}`). An invalid template rejects the set with `INVALID_CONTRACT_SET` and its
`index`. Forwarded responses of a matched route carry `contract` (`METHOD /pattern`) and
`violations`; `ProxyStatus.contracts` reports the set size.

## Concurrency burst

Fires N identical requests (1-100) at one loopback `http` target. Each worker opens and
handshakes its own HTTP/1.1 connection, then waits on a `tokio::sync::Barrier`; after release
the only remaining work is writing the request. Workers that fail to connect still join the
barrier and report a transport error.

`BurstSpec.syncMode` selects what the barrier releases (`null` is `preConnected`):

| Mode           | Before the barrier                                     | On release                    |
|----------------|--------------------------------------------------------|-------------------------------|
| `preConnected` | TCP connect and HTTP/1.1 handshake                     | hyper writes the full request |
| `lastByte`     | Connect, then every request byte but the last written and flushed on a `TCP_NODELAY` socket | each worker writes one byte from its own task |

A server cannot finish parsing a request before its final byte, so `lastByte` aligns the
requests at the server's parser instead of at the client's scheduler, and dispatch spread is
one single-byte write per worker. The request is encoded once per worker
(`http1::encode`: origin-form target, the template's headers, `content-length` for a
non-empty body) and queued with hyper before the barrier; hyper parses the response from the
read half while its own serialization of the request goes to a sink whose reads stay parked
until hyper flushed it. A server that answers before the last byte (431, 413) keeps its
response even when the final write fails. `burstStarted`, `burstCompleted` and the report
echo `syncMode`, so a dispatch spread is never read without the mode it was measured under.
The UI keeps the latest burst of each mode; once both modes have sent the same request from
as many workers, the Burst result lists their spreads side by side with the last-byte spread
against the pre-connected one (`last byte 87 us narrower (0.71x)`), and the audit report's
`burstSync` and `burstComparison` carry the same comparison. "Compare sync" produces it in one
action: the configured burst runs pre-connected, then last byte, and the second report is
shown with the table. A stateful target answers the second run after the first (a spent
coupon, created orders), so outcomes compare only after a reset; the spreads are measured on
the client side and compare either way. Neither mode is asserted to be tighter: both spreads
depend on the host scheduler, so they are measured and reported, not compared in tests.

Each worker records two monotonic intervals from the instant it writes its request: `ttfbUs`
to the parsed response head (hyper resolves `send_request` once the status line and headers
are read) and `latencyUs` to the last body frame. The report carries min/mean/p50/p95/p99/max
for both (`ttfb`, `latency`; nearest rank, responses only), the status histogram, response
size range, distinct body fingerprints (SipHash-64), dispatch spread (latest minus earliest
release), and anomalies:

| Kind               | Severity   | Condition                                                       |
|--------------------|------------|-----------------------------------------------------------------|
| `raceWindow`       | fault      | 2xx count above the quota; without a quota, more than one 2xx alongside 409/412/422/423/425/429 responses |
| `statusDivergence` | warn/fault | Statuses outside the majority (fault when any is 5xx)           |
| `bodyDivergence`   | warn       | Differing bodies within one status                              |
| `transportErrors`  | warn/fault | Workers without a response (fault when all failed)              |
| `idempotencyViolation` | fault  | Idempotency mode: 2xx responses with more than one body fingerprint |
| `contractDrift`    | warn/fault | Responses that broke `BurstSpec.contract`; fault when any is 2xx |

`BurstSpec.contract` (the selected OpenAPI route's contract, sent while the panel targets that
operation) checks every response. Workers keep up to 64 KiB of the body (a longer body is
checked by status only, bounding a 100-worker burst at 6.4 MiB); the check runs on the
collector after the timed section, so parsing never delays another worker's I/O. Violations
are attached to each `WorkerSample` and streamed with `burstSample`; `contractViolations`
counts drifted responses, and the anomaly names the most widespread violation with the
values that broke it (`/remainingUses: expected >= 0, got -1, -2`).

`BurstSpec.expectedMaxSuccesses` sets the quota: the number of 2xx the operation may
legitimately produce (1 for a single-use coupon or an idempotent charge, `0` for a resource
that is already spent). Without a quota, one 2xx plus conflicts is correct serialization and
twenty 2xx with no conflict are indistinguishable from an operation that admits everyone, so
neither is reported. With a quota, any surplus is a race window whether or not a conflict was
returned. The UI field "Max 2xx" sends `null` for 0.

`BurstSpec.idempotencyMode` (POST, PUT, PATCH; absent means off) sends one `Idempotency-Key`
from every worker: the operator's header when present, otherwise a UUID generated before the
barrier, echoed as `idempotencyKey` in the report and in `burstStarted`. Several 2xx responses
are then expected replays, so the race analysis is replaced by a body comparison: a
deduplicating handler answers every request with the stored response of the first, and more
than one 2xx fingerprint means the operation ran again (`idempotencyViolation`). 409 responses
to in-flight duplicates are accepted. 2xx body divergence is reported only through that
anomaly. The Burst panel's "Idempotency-Key replay" switch sets the mode; its "Sync" selector
sets `syncMode`.

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
(`*`, `[...slug]`, `{path...}`, `{*rest}`) become `{*name}`.

Mount prefixes are resolved when the mount and the mounted router are declared in the same
file. The prefix is joined into `path` and reported separately in `prefix`:

| Framework | Resolved mounts                                                                 |
|-----------|---------------------------------------------------------------------------------|
| Express   | `parent.use("/p", child)`, including middleware arguments and arrays (`[auth, router]`); chains such as `app.use("/api", api)` + `api.use("/admin", admin)` compose |
| Hono      | `new Hono().basePath("/p")`, derived `const v1 = app.basePath("/v1")`, `parent.route("/p", subApp)` |
| Axum      | `.nest("/p", r)` where `r` is built inline, bound with `let r = ..;`, or returned by a local `fn r()` / `self::r()`; nested nests compose |

A router mounted under several prefixes is reported once per prefix (at most 16). Routers
mounted from another file or module (`require("./users")`, `other::routes()`), Fastify
`register(.., { prefix })` and gin groups keep the path written at their declaration.

OpenAPI and Swagger operations with a JSON request body (`application/json` or `*+json`; a
Swagger 2.0 `in: body` parameter) carry `sampleBody`, a pretty-printed payload. Literal examples
win: the media `example`, the first `examples` entry, then schema `example`, `default`, `const`
and the first `enum` value. Otherwise the schema is synthesized: local `$ref` chains are
followed (recursive references are cut at the first repeat, remote ones yield `null`),
`allOf` is merged, the first `oneOf`/`anyOf` branch is taken, `readOnly` properties are
omitted, numbers take the smallest value inside `minimum`/`maximum` (exclusive forms of 3.0
and 3.1, default 1), strings respect `minLength`/`maxLength` and common `format`s. YAML
scalars are typed by the YAML 1.2 core schema, so `age: 3` stays a number and `tag: '7'` a
string.

Every operation with documented `responses` carries `contract: ResponseContract`: explicit
status codes, range keys (`4XX`), `default`, and for the 200 (else 201) JSON body the type and
`required` flag of every property as RFC 6901 pointers, nested objects to depth 3 (at most 96
fields). `$ref` responses and schemas are followed, `allOf` parts merged, `oneOf`/`anyOf`
become type unions (an unconstrained branch accepts anything), 3.0 `nullable` and 3.1
`type: [.., "null"]` admit `null`, `writeOnly` properties are skipped. Swagger 2.0 response
`schema` is read the same way. Each field also carries the value constraints declared on its
own schema as `constraints: ValueConstraints | null`: `minimum`/`maximum` with exclusivity
(3.0 boolean flag or 3.1 number form), `minLength`/`maxLength`, an all-scalar `enum` (at most
64 members) or `const`, and the `uuid`, `email`, `date-time` and `date` formats; composed
schemas contribute none. `engine/contract.rs` checks a response against it:

| Violation              | Condition                                                          |
|------------------------|--------------------------------------------------------------------|
| `undocumentedStatus`   | 2xx or 4xx status not listed, not covered by a range, no `default`  |
| `missingRequiredField` | Required property absent while its parent object is present        |
| `responseTypeMismatch` | Value type outside the documented types; an integer satisfies `number` |
| `constraintViolation`  | Correctly typed value outside its bounds, length, enum or format (`>= 0 <- -1`, `format uuid <- "order-1"`) |

Integer bounds compare exactly across the `i64`/`u64` range, enum members compare
numerically (`1` equals `1.0`), string length counts Unicode scalar values, and a `null`
value is never judged against constraints. Formats follow RFC 3339 (`date-time` requires an
offset, month lengths and leap years are checked); `email` only rejects values that cannot be
an address. `pattern` is not evaluated. 5xx statuses are faults wherever they appear and are
not judged as drift. Bodies above 1 MiB get the status check only; at most 16 violations are
reported per response.

### Static handler audit

Each route extracted from source (`scanner/audit.rs`; OpenAPI routes have no handler) gets
the region of its handler: the declaration up to the next route or top-level declaration (at
most 160 lines), plus the bodies of up to three handlers it names that are defined in the same
file (`post(create_item)`, `app.post("/x", validate(schema), create)`,
`router.post("/x", asyncHandler(create))`, `mux.HandleFunc("POST /x", createItem)`). A
dotted reference lands on the member it names: `router.post("/x", controller.create)` with
`const controller = new OrdersController()` is the `create` method or arrow property of that
class, and `handlers.remove` the `remove` property of `const handlers = { .. }`; a member's
region runs from its line to the end of its function body. A member's head is matched up to
the `(` of its parameter list and the list itself by bracket, so defaults that call functions
(`limit = Number(env.LIMIT)`), NestJS parameter decorators (`@Body() dto`, `@Param('id') id`),
decorators on the same line (`@Get(':id') async show(`) and return types with object
literals (`Promise<{ id: string }>`) do not hide it; a parenthesized value (`total: (a + b)`)
and an overload signature without a body are not members. A Next.js App Router method export
that does not hold the handler in place is followed to it: `export { POST } from "m"`,
`export { create as POST }` and `export const POST = withAuth(create)`.

A JavaScript or TypeScript handler that the file imports or re-exports from another module is
audited in that module. Bindings come from `import x from`, `import { a, b as c } from`,
`import * as ns from`, `const x = require(..)`, `const { a, b: c } = require(..)` and
`require(..).a`; type-only imports are ignored. `create` resolves to the binding's export and
`ns.create` to the named export `create`; `orders.create` on a default or named import is the
`create` member of the class instance or object literal exported there
(`export default new OrdersController()`, `module.exports = { create: .. }`), and
`controller.create` on an instance of an imported class is the member of that class in its
module. A relative specifier is joined to the file's directory; a `#name` specifier goes
through the `imports` of the nearest `package.json` inside the scan root (Node's subpath
imports: an exact key first, else the wildcard key with the longest prefix, every `*` of the
target replaced; condition objects take `node`, `import`, `require` or `default` in object
order, fallback arrays in order, local `./` targets only); any other goes through the nearest
`tsconfig.json` / `jsconfig.json` inside the scan root (`scanner/tsconfig.rs`):
`compilerOptions.paths` (an exact pattern first, else the wildcard with the longest prefix,
each substitution in order) and then `baseUrl`, both read through relative `extends` chains in
TypeScript's JSON-with-comments dialect. A package name no alias covers resolves to nothing.
Each candidate is tried as written, with each JS/TS extension, as a directory `index`, and a
`.js` path also as the `.ts` source beside it. The canonical path must stay inside the scan
root, at most 16 modules are read per file (each once, 1 MiB cap, loaded into fixed slots
when first reached), and the export is located as a named declaration, `exports.x =`,
`module.exports.x =`, `export default`, `module.exports =`, or a member of the exported
container. A module that does not define the export is followed up to two modules further:
`export { x as name } from "m"`, then an imported binding it passes on (`import { name } from
"m"; export { name }`), then each `export * from "m"` (at most four); the member of an exported
instance whose class is imported (`export const orders = new OrdersController()` in a barrel,
the class in a third module) resolves to that class's member there. Evidence found there
carries the module's path in `file`.

Checks run on the comment-masked text of every region and need positive evidence, so a
handler the pass cannot resolve reports nothing:

| Risk                   | Evidence                                                              |
|------------------------|-----------------------------------------------------------------------|
| `unvalidatedMutation`  | POST/PUT/PATCH/DELETE reads the body (`req.body`, `request.json()`, Hono `c.req.parseBody()` / `text()` / `arrayBuffer()`, `Json<..>`, `r.Body`), in code or inside a `${..}` template expression, and the region has no validator (Hono `c.req.valid(..)` returns already validated input and counts as one): zod, valibot, joi, yup, ajv, superstruct, TypeBox, Fastify `schema:`, `validate*`/`*Validator`, `X.parse(` / `safeParse(` on anything but `JSON`, `Date`, `URL`, `qs`; typed axum `Json<T>`/`Form<T>` or `from_slice::<T>` (`Value`/`HashMap` do not count); gin `Bind*`, typed `Decode(&..)`, `json.Unmarshal` |
| `unboundedQuery`       | `findMany(` / `findAll(` / `find({..})` / GORM `Find(&..)` without `take`/`limit`/`first`/`last` in the arguments or the chain; a `SELECT .. FROM` string literal without `LIMIT`, `TOP`, `FETCH FIRST`, an aggregate or an `id =` lookup |
| `floatingAsync`        | JS: a persistence call (`save`, `create`, `update`, `delete`, `insert*`, `execute`, `query`, `publish`, `sendMail`, `commit`, ... on a model chain or a db/queue receiver) or `fetch(` as a statement, neither awaited, returned nor chained to `.then`/`.catch`; an async Express handler that awaits without `try`, `next(err)` or `.catch(next)`, unless wrapped (`asyncHandler`, `catchAsync`), `express-async-errors` is loaded, or the nearest `package.json` declares Express 5 (`^5`, `~5`, `>=5`, `npm:express@5`), which forwards rejections natively. Go: `Exec`/`Commit`/`Create`/`Save`/`Delete`/`Update` as a statement, error dropped. Rust is skipped: unused futures and `Result`s are compiler warnings |
| `nonAtomicMultiWrite`  | Writes, one per statement: ORM `create`/`update`/`upsert`/`delete`/`insert*`/`save`/`destroy` on a client root (`db`, `prisma`, `knex`, `repo`, `tx`, ...), a model chain or a capitalized model, `await x.save()`, also with the chain broken across lines (`prisma.order` / `.create(`); `execute`/`Exec`/`ExecContext` unless the statement selects (labelled by its SQL); `INSERT INTO`, `UPDATE .. SET`, `DELETE FROM` literals (a literal inside a write call, or in the same statement, is that call's write). Reported when one write runs inside a loop (`for`, `for await`, `while`, `do`, `forEach`/`map`/`flatMap` callbacks; Rust `for`/`while`/`loop`/`for_each`; Go `for`), or when two or more writes include one outside every transaction. A transaction covers only what it encloses: the arguments of `$transaction(..)`, `.transaction(..)`, `withTransaction(..)`, GORM `Transaction(..)`, Diesel/SeaORM `transaction::<..>(..)`; writes on a `tx`/`trx`/`txn` receiver or passed one (`&mut *tx`, `{ transaction: t }`); everything under `@Transactional` / `#[transactional]`. A begin bound to a name (`const tx = await db.begin()`, `const t = await sequelize.transaction()`, `const trx = await knex.transaction()`, `let mut tx = pool.begin().await?`, Go `tx, err := db.Begin()` / `BeginTx(`) covers only writes through that handle (its receiver, or the handle among the arguments); a later write still on the connection it was begun on is reported even as the only write: "write on 'db' bypasses active transaction handle 'tx'". A begin without a binding (`client.query("BEGIN")`, `session.startTransaction()`) covers the writes after it. A model named `transaction` is not a handle. Receivers through request, response or in-memory state (`searchParams`, `session`, `cache`, `headers`, ...) and Go file packages (`os.Create`) never count |
| `unsafeSqlInterpolation` | A literal shaped like SQL (`SELECT .. FROM`, `INSERT INTO`, `UPDATE .. SET`, `DELETE FROM`, `WHERE col =`/`LIKE`/`IN`) built from values: an untagged template literal with `${..}` (tagged templates such as `` sql`..` `` and `` Prisma.sql`..` `` pass values as parameters and stay clean), a quoted literal followed by `+ expr`, the format string of `format!` with a placeholder, or of `fmt.Sprintf` with a verb |
| `blockingInAsync`      | Inside a handler body: JS `readFileSync`, `writeFileSync`, `appendFileSync`, `existsSync`, `statSync`, `readdirSync`, `execSync`, `execFileSync`, `spawnSync`, `pbkdf2Sync`, `scryptSync`, bcrypt `hashSync` / `compareSync` / `genSaltSync` (every JavaScript handler runs on the event loop, `async` or not); Rust `std::thread::sleep`, `std::fs::*`, `bcrypt::hash` / `verify` in an `async fn` handler, unless inside `spawn_blocking` / `block_in_place`. Module-scope calls after a route (a template read at startup) and mentions in strings are not findings |

Risks carry `kind`, `line`, the trimmed evidence line, a `detail`, and `file` when the
evidence is in an imported module. The route list shows a badge per risk, filters by
`at risk` or one kind, and lists the evidence of the selected route.

A risk badge (or the `burst` / `fuzz` button next to the selected route's evidence)
auto-targets the finding: it selects the route, loads its method, path, sample body and
contract, and opens the tab that exercises the failure mode with a fresh setup:

| Risk                     | Opens  | Preset                                                        |
|--------------------------|--------|---------------------------------------------------------------|
| `unvalidatedMutation`    | Fuzzer | `nullInjection`, `boundaryNumbers`, `typeConfusion`, `missingFields`, `schemaContractBounds` |
| `unsafeSqlInterpolation` | Fuzzer | `emptyStrings`, `typeConfusion`, `oversizedField`, `pathParamValidation`, `delimiterEscaping`, `queryAndHeaderBounds` |
| `floatingAsync`          | Fuzzer | `nullInjection`, `typeConfusion`, `malformedJson`             |
| `nonAtomicMultiWrite`    | Burst  | 32 workers, `lastByte` sync                                   |
| `unboundedQuery`         | Burst  | 32 workers, `lastByte` sync                                   |
| `blockingInAsync`        | Burst  | 32 workers, `lastByte` sync: a blocked loop serves them in turn, so TTFB p95 grows with queue position |

Selecting a route loads its method and path into the Burst and Fuzzer panels, loads its
`sampleBody` (if any) into both payload fields, and adds an endpoint node to the topology.

`{param}` and `{*param}` placeholders left in a Burst or Fuzzer target are resolved by the
engine (`engine/pathparam.rs`): every slot is sent as `1`, and the fuzzer's
`pathParamValidation` vector varies one slot at a time. Placeholders are replaced with
alphanumeric markers before the target goes through the loopback guard, so the slots are read
back from the normalized path (dot segments resolved, unsafe bytes percent-encoded) and a
placeholder in the authority is rejected like any other non-loopback host. Placeholders in
the query take the default and are not varied. A rewritten path changes only the request
line; the request goes to the connection opened for the validated target.

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
| `schemaContractBounds` | Valid JSON syntax that a strict schema refuses: each top-level key (at most 8) repeated with a conflicting value of the same type; an extra field nested 64 and 1 024 objects deep; undeclared fields (`zproxyExtra`, `isAdmin`, and one inside the first object field); each numeric field set to the literal `1e309` |
| `pathParamValidation` | Each `{param}` slot of the target path (at most 8) set to `0`, `-1`, `9223372036854775807`, `9223372036854775808`, `invalid-uuid`, the empty segment, and 4 096 digits; other slots stay `1`, the body is the base |
| `delimiterEscaping` | Each string field set to five ordinary catalogue values carrying the delimiters a string-built query, path or pattern must escape: `O'Reilly & Sons`, `15" display \ rev-2`, `item; category(1)`, `100%_discount_*`, and `cafe` followed by U+0301 (combining acute) and U+200B (zero-width space) and `test`, sent as raw UTF-8 (13 bytes, 10 characters) |
| `queryAndHeaderBounds` | Ten query cases, each replacing the parameter of the same name in the target's query: `limit=-1`, `limit=0`, `limit=1000000`, `page=0`, `page=-1`, `offset=-10`, `offset=9223372036854775807`, `sort=nonexistent_column`, `id=1&id=2`, `q=O%27Reilly`; then six header cases: `Accept: text/plain`, an empty `Accept`, `Content-Type: text/plain`, `application/x-www-form-urlencoded`, an empty `Content-Type`, and `application/json; charset=utf-16`. The body stays the base |

Classes run in the order above; new classes are appended, so case indices of earlier classes
never shift. Duplicate keys test parser differentials: a validator that keeps the first
occurrence and a handler that keeps the last disagree about the same body. The two nesting
depths sit inside common parser limits (serde_json 128, Python 1 000) and past them, where a
recursive parser or sanitizer runs out of stack.

Delimiter values are harmless text: storing one verbatim or refusing it with a 4xx is correct,
so acceptance raises no warning; a 5xx or a leaked driver error is the finding. The vectors
never carry exploit payloads. The same holds for the query bounds: clamping a limit or
returning an empty page is correct, a 5xx or a leaked driver error is not. The header cases
judge content negotiation: `text/plain` and form encoding are CORS-safelisted, so a browser
sends them cross-site without a preflight, and a write (POST, PUT, PATCH, DELETE) that parses
its JSON body under them is reachable from any page; a read may ignore the body they describe.

The default template yields 131 cases (no path cases without a placeholder). An unmutated
baseline request runs first. Cases run sequentially, one connection each, with
`Connection: close` and `x-zproxy-fuzz-case: <index>`; `Content-Type: application/json` is
added unless the operator sets one, and a header case replaces the default and the
operator's value alike.

| Response                                   | Verdict            | Severity               |
|--------------------------------------------|--------------------|------------------------|
| 4xx                                        | `rejected`         | none                   |
| 1xx-3xx                                    | `accepted`         | warn for `malformedJson`, `schemaContractBounds`, `pathParamValidation`, and the `text/plain` / form-encoded header cases of a write; fault for a mass assignment |
| 5xx                                        | `serverError`      | fault                  |
| Reset, closed before a response, timeout   | `transportFailure` | fault                  |
| Connect failure                            | `unreachable`      | none                   |

A `schemaContractBounds` case that adds an undeclared field (`zproxyExtra`, `isAdmin`, one
inside the first object field) and gets the same value back in its 2xx JSON response, at the
field's pointer or under one top-level envelope key (`{"data": {..}}`), is a mass assignment:
the service bound request input it does not document onto its model. The case becomes a fault
with `massAssignment { pointer, echoedAt, value, detail }` (`mass-assignment: undeclared field
'isAdmin' was accepted and echoed in 2xx response`), and `massAssignments` counts them. These
cases capture the response body up to 1 MiB so it can be parsed whole; an undeclared field
accepted without coming back stays a contract warning.

Three consecutive connect failures abort the run; the remaining cases are `skipped` and the last
case that reached the service is marked as a fault. A baseline that was not accepted is reported
as a note. One suite runs at a time (`FUZZER_BUSY`); `cancel_fuzzer_suite` stops between cases.
Response bodies are fingerprinted in full and the first 2 KiB are kept as a preview.

The preview of every response, whatever its status, is checked for disclosure signatures
(`engine/disclosure.rs`). A match is attached to the case as `disclosure { kind, evidence }` and
raises a case without other findings to severity warn, so a 400 that serializes a parser stack
trace is reported even though the payload was rejected. Patterns require structure, not
keywords, and accept JSON-escaped (`\n`) traces:

| Kind               | Signature                                                                  |
|--------------------|----------------------------------------------------------------------------|
| `nodeStackTrace`   | `at fn (path.js:line:col)`, `.mjs/.cjs/.ts/.tsx/.jsx`, `node:internal` frames |
| `pythonTraceback`  | `Traceback (most recent call last)`, `File "x.py", line N, in`             |
| `rustPanic`        | `panicked at src/x.rs:line:col`                                            |
| `goPanic`          | `goroutine N [state]:`, `panic: runtime error:`                            |
| `jvmStackTrace`    | `at pkg.Class.method(File.java:N)` (also `.kt`, `.scala`)                  |
| `dotNetStackTrace` | `at Ns.Type.Method(..) in path:line N`                                     |
| `sqlError`         | MySQL syntax error, PostgreSQL `syntax error at or near` / `invalid input syntax` / `out of range for type` / missing relation / negative `LIMIT` or `OFFSET`, `SQLSTATE[..]`, `ORA-NNNNN`, SQLite, psycopg2, MSSQL unclosed quotation |
| `sensitiveFieldLeak` | 2xx JSON only: a string field named `password`, `passwordHash`, `hashedPassword`, `passwordDigest`, `encryptedPassword`, `salt`, `twoFactorSecret`, `otpSecret`, `privateKey`, `resetToken` (any case, `_` / `-` ignored), or `secret`, `clientSecret`, `apiKey`, `refreshToken` outside a route with a `token`, `auth`, `oauth`, `login`, `session`, `keys`, `clients` segment; or any value in a bcrypt (`$2a$` / `$2b$` / `$2y$`), argon2, scrypt or PBKDF2 format. Masked values (`********`, `[redacted]`) are clean |

Runtime traces take precedence over database errors found in the same body. The report counts
affected mutation cases in `disclosures`; a disclosing baseline is reported as a note. A
sensitive field the baseline already exposes belongs to the route, not to a mutation: the note
names it once and cases exposing the same field are not charged with it.

`FuzzSpec.contract` (the selected OpenAPI route's contract, sent while the panel targets that
operation) checks the baseline and every case response. Bodies are then captured up to 1 MiB
for the check; the preview stays at 2 KiB. Violations are attached as `violations` and raise a
case without other findings to warn, like a disclosure; `contractViolations` counts requests,
baseline included, whose response drifted, and a drifting baseline is reported as a note.

Each finding offers two escalations. "Send to burst" loads the case's exact body, the suite's
method and its path into the Burst panel, so a payload that broke one request is fired from N
pre-connected workers (a crash that only appears under contention, or a race on an error
path). A path or query case is replayed with its exact target; a body case keeps the path
template, so the burst runner sends the same default identifier; a header case writes its
override into the Burst headers, replacing the line of the same name and keeping the
operator's others. "Load payload" makes the body the fuzzer's base payload for a second suite
around it; it is not offered for malformed and contract cases (a duplicate key or `1e309`
does not survive re-parsing into a base object) or for path, query and header cases (the body
is the base). The report carries `baseBody` (the base as sent), `classes`, `pathTemplate` and
`target`; `materialize_fuzz_case` regenerates case `index` from them, returning `path` for
path and query cases and `headers` for header cases, instead of the report holding every
payload (oversize cases are 64 KiB each). A query case needs `FuzzCaseRef.target` (optional,
so older callers stay valid) and is refused with `INVALID_FUZZ_SPEC` on `target` without it.
Bodies that were not valid UTF-8 come back with `lossy: true` and U+FFFD in place of the
invalid bytes; the Burst panel shows the replayed case and that substitution.

## Target lab

An embedded Axum service (`engine/lab.rs`) that gives the burst runner, fuzzer and proxy a
known target. It binds `127.0.0.1:17480`, or an ephemeral port when 17480 is taken (an
explicit port is bound exactly and fails with `LISTENER_BIND_FAILED`). The mode switches at
runtime without a restart and clears the coupon ledger, so both modes are observed from the
same state.

| Route                           | `unprotected`                                             | `hardened`                                   |
|---------------------------------|-----------------------------------------------------------|----------------------------------------------|
| `POST /api/v1/coupons/redeem`   | Reads the coupon's use count, waits 60 ms (provider call), writes back `read + 1`; the 200 body names the discount `discount` instead of `discountCents`, and `remainingUses` drops below 0 for every extra winner; no code is 400 | Check and increment under one lock, then the provider call; `remainingUses` is 0; no code is 422 |
| `POST /api/v1/orders/checkout`  | Unvalidated input reaches failing code; the failure is serialized into the response; `Idempotency-Key` and `Content-Type` ignored; undeclared scalar fields stored on the order | Every invalid input: 422 `{ error, violations[] }`; a declared `Content-Type` other than `application/json` (charset `utf-8` if given) is 415; `Idempotency-Key` deduplicated |
| `GET /api/v1/orders/{orderId}`  | `Number(orderId)` used as an index and passed raw to SQL  | `orderId` must be an integer 1-999 999, else 422 |
| `GET /api/v1/orders`            | `limit`, `offset`, `page`, `sort`, `id` and `q` spliced into one SQL string; the PostgreSQL error is serialized with the query | Every parameter validated first; repeated or unknown parameters, values out of range: 422 `{ error: "invalid_query", violations[] }` |
| `GET /api/v1/health`            | `{ status, mode }`                                        | same                                         |
| `GET /api/v1/lab/openapi.json`  | OpenAPI 3.1 document of the above                         | same                                         |

The document declares response schemas (`Order`, `OrderPage`, `Redemption`, `Health`,
`Error`, `ValidationError`), so the extracted contracts cover every route. Unprotected orders
carry `totalCents` as a string (`"9998"`), redemptions miss `discountCents`, order pages miss
`limit` and `offset`, and the 400/404 responses are undocumented; hardened responses match
the document exactly. Unprotected order responses (checkout, lookup and list items) return the
stored document instead of the `Order` DTO: the joined account row with a bcrypt-shaped
fixture hash (`customer.passwordHash`, which no password produces) and every undeclared scalar
field the checkout body carried (`Order.create({ ...req.body })` in a schemaless store, at
most 8 fields of 64 characters, documented fields never replaced). The passive audit reports
the hash as a `passiveDisclosure` fault and the fuzzer echoes of `isAdmin` and `zproxyExtra`
as mass assignments; hardened checkout refuses those fields with 422 and every hardened order
response is the documented projection. Unprotected responses also carry
`Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`, which the
passive audit reports on every proxied exchange.

Hardened checkout with an `Idempotency-Key` (1-255 visible ASCII characters, else 422)
claims the key, creates the order and records the response under one ledger lock, so
concurrent duplicates replay the stored 201 with `Idempotent-Replayed: true` and the order
counter grows by one. Reusing a key with a different body is 422 `idempotency_key_reused`;
only completed orders are recorded, and at most 1 024 keys are kept. Unprotected checkout
creates one order per request whatever the key, which an idempotency-mode burst reports as
`idempotencyViolation`.

Coupon `LAB-SINGLE-USE` admits one redemption. Each redemption in flight adds 5 ms of lookup
latency (a saturated pool), which spreads a burst's reads across the 60 ms commit window: in
`unprotected` mode the early reads all pass the check (several 200) and the late ones see the
write (409), which the burst analyzer reports as `raceWindow`. The written count stays at 1
(lost update) while `granted` counts every 200. In `hardened` mode exactly one request gets
200 and the rest 409. The window is wider than Windows' 15.6 ms timer resolution, so the
outcome does not depend on timer precision; with 17 or more workers at least one conflict is
guaranteed.

Redemptions report `remainingUses` (documented `integer`, `format: int32`, `minimum: 0`),
derived from the grant count. A burst with the route's contract therefore reports
`raceWindow` and `contractDrift` together in `unprotected` mode: every extra winner returns
`-1`, `-2`, ..., a 2xx body below its documented minimum, next to the missing
`discountCents`. `hardened` returns 0 to its single winner and stays clean.

Unprotected checkout failures, by input:

| Input                                                     | Response                                         |
|-----------------------------------------------------------|--------------------------------------------------|
| Malformed JSON                                            | 400 with a body-parser `SyntaxError` stack trace |
| Missing or `null` field, `null` note, non-object root     | 500 Node.js `TypeError` stack trace              |
| Non-string `sku`, `sku` containing `'` (`O'Reilly & Sons`) | 500 MySQL driver error object with the query     |
| String `quantity` (`"NaN"`, `"1"`)                        | 500 PostgreSQL `invalid input syntax` error      |
| Negative `quantity`                                       | 500 Go panic with goroutine dump                 |
| `quantity` above 10 000                                   | 500 Rust panic (index out of bounds)             |
| String above column length (sku 64, email 254, name 64, note 256) | 500 Python traceback ending in psycopg2 `StringDataRightTruncation` |
| Nesting beyond 128 levels                                 | 500 Node.js `RangeError: Maximum call stack size exceeded` |
| Number outside `f64` range (`1e309`)                      | 500 Rust panic from an `unwrap()` on the decode error |
| `quantity` 0, empty email or name, unknown fields (scalars stored and returned on the order), duplicate keys (last one wins), deep nesting under an unknown field, a JSON body declared `text/plain` | 201 (accepted without validation) |

Hardened checkout enforces the documented schema: `sku` `^[A-Z0-9-]{1,32}$` and in the
catalog, `quantity` integer 1-10 000, `customer.email` and `customer.name` required, `note`
optional string up to 256, `giftWrap` optional boolean, unknown fields rejected
(`additionalProperties: false`), body at most 32 KiB. Before field validation it refuses
nesting deeper than 8 levels and any key repeated within one object (the violation names the
duplicate's pointer); numbers outside `f64` range and nesting past the parser limit are
422 `malformed_json`. Delimiters are data there: the `delimiterEscaping` vector gets a clean
422 on the patterned `sku` and `customer.email`, and 201 with the value stored in
`customer.name` and `note`, where unprotected mode answers the apostrophe in `sku` with the
MySQL syntax error.

A checkout burst in idempotency mode with last-byte sync shows the replay contract at the
tightest overlap a client can produce: unprotected mode creates one order per worker under the
same key (`idempotencyViolation`, plus `contractDrift` for the string `totalCents` when the
route contract is attached); hardened mode claims the key, creates and records under one lock
and answers every worker with the stored response, under last-byte and pre-connected release
alike.

Order lookup serves the seeded history (orders 1-3) and every order confirmed by checkout
since the last reset or mode switch (at most 1 024). Unprotected responses, by `orderId`:

| `orderId`                                       | Response                                          |
|-------------------------------------------------|---------------------------------------------------|
| Known id                                        | 200 order                                         |
| Unknown positive integer                        | 404                                               |
| Empty segment, `0`, negative, fractional        | 500 Node.js `TypeError` stack trace               |
| Non-numeric (`invalid-uuid`)                    | 500 PostgreSQL `invalid input syntax for type bigint` |
| At or above `i64::MAX` (`9223372036854775807`)  | 500 PostgreSQL `out of range for type bigint` (SQLSTATE 22003) |
| Digits beyond `f64` range                       | 500 Python traceback ending in psycopg2 `NumericValueOutOfRange` |

Hardened lookup accepts only canonical decimal identifiers without sign or leading zero in
1-999 999 and answers anything else, including the empty segment, with
422 `{ error: "invalid_path_parameter", parameter, reason }`, without echoing the input.

The order list pages the same orders. Unprotected mode builds
`SELECT .. WHERE sku ILIKE '%<q>%' [AND id = <id>] ORDER BY <sort> LIMIT <limit> OFFSET <offset>`
the way an unvalidated Express gateway does (`qs` turns a repeated key into an array that
renders comma-joined, `Number()` converts paging input and renders 2^63 as
`9223372036854776000`) and answers what PostgreSQL answers to that string, as a 500 carrying
the driver's error object and the query:

| Query (the `queryAndHeaderBounds` vector)        | Response                                                    |
|--------------------------------------------------|-------------------------------------------------------------|
| `limit=-1`                                       | 500 `LIMIT must not be negative` (SQLSTATE 2201W)            |
| `page=0`, `page=-1`, `offset=-10`                | 500 `OFFSET must not be negative` (2201X)                    |
| `offset=9223372036854775807`                     | 500 `value "9223372036854776000" is out of range for type bigint` (22003) |
| `sort=nonexistent_column` (also `sort=totalCents`, folded to `totalcents`) | 500 `column "nonexistent_column" does not exist` (42703) |
| `id=1&id=2`                                      | 500 `syntax error at or near ","` (42601)                    |
| `q=O%27Reilly`                                   | 500 `unterminated quoted string at or near "' ORDER BY id LIMIT 20 OFFSET 0"` |
| `limit=0`, `limit=1000000`                       | 200, an empty page or every order                           |

Hardened mode accepts `limit` 1-100 (default 20), `offset` 0-10 000 or `page` 1-500 (not
both), `sort` among `id`, `sku`, `quantity`, `totalCents` with an optional `-`, and `q` up to
64 characters matched as data, and answers with `{ items, limit, offset, total }`; the
apostrophe search is a 200 with no match. Header cases are answered like any other read in
both modes.

"Load Lab Target" in the inspector sets the lab as the validated target (so the proxy
upstream and the Burst/Fuzzer origin follow), replaces the route list with the routes parsed
from the lab's OpenAPI document (`get_lab_routes`, through the same OpenAPI extractor and
body synthesis as a scanned project), preselects the redeem route with its sample body and
opens the Burst tab. Every request the lab serves is reported as a `labExchange` event with
the handler outcome and live counters.

"Via Proxy" in the inspector ("Route lab traffic via proxy" in the command palette) chains the proxy in front of the lab in one
step: it reuses a listener that already forwards to the lab, restarts one that forwards
elsewhere, or starts one on port 8787, then sends Burst and Fuzzer traffic to the listener.
The fault profile and route rules survive the restart. The inspector keeps the lab as the
validated target, so the proxy upstream and the topology still point at the service; the
Burst and Fuzzer origin rows show `via proxy -> <upstream>`. Requests fall back to the lab
directly whenever the listener stops or stops fronting the validated target, and the same
control switches back explicitly. With the redeem route bound to a rule (for example `503`
at 30 %), a burst through the listener shows how the rule interleaves with the lab's
conflicts, and both `proxyExchange` and `labExchange` events describe each request.

The topology's endpoint node lists the first proxy rule that applies to the selected route,
using the engine's matching rules (template segments, `{*rest}`, collapsed empty segments,
upstream base path prefixed; a route template's own `{param}` segments stand for any one
segment). The rule and the edge into the endpoint are drawn in the degraded tone while the
listener runs armed, and the rule is marked inactive otherwise.

## Audit report

The header's Report group and the command palette export the session state as one report:
guard verdict and probe, request origin (direct or via proxy), target lab mode and counters,
proxy listener, global profile (mid-body drop included) and route rules, the latest burst
report (barrier sync mode with the dispatch spread measured under it, status histogram, TTFB
and total latency percentiles, success quota, idempotency key, contract drift count,
anomalies), the latest burst of each sync mode side by side (`burstSync`: run, request,
workers, dispatch spread, TTFB p50, wall time, anomalies, and whether it sent the same request
as the reported burst; `burstComparison`: the last-byte spread against the pre-connected one
when both sent the same request) and the latest fuzz report (vector summary, notes, mass
assignment count, findings with mass-assignment evidence, disclosures and contract drift).
Four further sections
summarize the passive traffic audit (all seven counters and retained findings, faults
first), contract drift (proxied violations, drifting fuzz requests and drifting burst
workers), the static route audit of the route list in view (evidence location, with the
declaring file when the handler is imported), and the idempotency replay outcome. The report
is built in the UI (`src/lib/export.ts`) from state it already holds; nothing is re-run.

| Action | Output                                                                                   |
|--------|------------------------------------------------------------------------------------------|
| `.md`  | Tabular Markdown; the first 200 findings, faults first                                    |
| `.json`| `AuditReport` with `schema: "z-proxy.audit/5"`; burst samples and every finding included  |
| Copy   | The Markdown rendering to the clipboard                                                   |

`save_audit_report` opens the native save dialog from Rust (the webview has no `fs` or
`dialog` capability), pre-filled with `z-proxy-audit-<yyyymmdd>-<hhmmss>.<ext>` reduced to a
single file name component, and writes the file off the async runtime. Reports above 32 MiB
and write failures return `REPORT_EXPORT_FAILED` with the destination `path` when one was
chosen; cancelling resolves to `null`.

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
| `set_fault_rules`        | `rules: FaultRule[]`                        | `ProxyStatus`      |
| `set_proxy_contracts`    | `contracts: RouteContract[]`                | `ProxyStatus`      |
| `run_concurrency_burst`  | `spec: BurstSpec`                           | `BurstReport`      |
| `run_fuzzer_suite`       | `spec: FuzzSpec`                            | `FuzzReport`       |
| `cancel_fuzzer_suite`    | none                                        | `boolean`          |
| `materialize_fuzz_case`  | `reference: FuzzCaseRef`                    | `FuzzCasePayload`  |
| `scan_project_routes`    | `root: string`                              | `RouteScanReport`  |
| `pick_project_root`      | none                                        | `string \| null`   |
| `start_lab_server`       | `config: LabConfig`                         | `LabStatus`        |
| `stop_lab_server`        | none                                        | `LabStatus`        |
| `set_lab_mode`           | `mode: "unprotected" \| "hardened"`         | `LabStatus`        |
| `reset_lab_state`        | none                                        | `LabStatus`        |
| `get_lab_status`         | none                                        | `LabStatus`        |
| `get_lab_routes`         | none                                        | `RouteScanReport`  |
| `save_audit_report`      | `format: "markdown" \| "json", fileName: string, contents: string` | `string \| null` |

Telemetry is pushed over `tauri::ipc::Channel<TelemetryEvent>`; the UI does not poll.
Event kinds: `engineHeartbeat` (1 Hz), `guardDecision`, `probeCompleted`,
`proxyStateChanged`, `proxyExchange`, `burstStarted`, `burstSample`, `burstCompleted`,
`fuzzerStarted`, `fuzzerCaseCompleted`, `fuzzerCompleted`, `routeScanCompleted`,
`labStateChanged`, `labExchange`.

## Wire identifiers

Every value the engine writes onto the wire, so upstream logs can attribute test traffic:

| Origin       | Field                          | Value                                    |
|--------------|--------------------------------|------------------------------------------|
| Proxy        | `Via`                          | `1.1 z-proxy`                            |
| Proxy        | `x-zproxy-fault`               | `status-<code>` on synthetic responses, `partial-body-<bytes>` on truncated ones |
| Proxy        | `x-zproxy-injected-delay-us`   | Applied delay on forwarded responses     |
| Proxy        | `x-zproxy-error`               | Upstream failure class on 502/504        |
| Proxy        | JSON body `source`             | `z-proxy` on synthetic and error bodies  |
| Burst runner | `User-Agent`                   | `z-proxy-burst/<version>` unless set     |
| Burst runner | `x-zproxy-burst-worker`        | Worker number, 1-based                   |
| Burst runner | `Idempotency-Key`              | Generated UUID in idempotency mode, unless set |
| Fuzzer       | `User-Agent`                   | `z-proxy-fuzzer/<version>` unless set    |
| Fuzzer       | `x-zproxy-fuzz-case`           | Case index, `0` for the baseline         |
| Fuzzer       | Added fields                   | `zproxyPad`, `zproxyUtf8`, `zproxyNest`, `zproxyExtra`, `isAdmin` |
| Fuzzer       | Query parameters               | `limit`, `page`, `offset`, `sort`, `id`, `q` from `queryAndHeaderBounds` |
| Fuzzer       | `Accept`, `Content-Type`       | Replaced by the header cases of `queryAndHeaderBounds` |

## Requirements

- Node.js 20.19+ (Vite 8)
- Rust 1.90+
- Windows: WebView2 runtime and MSVC build tools
- Linux: WebKitGTK 4.1 development packages (`libwebkit2gtk-4.1-dev`, `libxdo-dev`,
  `libssl-dev`, `libayatana-appindicator3-dev`, `librsvg2-dev`)

## Commands

```
npm install
npm run tauri dev          # desktop app with HMR
npm run build              # tsc + vite build
cd src-tauri
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

`src-tauri/Cargo.toml` denies `unwrap_used`, `expect_used` and `panic` outside tests.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request:

| Job                    | Runner                         | Steps                                                       |
|------------------------|--------------------------------|-------------------------------------------------------------|
| `frontend`             | ubuntu-24.04, Node 24          | `npm ci`, `npm run build`                                   |
| `rust (ubuntu-24.04)`  | ubuntu-24.04, stable toolchain | WebKitGTK 4.1 packages, `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked` |
| `rust (windows-2025)`  | windows-2025, stable toolchain | `cargo clippy` and `cargo test` as above                    |

The Windows job runs the same integration tests (barrier burst, lab race, `SO_LINGER=0`
resets, listener release) on the platform whose timer resolution and socket teardown they
were written against. `--locked` fails the build when `Cargo.lock` is stale.
