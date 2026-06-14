# Wyrtloom — Ecosystem Security Overview

This document ties together the per-repository security models of the Wyrtloom
ecosystem into one picture: the shared threat model, the layered authentication
and root-of-trust, the per-crate controls, and the consolidated known limitations
and operational requirements.

It is a map, not a substitute. Each claim is owned and cited in detail by a
per-repo `SECURITY.md`; this overview links to each. The system has passed **two
adversarial audit rounds** (an internal round and a round-2 core hardening pass);
the per-repo docs carry the finding numbers behind each control.

Per-repo security models:

- Core monorepo (`SecurityModule`, policy/capability model, WASM sandbox,
  canonical encoder) — [`SECURITY.md`](../SECURITY.md) in this repo.
- Dashboard API (router, two-layer auth, RBAC, hardening) —
  [`wyrtloom-dashboard-api`](https://github.com/codepilots/wyrtloom-dashboard-api/blob/main/SECURITY.md).
- Config loader — [`wyrtloom-config`](https://github.com/codepilots/wyrtloom-config/blob/main/SECURITY.md).
- SQLite persistence — [`wyrtloom-store-sqlite`](https://github.com/codepilots/wyrtloom-store-sqlite/blob/main/SECURITY.md).
- User directory (argon2id, RBAC storage) — [`wyrtloom-users`](https://github.com/codepilots/wyrtloom-users/blob/main/SECURITY.md).
- TOFU client auth — [`wyrtloom-clientauth-tofu`](https://github.com/codepilots/wyrtloom-clientauth-tofu/blob/main/SECURITY.md).
- Web SPA client — [`wyrtloom-dashboard-web`](https://github.com/codepilots/wyrtloom-dashboard-web/blob/main/SECURITY.md).
- LLM provider — [`wyrtloom-provider-nous`](https://github.com/codepilots/wyrtloom-provider-nous/blob/main/SECURITY.md).

---

## Threat model

Wyrtloom is a local-first plugin host with an HTTP dashboard. Its security
boundaries assume a hostile environment around a trusted core process:

- **Untrusted browsers and clients.** The dashboard SPA runs in an **untrusted
  execution environment** — any in-page code (including XSS) has the same Web API
  access as the app. The real authorization boundary is on the server, not in the
  client. Every UI affordance is advisory; every write is re-checked server-side.
- **Loopback is not an authentication boundary.** Any local process — or a
  browser-driven SSRF/CSRF pivot — can reach a loopback socket. Binding loopback
  is a deployment rail, not auth: every endpoint except `/api/enroll` is
  client-signature gated and every `Role(...)` endpoint is additionally session
  gated, regardless of bind address.
- **Untrusted external input** — LLM responses, usernames, paths, config TOML,
  request bodies — must not inject terminal escapes, spoof audit logs
  (Trojan-Source), traverse the filesystem, drive SSRF, or exhaust memory/CPU.
- **The lethal trifecta is contained by a WASM sandbox.** Untrusted compute
  (`Safe` plugins, hunt harnesses) runs in a wasmtime sandbox whose `Linker` is
  created **empty and never populated** — a `Safe` module physically cannot name a
  host import for files, network, or shell, so it fails at instantiation if it
  tries. Memory growth is capped by a `ResourceLimiter`, wall-clock time is bounded
  by a shared epoch ticker (with fuel as a secondary backstop), and input/output
  pointers are range-checked against memory size. This is the containment for the
  "data + tools + exfiltration" lethal trifecta.

**Trusted in v0.1:** the operator and host OS; an in-process attacker who can
mutate core memory already holds the keys; DB file paths are operator-supplied;
the configured provider `https` base URL and `--session-key-file` are
operator-trusted.

---

## Two-layer authentication

The dashboard API gates every request through two independent layers (full detail
in the [API reference](https://github.com/codepilots/wyrtloom-dashboard-api/blob/main/docs/api-reference.md#request-authentication) and the
[dashboard-api `SECURITY.md`](https://github.com/codepilots/wyrtloom-dashboard-api/blob/main/SECURITY.md)).

1. **Client-application signature** (every route except `POST /api/enroll`) — a
   trust-on-first-use asymmetric signature over **server-rebuilt** canonical
   request bytes, carried in the `x-wyrtloom-client / -timestamp / -nonce /
   -signature` headers. The server never trusts client-supplied canonical bytes;
   it reconstructs them from the real method, full `path_and_query`, and
   `SHA-256(body)`.
2. **User session bearer** (every `Role(...)` route) — a `SecurityModule`-stamped
   token verified in a load-bearing order: **`exp` → MAC → revocation → role
   re-fetch**, then RBAC. Token roles are advisory; the directory's current roles
   and `active` flag are authoritative on every request. Roles are
   **non-hierarchical**.

Routing is **default-deny and typed**: every route declares one `RequiredAuth`,
and a startup assertion + test panic the server if any non-bootstrap route is
left ungated.

---

## SecurityModule — the root of trust

The core `SecurityModule` (`crates/core/src/security.rs`) is the cryptographic
root of trust for both session signing and audit integrity:

- **HMAC-SHA256 stamps** over message content; a `Stamp` stores the 32-byte MAC
  directly so validity needs no lookup table.
- **HKDF-style domain-separated sub-keys.** The root key is never used directly;
  one HMAC-extract per label derives `k_session` (session/stamp MACs) and
  `k_audit` (audit chain), so the two domains never share key material.
- **Constant-time stamp comparison** (`constant_time_eq`) — MAC verification is an
  attacker-observable oracle, so a short-circuiting `==` would leak prefix
  correctness. The dashboard API never byte-compares MACs itself; it always calls
  the core `is_valid`.
- **Tamper-evident keyed audit chain.** Each entry's `prev_hash` is an HMAC under
  `k_audit` (with a domain tag) of the previous entry's serialization; `audit()`
  holds the chain-head lock across read-compute-write so concurrent appends cannot
  fork the chain. `verify_chain` walks the chain and reports the first broken link.
  The **chain is verified at startup** (and again defensively after load), and the
  server refuses to serve if verification fails.
- **0600 files.** The audit file is created `mode(0o600)` with permissions
  defensively re-applied; the session/audit key file is created with `O_EXCL` +
  `mode(0o600)` and re-`set_permissions(0o600)` against a permissive umask. An
  all-zero or wrong-length key file is rejected.
- **`sanitize_detail`** caps audit detail at 512 chars and strips control chars
  **and** Unicode bidi/format codepoints (e.g. U+202E) to block log injection and
  Trojan-Source spoofing. Audit detail must never carry secrets — it de-fangs but
  does not redact.

A single `--session-key-file` keys both `k_session` and `k_audit`. It is generated
0600 if missing and reused thereafter so sessions and the audit chain survive a
restart.

---

## TOFU client authentication

[`wyrtloom-clientauth-tofu`](https://github.com/codepilots/wyrtloom-clientauth-tofu/blob/main/SECURITY.md)
authenticates the **client application** (distinct from the human user) with
asymmetric keys:

- **Asymmetric trust-on-first-use pinning.** A client enrolls with a bootstrap key
  + its public key; the server pins the public key, keyed by
  `client_id == SHA-256(public_key)` — a self-certifying id whose forgery for a
  different key requires breaking SHA-256 second-preimage resistance. Re-enrolling
  the same key/id is idempotent; a different key under the same id is `PinMismatch`.
- **Algorithms by key length** (no on-the-wire algorithm field): ed25519 (32-byte
  key, 64-byte sig) or ECDSA **P-256** (65-byte SEC1-uncompressed key, raw `r ‖ s`
  sig). **P-256 enforces canonical low-s** — high-s signatures are rejected to
  remove ECDSA malleability (WebCrypto emits high-s ~50% of the time, so web
  clients must normalize).
- **Hashed, single-use bootstrap keys.** `issue_bootstrap_key` draws 256 bits from
  the OS CSPRNG, returns the plaintext **once**, and stores only its **SHA-256
  hash** (compared constant-time via `ct_eq`). Single-use is now **cross-process
  atomic**: consumption is a compare-and-set via the persistence layer's
  `put_if_absent` (`INSERT … ON CONFLICT DO NOTHING` under WAL), so it no longer
  depends on the in-process enroll lock.
- **Replay / freshness.** A bounded ±skew window (default ±300 s) plus an O(1)
  replay cache `(client_id, nonce)` with a fail-closed cap. Stored records hold
  **only public material** (public key, fingerprint, name, enrollment time) — no
  recoverable secret at rest. The shared canonical encoder
  (`wyrtloom-client-auth-v1`, length-prefixed, domain-tagged) is the same one the
  API verifier and the web client use, so signed bytes are byte-identical.

---

## Passwords

[`wyrtloom-users`](https://github.com/codepilots/wyrtloom-users/blob/main/SECURITY.md)
stores credentials with **argon2id**:

- Per-hash CSPRNG salt (`OsRng` via `SaltString::generate`), stored only as the PHC
  string — plaintext is never written. Verification is constant-time (argon2's own
  `verify_password`); a malformed stored hash returns `false`, never an error.
- **Timing-uniform rejection.** A per-instance dummy hash (minted from the same
  `Argon2` instance, so its cost params always match real hashes) is verified on
  every rejection path — unknown user, disabled, and locked accounts all spend an
  argon2 verify before returning, closing the user-enumeration timing oracle.
- **Per-account lockout** — 5 failed attempts arm a 300 s lockout (resetting the
  counter to 0 so the policy stays 5-strike). A correct password is rejected while
  locked. No default credential exists; `ensure_admin` is idempotent and never
  resets an existing password.

(The dashboard API folds `Disabled` into a generic credential failure, rate-limits
`/login`, and caps argon2 concurrency — the per-IP and concurrency controls that
`wyrtloom-users` explicitly delegates to the caller.)

---

## Persistence

[`wyrtloom-store-sqlite`](https://github.com/codepilots/wyrtloom-store-sqlite/blob/main/SECURITY.md)
is a document/collection store whose central threat is **SQL injection via
identifier interpolation** (table/index/field names cannot be parameterized):

- **SQL-identifier validation on every code path** via
  `persistence::is_valid_identifier` — `[a-z][a-z0-9_]*`, length 1–64, excluding
  quotes, semicolons, dots, whitespace. Re-validated on reopen from the catalog
  (catalog rows are not trusted because they were once written), and `ByField`
  queries are additionally allow-listed against declared indexed fields (a second
  gate that also prevents full-table-scan DoS).
- **All values bound, never interpolated** (positional `?n` params); malformed
  rows fail loud as integrity errors rather than panicking or silently dropping;
  mutex poisoning maps to a storage error.
- **No recoverable secrets at rest** — the store keeps whatever consumers put in
  verbatim (argon2id PHC hashes from `wyrtloom-users`, public-key-only records from
  `wyrtloom-clientauth-tofu`); cryptographic protection is the consumer's job. The
  store provides the **atomic `put_if_absent`** CAS that makes bootstrap single-use
  cross-process-safe.

The config loader
([`wyrtloom-config`](https://github.com/codepilots/wyrtloom-config/blob/main/SECURITY.md))
treats TOML as potentially attacker-influenced: `#[serde(deny_unknown_fields)]`
(a typo'd flag is a hard error, not a permissive fall-through), closed enums,
strict SemVer, recursive `..`-traversal screening of every string value, and
SAFE-plugins-declare-no-capabilities — all enforced by `validate()`, which the
`PUT /api/config` endpoint runs before saving. A failed config load is
fail-safe: the API falls back to `SecurityPolicy::deny_all()`.

---

## Providers

[`wyrtloom-provider-nous`](https://github.com/codepilots/wyrtloom-provider-nous/blob/main/SECURITY.md)
(and the core provider model) defend the host against a hostile/buggy inference
endpoint and SSRF:

- **SSRF defense via real URL parsing** (`validate_base_url`) — the base URL is
  parsed with the `url` crate, not prefix-matched. It requires `http` with an
  **exact** host of `localhost`/`127.0.0.1`, or `https`, and **rejects any
  userinfo**. This defeats `http://localhost@evil.com`, `http://localhost.evil.com`,
  `http://127.0.0.1.evil/`, and IMDS `http://169.254.169.254/...`. Redirects are
  disabled (following one re-enables SSRF) and a 30 s timeout applies.
- **Response body cap** — 8 MiB, enforced **before** deserialization by streaming
  through `take(cap + 1)`, so a chunked / absent / lying Content-Length cannot
  exhaust memory.
- **Output sanitization** — model output passes through `strip_control` (shared
  core implementation), stripping ANSI CSI/OSC/DCS escape sequences and bidi/format
  codepoints (preserving `\n`/`\r`/`\t`) to block terminal-injection / Trojan-Source
  attacks. Transport and HTTP errors are mapped to opaque categories; the API key
  is sent only as a bearer header and never logged.

---

## Capability model

The core `SecurityPolicy` and plugin model are **deny-by-default** in production:

- `deny_all()` grants nothing; the capability checks match on **component
  boundaries** — a `..` anywhere is rejected, and a file prefix must match exactly
  or up to a `/` separator (so `/etc` does not grant `/etc-evil/secret`). The
  network allowlist uses dot-separator suffix matching (so `evillocalhost` does not
  match `localhost`).
- **`Safe` plugins must hold NO capabilities** — enforced in `SecurityModule::verify`
  **and** again in the bootstrap loop, and also by the config loader's `validate()`.
  Plugin names are validated `[a-z0-9_-]{1,64}` (rejecting path separators and
  escapes) before any other manifest check. Bootstrap runs the SecurityModule
  `self_check` first, before verifying any plugin.

---

## Known limitations / operational requirements

These are the sharp edges, consolidated from the per-repo `SECURITY.md` files.
Treat them as deployment requirements.

- **Single-instance / single-writer assumption.** The client-auth **nonce replay
  cache** and the in-process belt-and-braces enroll path are process-local; a nonce
  replayed against a *different* instance would not be caught. **Do not horizontally
  scale the API as-is.** (Bootstrap single-use is the exception — it is store-atomic
  via `put_if_absent` and is safe across processes.) Run a single instance only.
- **`--session-key-file` is the root of trust for BOTH session signing and audit
  anchoring.** Its compromise lets an attacker forge sessions **and** rewrite the
  audit log. Protect it (0600, restricted host, backups treated as secrets); it
  must be reused across restarts for sessions and the chain to survive.
- **`validate_db_path` is a `..` screen, NOT confinement.** It blocks `ParentDir`
  components but permits **absolute paths and symlinks** (shared by the config
  loader and the SQLite store). DB and config paths must be operator-trusted; do
  not feed it untrusted input expecting a jail.
- **Audit suffix-truncation needs external anchoring (roadmap).** The keyed chain
  detects in-place tampering, reordering, and mid-chain deletion, but an attacker
  who can rewrite the entire file from the start can produce a self-consistent
  shorter chain. Detecting truncation needs an external high-water mark (a signed
  entry-count / chain-head stored outside the log) — roadmapped, not yet
  implemented. Note also that the keyed MAC buys nothing against an in-process
  attacker (who can read `k_audit` from the same process); it matters only for a
  persisted log verified later by a separate trusted process.
- **Unbounded WASM module cache.** Compiled modules are cached by content hash with
  no eviction; a stream of *distinct* modules is a memory-growth vector. Fine for a
  fixed plugin set, risky for arbitrary tenant-supplied modules. Bounded/evicting
  cache is roadmapped.
- **`permissive()` is the v0.1 demo default.** `SecurityPolicy::default()` is
  permissive (grants `/tmp`+`.`, localhost network, git) so the demo runs out of
  the box, and the default `bootstrap.rs::run` path boots with it. **Production must
  construct the module with an explicit policy** (`deny_all()` plus specific grants)
  and a durable key. The dashboard API already falls back to `deny_all()` on a
  failed config load.
- **Remote use needs TLS.** The API binds loopback plain HTTP and refuses a
  non-loopback bind unless `--insecure-allow-remote-http` is passed. Terminate TLS
  in a reverse proxy in front and keep the bind on loopback. TOFU first-contact
  enrollment over a non-loopback path likewise needs TLS, and bootstrap keys must be
  distributed out-of-band, once.
- **Other operational requirements:** provide `--audit-file` (the server fails
  closed without it); set exact `--cors-origin` values for any cross-origin SPA
  (omit to deny cross-origin); provision out-of-band while the server is stopped
  (single-writer); keep the host clock sane (freshness gates fail closed on a
  rolled-back clock); default session TTL is 30 minutes. The serving layer must
  also send the CSP / `nosniff` security response headers (the SPA's `<meta>` CSP is
  a fallback, and `frame-ancestors` is only honored as an HTTP response header).

---

## Audit history

The ecosystem has passed **two adversarial audit rounds** — an internal audit
(22 findings) and a round-2 core security hardening pass (10 review findings) —
whose finding numbers are cited inline in each per-repo `SECURITY.md`. This
overview is a map; consult the linked per-repo documents for the load-bearing
detail and code citations behind every control above.
