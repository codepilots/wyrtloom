# Security Model

This document describes the security model of the Wyrtloom core monorepo and its
first-party plugins. It is written to be honest about what the current code does
and does *not* protect against — several items below came directly from an
adversarial internal audit (see `CHANGELOG.md` finding numbers, referenced
throughout). Every claim cites the code that implements it. Where a control has a
sharp edge, it is called out under **Gotchas / watch-outs** rather than buried.

Status: **v0.1**. Some controls are deliberately staged for later phases; these
are listed under **Known limitations (roadmap)**.

---

## Threat model & scope

Wyrtloom is a plugin host. The core loads plugins (some `Safe`, some `Unsafe`),
runs untrusted compute in a WASM sandbox, talks to an external LLM provider, and
persists state through storage plugins. The security boundaries we defend:

1. **Untrusted WASM compute** (`Safe` plugins, hunt harnesses) must not reach
   host resources (files, network, shell) — *lethal-trifecta containment*. It
   also must not be able to exhaust host memory or CPU.
2. **Untrusted external input** — LLM responses, usernames, paths, request
   bodies — must not be able to inject terminal escape sequences, spoof audit
   logs (Trojan-Source), or drive an SSRF/memory-exhaustion via the provider.
3. **Plugin capabilities** — a plugin must not be able to obtain a capability it
   was not granted, and a `Safe` plugin must hold *no* capabilities at all.
4. **Audit integrity** — security decisions must be tamper-evident when a
   persisted log is later checked by a trusted process holding the durable key.
5. **Client/request authentication** — request signatures must bind
   unambiguously to method/path/body/client/time/nonce, with no field-boundary
   confusion, identically across every signer and verifier.
6. **SQL surface** — storage plugins must not be injectable.

**Explicitly out of scope / trusted in v0.1:**

- The operator and the host OS are trusted. An in-process attacker who can mutate
  core memory already holds the keys (see the audit-chain note below).
- DB file paths are operator-supplied and trusted (see `validate_db_path`).
- Binary-level attestation / measured boot is **not** implemented (Phase 3 —
  `security.rs` line 5, 234-235).
- The default `SecurityPolicy` is **permissive** for the v0.1 demo; production
  deployments must pass an explicit policy (see Gotchas).

---

## Security mechanisms

### 1. SecurityModule — root of trust (`crates/core/src/security.rs`)

- **Stamps are HMAC-SHA256** over message content (`stamp`, `compute_mac`,
  lines 284-288, 368-370). A `Stamp` stores the 32-byte MAC directly so
  validity is checked without a lookup table.
- **Constant-time stamp comparison** (`constant_time_eq`, lines 468-474; used in
  `is_valid`, line 301). A short-circuiting `==` would leak, via timing, how many
  leading bytes of a forged stamp are correct. The revocation set is checked
  first (line 295) only to short-circuit *already-invalidated* stamps.
- **Operator-supplied persisted key** via `with_key` (lines 159-175). The
  random key from `new`/`with_policy` is ephemeral and cannot re-verify stamps or
  the audit anchor across a restart; a durable key keeps them valid. `self_check`
  **rejects an all-zero key** (lines 236-242) as an RNG-failure indicator.
- **HKDF-style domain-separated sub-keys** (finding 027). The root key is never
  used directly for crypto; `derive_subkey` (lines 451-453) does an HMAC-extract
  per label to produce `k_session` (stamp/session MACs) and `k_audit` (audit
  chain), so the two domains never share a key (lines 162-164).
- **Keyed-MAC audit chain + `verify_chain`** (lines 341-365). Each entry's
  `prev_hash` is the HMAC (under `k_audit`, with a domain tag
  `wyrtloom-audit-chain-v1\0`) of the previous entry's serialization.
  `verify_chain` (lines 341-354) walks the chain and reports the first broken
  link; `audit()` holds the `last_hash` lock across read-compute-write so
  concurrent appends cannot fork the chain (lines 402-414).
- **Persistent audit file opened 0600 with restart re-anchoring**
  (`with_audit_file`, lines 186-227, finding 028). The file is created
  `mode(0o600)` and permissions are *defensively re-applied* to a pre-existing
  file (lines 189-200). On reopen, existing entries are loaded and the chain head
  is re-anchored from the **last** line so new entries link onto old ones across
  the restart (lines 205-223; verified by `audit_file_chains_across_restart`).
- **`record_decision`** (lines 314-317) lets consumers (e.g. an API server) write
  grant/deny decisions into the same tamper-evident chain.
- **`sanitize_detail`** (lines 459-465) caps detail at 512 chars and strips both
  control characters **and** Unicode bidi/format codepoints (via
  `crate::util::is_bidi_or_format`) to block log injection and Trojan-Source
  visual spoofing (e.g. U+202E).

### 2. SecurityPolicy & capability model (`security.rs`, `plugin.rs`)

- **Deny-by-default vs permissive**: `deny_all()` (lines 70-78) grants nothing;
  `permissive()` (lines 59-67) allows `/tmp`+`.`, localhost network, and git —
  for trusted local dev only.
- **`check_file_path` matches on component boundaries** (lines 388-400, finding
  026): a `..` anywhere is rejected, and a prefix must match exactly or up to a
  `/` separator, so `/etc` does **not** grant `/etc-evil/secret`
  (test `file_prefix_does_not_grant_sibling_directory`).
- **Network allowlist uses dot-separator suffix match** (lines 377-381): `host ==
  allowed` or `host.ends_with(".{allowed}")`, so `evillocalhost` does not match
  `localhost`.
- **`Safe` plugin must declare no capabilities** — enforced in
  `SecurityModule::verify` (lines 257-263, `SafePluginViolation`) *and* again in
  the bootstrap loop (`bootstrap.rs` lines 72-76).
- **Plugin name validation** (`PluginManifest::validate_name`, `plugin.rs` lines
  39-53, finding 020): `[a-z0-9_-]{1,64}`, rejecting path separators, escapes,
  and uppercase. Bootstrap runs this before any other manifest check
  (`bootstrap.rs` lines 52-54).
- **Bootstrap runs security `self_check` first** (`bootstrap.rs` lines 39-40):
  Stage 1 is the SecurityModule, and its self-check must pass before any plugin
  manifest is verified.

### 3. WASM sandbox (`crates/plugin-sandbox-wasmtime`, `core/src/sandbox.rs`)

- **No host imports linked** (lethal-trifecta containment): the `Linker` is
  created empty (`lib.rs` line 157) and never populated, so a `Safe` module that
  imports e.g. `env.read_file` fails at instantiation
  (test `module_with_host_import_fails_at_instantiation`).
- **Memory limiter** enforcing `max_memory_bytes` via a wasmtime
  `ResourceLimiter` (`StoreLimits::memory_growing`, lines 33-44, finding 023):
  growth past the cap is rejected, and the subsequent out-of-bounds store traps
  (test `memory_growth_past_limit_traps`).
- **Shared epoch-ticker wall-clock timeout** (finding 024): a single background
  thread increments the engine epoch every `TICK_MS=1` (lines 79-89); each call
  sets a relative `deadline_ticks` (lines 152-153). This is concurrency-safe —
  the previous per-call thread both raced and was itself a thread-spawn DoS
  vector. **Fuel** is kept as a secondary compute backstop (lines 144-147), and
  both `Trap::Interrupt` and `Trap::OutOfFuel` are mapped to `Timeout`
  (lines 196-202).
- **Input/output bounds checks**: input length is checked against `i32::MAX`
  before the cast (lines 116-121, finding 012) and against the WASM memory size
  before write (lines 170-176); the returned output pointer/length is range-checked
  against memory size (lines 213-216).
- **SHA-256-keyed module cache** (lines 124-135, finding 014): compiled modules
  are cached by the `content_hash` precomputed in `SafeModule::new`
  (`sandbox.rs` lines 25-32), avoiding repeated Cranelift compilation (a CPU-DoS
  vector).

### 4. Storage plugins (`plugin-kanban-sqlite`, `plugin-logger-sqlite`)

- **Fully parameterized SQL**: all values are bound via `params!` / positional
  `?n` placeholders, never string-interpolated
  (e.g. kanban `lib.rs` lines 104-115, 251-269; logger `lib.rs` lines 156-177).
- **Malformed rows → integrity errors, not panics**: unknown state/outcome, bad
  timestamps, or unparseable JSON map to `Storage("integrity error: …")`
  (kanban lines 323-334; logger lines 109-128, finding 011).
- **Mutex-poison mapped to a Storage error** (finding 030): the `lock()` helper
  maps a poisoned mutex to `Storage("lock poisoned")` so one panicking thread
  cannot DoS the whole store (kanban lines 74-80; logger lines 36-41). During
  construction only, the guard is recovered with `into_inner()`.
- **`storage::validate_db_path`** (`core/src/storage.rs` lines 7-16) rejects any
  path containing a `..` (`ParentDir`) component; both SQLite plugins import it
  (kanban line 18, logger line 10).

### 5. LLM provider (`crates/plugin-provider-ollama`)

- **SSRF defense via real URL parsing** (`validate_base_url`, lines 58-82,
  finding 006/025): the base URL is parsed with the `url` crate; it requires
  scheme `http` with an **exact** host of `localhost`/`127.0.0.1`, or scheme
  `https`, and **rejects any userinfo** (`user:pass@`). This defeats the
  `starts_with` bypasses `http://localhost@evil.com`, `http://localhost.evil.com`,
  `http://127.0.0.1.evil/`, and IMDS `http://169.254.169.254/...`
  (tests `ssrf_bypass_strings_are_rejected`, `non_localhost_http_url_is_rejected`).
- **Response body size cap** of 8 MiB (`read_capped_body`, lines 84-110, finding
  025): streams through `take(cap + 1)` so a chunked / absent / lying
  Content-Length cannot exhaust memory; applied to both `/api/chat` and
  `/api/tags` (lines 203, 224).
- **`strip_control` on all external strings** (re-exported from
  `wyrtloom_core::util`, line 115; applied at line 212): the canonical
  terminal-injection stripper handles ANSI **CSI/OSC/DCS** state machines plus
  C0/C1 control chars and bidi/format codepoints (`core/src/util.rs` lines
  33-107), including the unterminated-OSC-then-CSI leak regression.
- **Opaque error mapping** (finding 021): transport errors collapse to generic
  categories (`connection timed out`/`connection refused`/`network error`,
  lines 179-187) and HTTP ≥400 bodies are *not* echoed (lines 189-197), so socket
  addresses and server internals do not leak (test `transport_error_is_generic`).
- **30s timeout, redirects disabled** (lines 33-39): redirect following is set to
  `Policy::none()` precisely because automatic following would re-enable SSRF.

### 6. Contracts imposing security invariants

- **`persistence::is_valid_identifier`** (`core/src/persistence.rs` lines 85-96):
  an SQL-identifier whitelist — leading ASCII letter, then `[a-z0-9_]`, 1..=64
  chars. SQL identifiers (collection/field names) cannot be bound as parameters,
  so implementations must whitelist them; this is deliberately *stricter* than
  the plugin-name rule (no leading digit, no `-`).
- **`client_auth::canonical_request`** (`core/src/client_auth.rs` lines 28-44):
  builds the bytes a client signs and the server verifies via the
  length-prefixed, domain-tagged `CanonicalEncoder` (`core/src/canon.rs`). Living
  in the contract (not a scheme plugin) guarantees the signer, the scheme
  implementation, and the API server produce byte-identical input, so a signature
  binds unambiguously to method/path/body-hash/client/time/nonce with no
  field-boundary ambiguity (`CanonicalEncoder` length-prefixes every field under
  a domain tag, `canon.rs` lines 24-57).

---

## Key decisions & rationale

- **Keyed MAC for the audit chain, not a plain hash.** A keyed link is meaningful
  *across the trust boundary*: a persisted log checked later by a separate process
  holding the durable key cannot be silently rewritten by an attacker who lacks
  the key. (In-process this buys nothing — see Gotchas.)
- **Domain-separated sub-keys (HKDF-style).** Reusing one secret for two purposes
  is a footgun; one HMAC-extract per label from a uniformly-random 32-byte root is
  a sound KDF here and keeps session signing and audit chaining cryptographically
  independent (finding 027).
- **Constant-time stamp compare.** MAC verification is an attacker-observable
  oracle; non-constant-time comparison leaks prefix correctness.
- **Empty WASM linker over a filtered one.** The simplest containment for the
  lethal trifecta is to link *nothing*: a `Safe` module physically cannot name a
  host function.
- **Shared epoch ticker over per-call threads.** Per-call timeout threads raced
  under concurrency and were themselves a DoS amplifier; one global ticker with
  relative deadlines is both correct and cheap (finding 024).
- **Real URL parsing for SSRF, not string prefixing.** `starts_with` is
  repeatedly bypassable (userinfo, suffix hosts); parsing + exact-host +
  no-userinfo is the only robust form (finding 025).
- **Security controls promoted to core (`util`, `canon`, contracts).** Terminal
  stripping, canonical encoding, and identifier validation are written once and
  shared, so every plugin applies *identical* audited logic rather than vendoring
  divergent copies ("Ecosystem Lens").

---

## Gotchas / watch-outs

- **`SecurityPolicy::default()` is permissive, not deny-all** (`security.rs`
  lines 81-85). `SecurityModule::new()` / `with_policy(default())` therefore grant
  `/tmp`+`.` file access, localhost network, and git. This exists so the v0.1
  demo runs out of the box. **Production must construct the module with an
  explicit policy** (`with_policy(deny_all())` plus the specific grants needed,
  ideally via `with_key` for a durable key). Note `bootstrap.rs::run` currently
  calls `SecurityModule::new()` (line 39) — i.e. it boots with the permissive
  default; a hardened deployment should not rely on the default bootstrap path.
- **The in-memory audit chain's keyed MAC adds nothing against an in-process
  attacker.** Any actor that can mutate the in-memory `Vec<SecurityDecision>` can
  also read `k_audit` from the same process and recompute valid links. The keying
  only matters for a **persisted** log verified later by a separate trusted
  process (`security.rs` lines 327-338).
- **Suffix truncation of the audit chain is undetected.** Dropping the most
  recent entries leaves a still-valid shorter chain; `verify_chain` only catches
  in-place mutation, reordering, and mid-chain deletion (lines 335-338). Detecting
  truncation needs an external high-water mark (roadmap below).
- **`validate_db_path` is a `..` traversal screen, NOT a confinement boundary**
  (`storage.rs` lines 1-16). It permits **absolute paths and symlinks** — it only
  blocks `ParentDir` components. DB paths must be **operator-trusted**; do not
  feed it untrusted input expecting it to jail writes to a directory.
- **Module cache is unbounded** (`plugin-sandbox-wasmtime/lib.rs` lines 60,
  124-135). Many *distinct* WASM modules grow the cache without eviction; a stream
  of unique modules is a memory-growth vector. Fine for a fixed plugin set, risky
  for arbitrary tenant-supplied modules.
- **`record_decision` / audit detail must never carry secrets.** `sanitize_detail`
  de-fangs control/bidi characters but does not redact — never pass key/token
  material as audit detail (`security.rs` lines 311-313).
- **`https://` with any host is allowed by the provider.** SSRF protection is
  scoped to `http` (localhost only); an attacker who controls the configured
  `https` base URL is trusted. The base URL is an operator config value, not
  untrusted input.

---

## Known limitations (roadmap)

- **External high-water-mark anchoring** for the audit chain, to detect suffix
  truncation (a signed entry-count / chain-head stored outside the log)
  — `security.rs` lines 336-338.
- **Binary measurement / platform attestation** in `self_check` — reserved for
  Phase 3 (`security.rs` lines 4-5, 234-235). v0.1 validates only key entropy and
  data-structure accessibility.
- **Bounded / evicting module cache** in the sandbox to cap memory under a stream
  of distinct modules.
- **Hardened default bootstrap path**: `Bootstrapper::run` should accept an
  explicit `SecurityPolicy` (and ideally a durable key) rather than constructing
  `SecurityModule::new()` with the permissive default.

---

## Reporting a vulnerability

This is a v0.1 research codebase. Report security issues privately to the
maintainer rather than opening a public issue.
