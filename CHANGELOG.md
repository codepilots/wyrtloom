# Wyrtloom Changelog

---

## Second code-review fixes (2026-06-07)

A follow-up review surfaced findings that survived the earlier hardening passes;
all are now addressed. Test count grew from 103 to 120; all pass, clippy clean.

### Security

- **S1 — SSRF in the Ollama provider base-URL check.**
  `crates/plugin-provider-ollama/src/lib.rs`. The old
  `url.starts_with("http://localhost")` test was bypassable
  (`http://localhost.attacker.com`, `http://127.0.0.1.attacker.com`,
  `http://localhost@attacker.com`), and the `https://` arm allowed *any* host
  including cloud metadata (`https://169.254.169.254`). `validate_base_url` now
  parses with the `url` crate and matches the host exactly: `http` only to
  loopback (`localhost`/`127.0.0.1`/`::1`), `https` to DNS hosts but not to
  private/loopback/link-local IP literals.
- **S2 — File-capability prefix boundary bug.** `crates/core/src/security.rs`.
  `path.starts_with("/tmp")` matched `/tmpevil`. `check_file_path` now rejects
  `..` via path-component parsing and uses a separator-boundary prefix match
  (`path_has_prefix`), the same fix class as CR-01 for hostnames.
- **S3 — Non-constant-time MAC comparison.** `crates/core/src/security.rs`.
  `is_valid` compared the HMAC with `==`; it now uses `Mac::verify_slice` for a
  constant-time check.
- **S4 — Audit hash-chain broke on restart; write errors were swallowed.**
  `with_audit_file` now resumes the chain by seeding `last_hash` from the last
  persisted line, and audit-file write failures are surfaced on stderr.

### Correctness

- **C1 — Sandbox timeout interfered across concurrent executions.**
  `crates/plugin-sandbox-wasmtime/src/lib.rs`. The wall-clock timeout increments
  the engine-global epoch; executions are now serialised with an `exec_lock` so
  one call's timeout cannot prematurely trap another.
- **C2 — `parse_llm_output` rejected valid JSON with trailing text.**
  `src/pipeline.rs` now uses a streaming deserialiser that stops at the end of
  the first object, so `{"status":"done",…} thanks!` parses.
- **C3 — "Retry"/free-text escalation responses were no-ops.** `src/pipeline.rs`
  now runs a bounded retry loop (`MAX_ATTEMPTS`): Retry re-runs the task, and
  free-text guidance is appended to the prompt before retrying.
- **C4 — `claim()`'s owner was wiped by the next transition.**
  `crates/plugin-kanban-sqlite/src/lib.rs`. `transition` only clears the actor
  when returning a task to an unclaimed pool state (Backlog/Todo/Ready); the
  owner now survives Ready→Running.
- **C5 — Success path ignored a failed `Done` transition.** `src/pipeline.rs`
  now returns Blocked (and records it) instead of reporting Done when the board
  write fails.

### Maintainability

- **M1 — WASM memory limit was never enforced.** `max_memory_bytes` is now
  applied via a per-store `StoreLimits` ResourceLimiter.
- **M2** — documented that the plugin factory seam is unused in v0.1.
- **M3** — removed the duplicated safe-plugin capability check from bootstrap
  (`SecurityModule::verify` is the single source of truth).
- **M4** — cleared all clippy warnings (useless `format!`, identical if-blocks,
  redundant closure, and pre-existing test-only lints).
- **M5** — renamed the misleading `dotdot_as_filename_component_is_rejected`
  storage test to `dotdot_within_filename_is_allowed`.
- **M6** — documented the deliberately-coarse fuel/wall-clock relationship.

---

## Code-review fixes (2026-06-07)

Ten findings from an internal code review addressed.
Test count grew from 100 to 103; all pass.

---

### Security fixes

#### CR-01 — Network allowlist suffix matching now requires a dot separator
**File:** `crates/core/src/security.rs`
**Was:** `host.ends_with(allowed)` — a hostname like `"evillocalhost"` matched the
allowlist entry `"localhost"` because the suffix check had no separator guard.
The default permissive policy's `["localhost", "127.0.0.1"]` entries were both
bypassable this way.
**Fix:** Changed to `host.ends_with(&format!(".{}", allowed))` (subdomain match)
combined with the existing exact-match check (`host == allowed`).
Only `"localhost"` itself or `"sub.localhost"` now match `"localhost"`.

#### CR-04 — `audit()` hash chain is now race-free under concurrent callers
**File:** `crates/core/src/security.rs`
**Was:** `last_hash` was acquired once to read `prev_hash`, released, and acquired
again to write `new_hash` — a window in which a second thread could read the
same `prev_hash`, silently forking the chain.
**Fix:** Both the read of `prev_hash` and the write of `new_hash` now happen
inside a single lock scope.  The file write and log push happen after the lock
is released to avoid blocking other auditors during I/O.

---

### Correctness fixes

#### CR-02 — Epoch timer spawned only after all fallible setup completes
**File:** `crates/plugin-sandbox-wasmtime/src/lib.rs`
**Was:** The background epoch-timer thread was spawned before any of the fallible
setup steps (fuel config, linker instantiation, memory export check, etc.).
On any early-return error the thread ran to completion and called
`engine.increment_epoch()`, which corrupted the *next* call's relative epoch
deadline, potentially causing it to trap immediately.
**Fix:** The `std::thread::spawn` is now placed immediately before `run.call()`,
after all fallible operations have succeeded.  The `cancel` flag is still set
to `true` after the call returns so the timer is suppressed on completion.

#### CR-03 — `parse_llm_output` scans all `{` positions, not just the first
**File:** `src/pipeline.rs`
**Was:** `text.find('{')` located the first `{` in the response.  If the model
included prose with braces before the JSON object (e.g. `"involves {retry}. {…}"`)
`serde_json::from_str` would fail on the prose brace and the task was
incorrectly marked as blocked.
**Fix:** The parser now iterates forward through every `{` position, attempting
`serde_json::from_str` at each.  The first position that deserialises
successfully as a valid `LlmResponse` is used; only if none succeeds is
the response treated as unparseable.

---

### Efficiency fixes

#### CR-05 — `SafeModule` carries a precomputed SHA-256; sandbox no longer re-hashes on cache hits
**Files:** `crates/core/src/sandbox.rs`, `crates/plugin-sandbox-wasmtime/src/lib.rs`
**Was:** `execute()` recomputed SHA-256 of the WASM bytes on every call to key
the module cache, including all cache-hit calls.
**Fix:** `SafeModule::new(wasm_bytes)` computes and stores `content_hash: [u8; 32]`
once at construction.  `execute()` uses `module.content_hash` directly for the
cache lookup.

#### CR-06 — Epoch timer spawned after setup (also eliminates spurious early threads)
*(Covered by CR-02 above.)*

#### CR-07 — `is_valid()` checks the revocation set before computing HMAC
**File:** `crates/core/src/security.rs`
**Was:** `compute_mac(content)` (expensive HMAC-SHA256) ran before the O(1)
`HashSet::contains` check.  Replayed invalidated stamps consumed full MAC work.
**Fix:** The revocation-set check now runs first; HMAC is only computed for
stamps not already revoked.

---

### Maintenance / simplification fixes

#### CR-08 — `validate_db_path` moved to `wyrtloom-core::storage`
**Files:** `crates/core/src/storage.rs` (new),
           `crates/plugin-kanban-sqlite/src/lib.rs`,
           `crates/plugin-logger-sqlite/src/lib.rs`
**Was:** Identical nine-line path-traversal validation functions were duplicated
in both SQLite plugins.  A future fix to this security-critical check would have
had to be applied in two places.
**Fix:** `wyrtloom_core::storage::validate_db_path` is the single implementation;
both plugins import it.

#### CR-09 — `is_allowed()` extracts a shared `check_file_path` helper
**File:** `crates/core/src/security.rs`
**Was:** The path validation block (`!path.contains("..")` + prefix check) was
copy-pasted for `FileRead` and `FileWrite` capabilities — divergence risk if
either branch was hardened independently.
**Fix:** Both match arms delegate to `check_file_path(path, prefixes)`.

#### CR-10 — `Pipeline::make_call_log` eliminates duplicate `CallLog` construction
**Files:** `src/pipeline.rs`, `crates/core/src/profile.rs`
**Was:** `CallLog` was constructed with duplicated field-by-field code in both
the `Ok` and `Err` branches of the LLM call, with `"ollama"` hardcoded in both.
**Fix:** `Pipeline::make_call_log(task_id, usage, outcome)` is a single helper.
`TaskProfile` gains a `provider: String` field (defaults to `"ollama"` in
`default_v01()`) so the provider name is sourced from the profile rather than
hardcoded.

---

## Security hardening — post-audit fixes (2026-06-07)

All 22 findings from the internal security audit have been addressed.
The test count grew from 70 to 100; all pass.

---

### Critical fixes

#### 001 — `self_check()` now validates internal invariants
**File:** `crates/core/src/security.rs`
**Was:** `self_check()` unconditionally returned `Ok(())` — a complete no-op.
**Fix:** Now verifies that (a) the HMAC key is not all-zero (detects RNG failure
at init), and (b) both internal mutexes are accessible. A poisoned or zeroed
state returns `SecurityError::IntegrityFailure` and halts bootstrap.
Binary-level attestation (code signing, TPM PCR sealing) is reserved for Phase 3;
the seam is present and the method is no longer silent.

#### 002 — `is_allowed()` enforces a real capability policy
**File:** `crates/core/src/security.rs`
**Was:** `is_allowed()` returned `true` for every possible capability.
**Fix:** Added `SecurityPolicy` struct with explicit allow-lists:
- `file_read_prefixes` / `file_write_prefixes`: path-prefix allowlists;
  paths containing `..` are unconditionally denied regardless of prefix.
- `network_allowlist`: exact or suffix hostname matching.
- `allow_shell: bool` — `false` by default; opt-in per installation.
- `allow_git: bool` — `true` in the default permissive policy.

`SecurityModule::with_policy(SecurityPolicy::deny_all())` locks down
everything; `SecurityPolicy::permissive()` (the default) allows localhost
network and local filesystem paths only.

---

### High fixes

#### 003 — Plugin manifest signing gap documented
**File:** `crates/core/src/plugin.rs`
**Was:** No note on the gap between manifest declarations and the factory
closure's actual behaviour.
**Fix:** Inline documentation added explaining that v0.1 relies on the
manifest being self-reported; cryptographic code signing (binding the
manifest to the compiled binary via HMAC/public-key signature) is a
Phase 3 requirement. The manifest validation surface has been hardened
via finding 020 (name restrictions) as a partial mitigation.

#### 004 — Stamps are now HMAC-SHA256 and are enforced
**File:** `crates/core/src/security.rs`
**Was:** `Stamp(u64)` — a monotonic counter. Trivially forgeable.
`is_valid()` was defined but never called.
**Fix:**
- `Stamp` is now `Stamp([u8; 32])` — a 32-byte HMAC-SHA256 output.
- `stamp(content: &[u8]) -> Stamp` computes `HMAC-SHA256(key, content)` where
  `key` is a 32-byte random secret generated at `SecurityModule::new()`.
- `is_valid(&self, stamp: &Stamp, content: &[u8]) -> bool` re-derives the
  expected MAC and verifies equality, then checks the revocation set.
- A forged stamp (any `Stamp([1,0,...])` etc.) fails `is_valid()` because it
  does not match the HMAC for any content the attacker can supply.
- An invalidated stamp also fails even if the MAC is correct, covering the
  "transform and replay" attack.

#### 005 — TOCTOU race in `transition()` and `block()` fixed
**File:** `crates/plugin-kanban-sqlite/src/lib.rs`
**Was:** `get()` (read) and `UPDATE` (write) were two separate lock acquisitions
separated by a race window.
**Fix:** Both `transition()` and `block()` now wrap read-validate-write in a
`BEGIN IMMEDIATE` transaction. If the transition fails validation, the
transaction is rolled back. The `claim()` method already used the correct
atomic `UPDATE … WHERE actor IS NULL` pattern and was not changed.

#### 006 — HTTP client hardened against SSRF and hangs
**File:** `crates/plugin-provider-ollama/src/lib.rs`
**Was:** `reqwest::blocking::Client::new()` with all defaults — no timeout,
follow-redirects enabled, no URL validation.
**Fix:**
- `validate_base_url()` enforces `http://localhost…`, `http://127.0.0.1…`,
  or `https://…` — everything else is rejected at construction.
  Cloud IMDS (`169.254.169.254`) and arbitrary internal hosts are blocked.
- `OllamaProvider::new()` now returns `Result<Self, String>`.
- `redirect::Policy::none()` — automatic redirect following disabled;
  a server cannot redirect the client to an internal host.
- `timeout(30s)` — prevents indefinite thread blocking on a slow server.

#### 007 — ANSI / control sequences stripped from LLM output
**File:** `crates/plugin-provider-ollama/src/lib.rs`
**Was:** Raw LLM output (including any server-injected escape sequences) was
returned unmodified and printed to the terminal / shown in escalation prompts.
**Fix:** `strip_control()` removes ANSI escape sequences (ESC + …letter) and
all non-printable control characters (preserving `\n`, `\r`, `\t`) from the
model's response before it is returned. This prevents terminal-injection
attacks from a compromised provider.

#### 008 — LLM output parsed as structured JSON (prompt injection hardening)
**Files:** `src/pipeline.rs`, `crates/core/src/profile.rs`
**Was:** The pipeline used `text.starts_with("BLOCKED:")` and
`text.trim_start_matches("DONE:")` as state-machine signals — trivially
manipulated by adversarial content in the user prompt.
**Fix:**
- The system prompt now instructs the model to always respond with exactly
  `{"status":"done","result":"…"}` or `{"status":"blocked","reason":"…"}`.
- `parse_llm_output()` in `pipeline.rs` extracts the first `{…}` block and
  deserialises it as `LlmResponse`. Only the `status`, `result`, and `reason`
  fields are read; everything else is ignored.
- A response that does not parse as valid JSON, or has an unrecognised
  `status` value, is treated as `blocked` — the agent escalates rather than
  silently proceeding.

#### 009 — Audit log hardened: hash chain + optional persistence
**File:** `crates/core/src/security.rs`
**Was:** `Vec<SecurityDecision>` in RAM only; wiped on any crash; no tamper detection.
**Fix:**
- Every `SecurityDecision` now carries a `prev_hash: String` field — the
  SHA-256 (hex) of the preceding entry's JSON serialisation. This forms a
  hash chain: any deletion or mutation of an earlier entry breaks the chain
  for all subsequent entries.
- `SecurityModule::with_audit_file(path)` opens a JSONL append-only file;
  every `audit()` call writes to the file *before* updating the in-memory log,
  so entries survive process crashes.
- Read access to the log via `audit_log_snapshot()` is unchanged for v0.1;
  access-controlled read (Phase 3) is noted in the code.

---

### Medium fixes

#### 010 — SQLite path traversal prevented
**Files:** `crates/plugin-kanban-sqlite/src/lib.rs`,
           `crates/plugin-logger-sqlite/src/lib.rs`
**Was:** `Connection::open(path)` accepted any string, including `../etc/`.
**Fix:** `validate_db_path()` iterates the path's components and rejects any
`ParentDir` (`..`) component, returning `rusqlite::Error::InvalidPath`.

#### 011 — Silent data substitution replaced by integrity errors
**Files:** `crates/plugin-kanban-sqlite/src/lib.rs`,
           `crates/plugin-logger-sqlite/src/lib.rs`
**Was:** Unknown state strings mapped to `Backlog`; bad timestamps mapped to
`Timestamp::now()`; unknown outcome strings mapped to `Completed`.
**Fix:** All three cases now return a typed `Storage("integrity error: …")` error
containing the offending value. Callers receive an explicit error rather than
silently wrong data that could mislead the ML tuner or conceal DB tampering.

#### 012 — WASM input size bounds-checked before i32 cast
**File:** `crates/plugin-sandbox-wasmtime/src/lib.rs`
**Was:** `input.len() as i32` silently wrapped on inputs > 2 GiB.
**Fix:** An explicit `if input.len() > i32::MAX as usize` check returns
`SandboxError::Trap` before the cast. An additional memory-bounds check before
the `memory.write()` call rejects inputs larger than the module's linear memory.

#### 013 — Real wall-clock timeout via epoch interruption
**File:** `crates/plugin-sandbox-wasmtime/src/lib.rs`
**Was:** Only fuel-based limiting, which does not map linearly to wall-clock time.
**Fix:** `Config::epoch_interruption(true)` + `store.set_epoch_deadline(1)` +
`store.epoch_deadline_trap()`. A background thread sleeps for `max_wallclock_ms`
and then calls `engine.increment_epoch()`, triggering a `SandboxError::Timeout`.
The thread is cancelled via an `AtomicBool` if the call completes first.
Fuel limiting is retained as a secondary compute-instruction budget.

#### 014 — WASM module compilation cache added
**File:** `crates/plugin-sandbox-wasmtime/src/lib.rs`
**Was:** `Module::new()` (full Cranelift compilation) called on every `execute()`.
**Fix:** `module_cache: Mutex<HashMap<[u8; 32], Module>>` keyed by SHA-256 of the
WASM bytes. Identical modules are compiled once; subsequent calls clone the
cached `Module`. A maximum WASM binary size check (via memory bounds) limits
single-compilation cost.

#### 015 — Message bus uses per-topic channels
**File:** `crates/plugin-bus-tokio/src/lib.rs`
**Was:** All events flowed through a single broadcast channel; `subscribe(topic)`
ignored the topic parameter — any subscriber received all events.
**Fix:** `TokioMessageBus` now holds a `Mutex<HashMap<Topic, broadcast::Sender>>`.
A new channel is created lazily per topic on first publish or subscribe.
A subscriber to `"metrics"` cannot receive events published to `"security"`.

#### 016 — Hop counter now enforced at `validate()` time
**File:** `crates/core/src/agent.rs`
**Was:** `hops: u8` was present and serialised but `validate()` never checked it.
**Fix:** `validate()` returns `MessageError::Malformed` when `hops >= MAX_HOPS`
(16). A body size limit (`MAX_BODY_BYTES = 1 MiB`) is also checked for all
message variants carrying a body. Both constants are pub for operator visibility.

#### 017 — `Money::usd()` uses rounding, not truncation
**File:** `crates/core/src/types.rs`
**Was:** `(dollars * 1_000_000.0) as i64` — float truncation caused systematic
under-reporting (e.g. `0.001 * 1_000_000.0 → 999.999… → 999`).
**Fix:** `.round() as i64` rounds to the nearest microdollar before casting.

#### 018 — `.expect()` panics replaced in pipeline
**File:** `src/pipeline.rs`
**Was:** Six `.expect()` calls in `Pipeline::run()` would panic on any Kanban
error, crashing the process and wiping the in-memory audit log.
**Fix:** All Kanban operations return `Result` and are handled with `match`/`if let`.
Failures return `PipelineOutcome::Blocked` with a descriptive reason and call
`record_blocked()` to persist the blocked state on the board.

---

### Low fixes

#### 019 — `WasmtimeSandbox::default()` panicking impl removed
**File:** `crates/plugin-sandbox-wasmtime/src/lib.rs`
**Was:** `impl Default` called `.expect("failed to create wasmtime engine")`.
**Fix:** `Default` implementation removed. All call sites use
`WasmtimeSandbox::new()?` which propagates the error cleanly.

#### 020 — Plugin names validated against `[a-z0-9_-]{1,64}`
**File:** `crates/core/src/plugin.rs`
**Was:** Only checked `name.is_empty()`.
**Fix:** `PluginManifest::validate_name()` enforces lowercase alphanumerics,
hyphens, and underscores only, maximum 64 characters. Called from
`Bootstrapper::run()` before security verification. Path separators,
uppercase letters, and control/escape characters are all rejected.

#### 021 — Raw transport error strings no longer leak internal detail
**File:** `crates/plugin-provider-ollama/src/lib.rs`
**Was:** `ProviderError::Transport(e.to_string())` passed raw reqwest error
strings (socket addresses, TLS codes) into escalation prompts and logs.
**Fix:** `reqwest::Error` is categorised by kind: `is_timeout()` →
`"connection timed out"`, `is_connect()` → `"connection refused"`, else
`"network error"`. HTTP status errors report only the numeric code. Raw
internal strings are never propagated to user-facing surfaces.

#### 022 — Raw `rusqlite::Error` strings replaced with opaque categories
**Files:** `crates/plugin-kanban-sqlite/src/lib.rs`,
           `crates/plugin-logger-sqlite/src/lib.rs`
**Was:** `.map_err(|e| KanbanError::Storage(e.to_string()))` forwarded raw
SQLite error messages (schema names, SQL text, file paths) to callers.
**Fix:** `sqlite_code(&e)` extracts only the numeric extended error code;
all `KanbanError::Storage` strings now read `"operation failed (code N)"`.
`LogError::Storage` strings use `"operation failed"` with no internal detail.
Full SQLite errors are not logged in v0.1 (structured logging arrives in Phase 2).

---

## v0.1.0 — Initial implementation (2026-06-07)

Full implementation of the Wyrtloom v0.1 specification:

- Core kernel: SecurityModule, PluginLoader, KanbanStateMachine,
  LlmProvider, CallLogger, HumanEscalation, SandboxRuntime,
  MessageBus, AgentMessage contracts, TaskProfile, Bootstrap sequence.
- Plugins: kanban-sqlite, provider-ollama, sandbox-wasmtime,
  logger-sqlite, escalation-cli, bus-tokio.
- 70 contract tests, all green.
- Apache 2.0 licence.
