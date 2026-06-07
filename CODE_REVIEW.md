# Wyrtloom v0.1 — Code Review

**Scope:** the v0.1 implementation on branch `claude/wyrtloom-spec-v0.1-FRQ9W`
(PR #1, "Implement Wyrtloom v0.1 — The Seed").
**Reviewed:** 33 files, ~7,555 lines — a Rust workspace (core kernel + 6 plugins
+ binary).
**Date:** 2026-06-07

## Verdict

Solid, well-structured v0.1. The architecture (deny-by-default security core,
contract traits in `core`, swappable plugins behind them, security-first
bootstrap) is clean and the test discipline is genuinely good. The codebase has
already absorbed two documented review passes (a 22-finding security audit and a
10-finding code review — see `CHANGELOG.md`), and it shows.

I verified the build from a clean checkout:

- `cargo test --workspace` → **103 passed, 0 failed** (matches the CHANGELOG claim).
- `cargo clippy --workspace` → 3 minor warnings only.

The findings below are what survived that prior hardening. The recurring theme is
**boundary-aware matching**: the earlier review fixed `ends_with`/`starts_with`
boundary bugs in one place (the network allowlist, CR-01) but the *same bug class*
still lives in two other validators.

---

## Security

### S1 — SSRF: `validate_base_url` prefix check is bypassable, and `https://` is wide open  · **High**
`crates/plugin-provider-ollama/src/lib.rs:45`

```rust
if url.starts_with("http://localhost")
    || url.starts_with("http://127.0.0.1")
    || url.starts_with("https://")
```

- `"http://localhost.attacker.com/".starts_with("http://localhost")` is **true** —
  an attacker-registered domain passes the localhost check and resolves to any IP
  they choose. Same for `http://127.0.0.1.attacker.com`.
- The `https://` arm permits **any** HTTPS host, including internal services and
  cloud metadata (`https://169.254.169.254/…`) over TLS.

This is exactly the boundary bug CR-01 fixed for the network allowlist, recurring
here. Finding 006's stated goal (block IMDS / internal hosts) is not actually met.

**Fix:** parse with a real URL parser, match `host` *exactly* against
`{"localhost","127.0.0.1","::1"}`, and for the `https` path resolve the host and
reject private/loopback/link-local ranges (or require an explicit host allowlist).

### S2 — File-capability prefix matching has the same boundary bug  · **Medium**
`crates/core/src/security.rs:272` (`check_file_path`)

```rust
!path.contains("..") && prefixes.iter().any(|p| path.starts_with(p.as_str()))
```

With prefix `/tmp`, the path `/tmpevil/secret` or `/tmp_x` is accepted — a
capability outside the intended directory is granted. Also `!path.contains("..")`
is purely textual: it doesn't canonicalize (symlink escapes survive) and it
*wrongly rejects* legitimate names like `a..b`.

**Fix:** mirror `storage::validate_db_path` — reject `Component::ParentDir`, then
do a boundary-aware ancestor check (compare canonicalized path components, or
require the prefix to end at a `/`).

### S3 — HMAC stamp comparison is not constant-time  · **Medium**
`crates/core/src/security.rs:233` — `stamp.0 == expected`

Verifying a MAC with `==` is a non-constant-time comparison in the module that is
explicitly the "root of trust." Use the `hmac` crate's `verify_slice` (or a
`subtle::ConstantTimeEq`) so the comparison can't leak timing. In-process
exploitability is low, but it's a crypto-hygiene defect where it matters most.

### S4 — Audit hash-chain does not survive a restart, and write errors are swallowed  · **Medium**
`crates/core/src/security.rs:148,153,293`

`last_hash` starts as `""` and `with_audit_file` opens append-only without reading
the tail of the existing file. After a restart the first new entry carries an
empty `prev_hash` — a deliberate-looking break/fork at exactly the restart
boundary, which weakens the tamper-evidence guarantee finding 009 set out to
provide. Separately, `let _ = writeln!(f, …)` silently drops audit persistence on
a full/again-failing disk.

**Fix:** on open, seed `last_hash` from the last JSONL line; treat audit-file
write failure as a hard error (or at minimum surface it).

---

## Correctness

### C1 — Sandbox wall-clock timeout interferes across concurrent executions  · **Medium**
`crates/plugin-sandbox-wasmtime/src/lib.rs:117-126,80`

The `Engine` is shared (`Arc<Engine>`) and the module cache is explicitly built to
serve repeated/concurrent `execute()` calls, but the timeout works by
`engine.increment_epoch()` on a **global** engine epoch while each store uses
`set_epoch_deadline(1)`. If two executions overlap, one task's timeout thread
increments the shared epoch and can prematurely trap the *other* in-flight task
(spurious `Timeout`). CR-02 fixed the early-return thread leak but not this
cross-call interference.

**Fix:** use a per-execution `Engine`, or serialize executions, or track absolute
epoch deadlines so an increment only trips the intended store.

### C2 — `parse_llm_output` rejects valid JSON that has trailing text  · **Medium**
`src/pipeline.rs:48-62`

`serde_json::from_str::<LlmResponse>(candidate)` requires the *whole* remaining
slice to be valid JSON; trailing non-whitespace is a parse error. So a perfectly
good `{"status":"done","result":"4"} thanks!` is treated as unparseable → the task
is wrongly **Blocked**. CR-03 handled *leading* prose-with-braces but trailing
prose still breaks it.

**Fix:** use a streaming parser that stops at the end of the first object:
`serde_json::Deserializer::from_str(candidate).into_iter::<LlmResponse>().next()`.

### C3 — The "Retry" escalation option is a no-op  · **Low**
`src/pipeline.rs:182-216`

`handle_blocked` offers a "Retry" button, but `Ok(HumanResponse::Chose("retry"))`
falls through to `Ok(_) => self.record_blocked(...)`. Choosing Retry just blocks;
the task is never re-run. `HumanResponse::FreeText` is likewise silently treated as
a block. Either implement retry (loop the execute stage) or stop offering an
action that does nothing.

### C4 — `claim()`'s actor assignment is wiped by the very next transition  · **Low**
`crates/plugin-kanban-sqlite/src/lib.rs:196` (`transition_inner` always sets
`actor = NULL`)

Pipeline flow is `claim` (sets `actor = worker`) → `transition(Ready→Running)`
(sets `actor = NULL`). A Running task therefore has no recorded owner. The atomic
claim still provides mutual exclusion in its narrow window, but the ownership it
establishes is discarded one statement later — surprising for any multi-worker use.

### C5 — Success path ignores a failed `Done` transition  · **Low**
`src/pipeline.rs:160-166`

If `Running→Done` fails, the code logs to stderr but still returns
`PipelineOutcome::Done`. Board state (still Running) and reported outcome (Done)
then diverge — inconsistent with the finding-018 philosophy applied everywhere
else. Return Blocked / record the failure.

---

## Maintainability & minor

- **M1 — Memory limit is never enforced.** `ResourceLimits.max_memory_bytes`
  (default 16 MiB) is plumbed through but the wasmtime sandbox sets no
  `Store::limiter`; a SAFE module can `memory.grow` unbounded. `SandboxError::
  MemoryExceeded` is consequently never produced. Wire up a `StoreLimits` limiter.
  (*Borderline Medium given it's a DoS vector.*)
- **M2 — The loader never instantiates plugins.** `PluginRegistry::take_factories`
  exists but `Bootstrapper::run` only validates manifests; `main.rs` builds the
  concrete plugins directly. The factory / `Arc<dyn Any>` machinery is dead in
  v0.1 — fine as a seam, but worth a doc note or removal.
- **M3 — Duplicated verification.** `bootstrap.rs:72` re-checks "safe plugin with
  capabilities," which `SecurityModule::verify` (`security.rs:191`) already
  enforces. Single source of truth would be cleaner.
- **M4 — Clippy (3 warnings):** useless `format!` (`plugin-logger-sqlite/src/lib.rs:114`),
  identical `if`/`else` blocks (`plugin-sandbox-wasmtime/src/lib.rs:132-137` — both
  the epoch and fuel arms return `Timeout`; collapse them), and a redundant closure
  in the kanban plugin. `cargo clippy --fix` handles two automatically.
- **M5 — Misleading test name.** `crates/core/src/storage.rs:35`
  `dotdot_as_filename_component_is_rejected` actually asserts `/tmp/..hidden` is
  *accepted* (`is_ok()`), which is correct behavior (`..hidden` is a normal
  filename) but the opposite of what the name says. Rename.
- **M6 — Arbitrary fuel/wall-clock coupling.** `fuel = max_wallclock_ms * 10_000`
  (`plugin-sandbox-wasmtime/src/lib.rs:73`) ties two unrelated budgets together;
  document the rationale or expose them separately.

---

## What's done well

- Deny-by-default `SecurityPolicy` with explicit opt-in for Shell/Git.
- HMAC-bound, revocable stamps replacing the original forgeable counter.
- TOCTOU-safe Kanban transitions via `BEGIN IMMEDIATE`; atomic `claim`.
- Tamper-evident, optionally-persisted audit log (hash-chained).
- Real sandbox isolation proof (no host imports) with an actual test asserting it.
- Integrity errors instead of silent data substitution in the SQLite plugins.
- Consistent typed errors; opaque external-facing error strings (no detail leaks).
- Tests written alongside every interface — 103 of them, all green.

## Suggested priority

1. **S1** (SSRF) — close the localhost/`https://` bypass.
2. **C1** (sandbox concurrency) and **M1** (memory limit) — before any concurrent
   or multi-task use of the sandbox.
3. **S2 / S3 / S4** — boundary-aware file paths, constant-time MAC, restart-safe
   audit chain.
4. **C2** — JSON trailing-text robustness.
5. The remaining Low / minor items as cleanup.
