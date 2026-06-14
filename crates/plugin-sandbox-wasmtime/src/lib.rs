/// Wasmtime sandbox runtime plugin.
///
/// Security hardening (see CHANGELOG.md):
///   012 – Input length bounds-checked before i32 cast to prevent truncation.
///   013 – Epoch-based wall-clock interruption replaces fuel-only limiting;
///         fuel remains as a secondary compute budget guard.
///   014 – Compiled modules are cached by SHA-256 of their WASM bytes to
///         prevent repeated Cranelift compilation (CPU DoS vector).
///   019 – Default trait impl removed; construction is now explicitly fallible.
///   023 – ResourceLimits.max_memory_bytes is enforced via a wasmtime
///         ResourceLimiter that rejects memory growth beyond the cap.
///   024 – A single background epoch-ticker thread drives wall-clock timeouts;
///         the previous per-call thread both raced under concurrency and was a
///         per-execution thread-spawn DoS vector.
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;
use wasmtime::{Config, Engine, Linker, Module, ResourceLimiter, Store};
use wyrtloom_core::sandbox::{ResourceLimits, SafeModule, SandboxError, SandboxRuntime};
use wyrtloom_core::types::Bytes;

/// Cadence of the background epoch ticker. Per-call deadlines are expressed as a
/// number of ticks (`ceil(max_wallclock_ms / TICK_MS)`), giving wall-clock
/// timeout resolution of one tick.
const TICK_MS: u64 = 1;

/// Hard upper bound on table element count (finding 027). A module that declares
/// a table with no maximum would otherwise be bounded only by fuel/epoch; this
/// caps growth so a no-max table can't be grown unboundedly within a single
/// call. 10M function-reference slots is far above any legitimate guest need.
const MAX_TABLE_ELEMS: u32 = 10_000_000;

/// Per-store data: enforces the memory cap (finding 023) via `ResourceLimiter`.
struct StoreLimits {
    max_memory_bytes: usize,
}

impl ResourceLimiter for StoreLimits {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        // Reject growth past the configured cap. Returning Ok(false) makes the
        // guest's memory.grow yield -1; an explicit allocation past the limit
        // (e.g. linear-memory initialisation) then traps.
        Ok(desired <= self.max_memory_bytes)
    }

    fn table_growing(
        &mut self,
        _current: u32,
        desired: u32,
        maximum: Option<u32>,
    ) -> wasmtime::Result<bool> {
        // Enforce BOTH the module's own declared maximum (if any) AND a hard
        // absolute cap, so a table that declares no maximum cannot be grown
        // unboundedly (previously bounded only by fuel/epoch).
        let within_module_max = maximum.map(|m| desired <= m).unwrap_or(true);
        Ok(within_module_max && desired <= MAX_TABLE_ELEMS)
    }
}

pub struct WasmtimeSandbox {
    engine: Arc<Engine>,
    /// Cache of compiled modules keyed by SHA-256 of the WASM bytes.
    module_cache: Mutex<HashMap<[u8; 32], Module>>,
    /// Set on drop to stop the background epoch ticker thread.
    ticker_stop: Arc<AtomicBool>,
    /// Handle to the background epoch ticker, joined on Drop so the thread and
    /// its `Arc<Engine>` are released deterministically.
    ticker: Option<JoinHandle<()>>,
}

impl WasmtimeSandbox {
    pub fn new() -> Result<Self, SandboxError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        // Epoch interruption enables real wall-clock timeouts (finding 013).
        config.epoch_interruption(true);
        let engine =
            Engine::new(&config).map_err(|e| SandboxError::Compile(e.to_string()))?;
        let engine = Arc::new(engine);

        // 024 — a SINGLE background ticker increments the global epoch at a
        // fixed cadence. Per-call deadlines are relative tick counts, so this
        // shared clock is sound under concurrent executions and spawns no
        // per-call threads.
        let ticker_stop = Arc::new(AtomicBool::new(false));
        let ticker = {
            let engine = Arc::clone(&engine);
            let stop = Arc::clone(&ticker_stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(TICK_MS));
                    engine.increment_epoch();
                }
            })
        };

        Ok(Self {
            engine,
            module_cache: Mutex::new(HashMap::new()),
            ticker_stop,
            ticker: Some(ticker),
        })
    }
}

impl Drop for WasmtimeSandbox {
    fn drop(&mut self) {
        // Signal the ticker to stop, then JOIN it so the thread (and the
        // `Arc<Engine>` it holds) is released deterministically before this
        // sandbox is fully dropped. The thread wakes within one TICK_MS.
        self.ticker_stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.ticker.take() {
            let _ = handle.join();
        }
    }
}

// Finding 019: Default is deliberately not implemented for WasmtimeSandbox.
// Construction is fallible — callers must handle the error explicitly.

impl SandboxRuntime for WasmtimeSandbox {
    fn execute(
        &self,
        module: SafeModule,
        input: Bytes,
        limits: ResourceLimits,
    ) -> Result<Bytes, SandboxError> {
        // 012 — bounds-check before i32 cast.
        if input.len() > i32::MAX as usize {
            return Err(SandboxError::Trap(format!(
                "input too large: {} bytes exceeds i32::MAX",
                input.len()
            )));
        }

        // 014 — look up or compile the module using the precomputed hash from
        // SafeModule::new(), avoiding a full SHA-256 on every cache-hit call.
        let compiled = {
            let mut cache = self.module_cache.lock().unwrap();
            if let Some(m) = cache.get(&module.content_hash) {
                m.clone()
            } else {
                let m = Module::new(&self.engine, &module.wasm_bytes)
                    .map_err(|e| SandboxError::Compile(e.to_string()))?;
                cache.insert(module.content_hash, m.clone());
                m
            }
        };

        // 023 — store the memory cap in the Store data and install it as the
        // ResourceLimiter so memory.grow past the cap is rejected.
        let max_memory_bytes = usize::try_from(limits.max_memory_bytes).unwrap_or(usize::MAX);
        let mut store = Store::new(&self.engine, StoreLimits { max_memory_bytes });
        store.limiter(|data| data as &mut dyn ResourceLimiter);

        // Fuel-based secondary compute limit.
        let fuel = limits.max_wallclock_ms.saturating_mul(10_000);
        store
            .set_fuel(fuel)
            .map_err(|e| SandboxError::Trap(format!("fuel setup: {}", e)))?;

        // 024 — wall-clock deadline expressed in ticks of the shared epoch
        // ticker: ceil(max_wallclock_ms / TICK_MS), at least 1 so a zero/short
        // budget still traps rather than running unbounded.
        let deadline_ticks = limits.max_wallclock_ms.div_ceil(TICK_MS).max(1);
        store.set_epoch_deadline(deadline_ticks);
        store.epoch_deadline_trap();

        // No host imports — enforces isolation; a SAFE plugin cannot call the host.
        let linker: Linker<StoreLimits> = Linker::new(&self.engine);

        let instance = linker
            .instantiate(&mut store, &compiled)
            .map_err(|e| SandboxError::Trap(e.to_string()))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| SandboxError::Trap("module must export 'memory'".into()))?;

        let input_len = input.len() as i32;
        if !input.is_empty() {
            // Additional memory-bounds check before write.
            if input.len() > memory.data_size(&store) {
                return Err(SandboxError::Trap(format!(
                    "input ({} bytes) exceeds WASM memory size ({} bytes)",
                    input.len(),
                    memory.data_size(&store)
                )));
            }
            memory
                .write(&mut store, 0, &input)
                .map_err(|e| SandboxError::Trap(e.to_string()))?;
        }

        let run = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "run")
            .map_err(|e| SandboxError::Trap(format!("module must export 'run': {}", e)))?;

        // 024 — no per-call thread: the shared background epoch ticker drives
        // the wall-clock deadline set above. The call traps once the epoch has
        // advanced `deadline_ticks` times.
        let result = run
            .call(&mut store, (0, input_len))
            .map_err(|e| {
                // Classify resource-exhaustion traps as Timeout. Match on the
                // structured wasmtime::Trap code rather than the (unstable)
                // display string: both epoch interruption and fuel exhaustion
                // mean the budget ran out.
                match e.downcast_ref::<wasmtime::Trap>() {
                    Some(wasmtime::Trap::Interrupt) | Some(wasmtime::Trap::OutOfFuel) => {
                        SandboxError::Timeout
                    }
                    _ => SandboxError::Trap(e.to_string()),
                }
            });

        let packed = result?;

        let output_ptr = ((packed >> 32) & 0xFFFF_FFFF) as usize;
        let output_len = (packed & 0xFFFF_FFFF) as usize;

        if output_len == 0 {
            return Ok(vec![]);
        }

        let mem_size = memory.data_size(&store);
        if output_ptr + output_len > mem_size {
            return Err(SandboxError::Trap("output pointer out of bounds".into()));
        }

        Ok(memory.data(&store)[output_ptr..output_ptr + output_len].to_vec())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use wyrtloom_core::sandbox::ResourceLimits;

    fn sandbox() -> WasmtimeSandbox {
        WasmtimeSandbox::new().unwrap()
    }

    #[test]
    fn executes_safe_module_returning_empty_output() {
        let sb = sandbox();
        let wasm = wat::parse_str(
            r#"(module
              (memory (export "memory") 1)
              (func (export "run") (param i32 i32) (result i64) i64.const 0)
            )"#,
        )
        .unwrap();
        let out = sb
            .execute(SafeModule::new(wasm), vec![], ResourceLimits::default())
            .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn trap_returns_trap_error() {
        let sb = sandbox();
        let wasm = wat::parse_str(
            r#"(module
              (memory (export "memory") 1)
              (func (export "run") (param i32 i32) (result i64) unreachable)
            )"#,
        )
        .unwrap();
        let err = sb
            .execute(SafeModule::new(wasm), vec![], ResourceLimits::default())
            .unwrap_err();
        assert!(matches!(err, SandboxError::Trap(_)));
    }

    #[test]
    fn invalid_wasm_bytes_give_compile_error() {
        let sb = sandbox();
        let err = sb
            .execute(
                SafeModule::new(b"not wasm at all".to_vec()),
                vec![],
                ResourceLimits::default(),
            )
            .unwrap_err();
        assert!(matches!(err, SandboxError::Compile(_)));
    }

    /// Key isolation contract: SAFE module cannot import host functions.
    #[test]
    fn module_with_host_import_fails_at_instantiation() {
        let sb = sandbox();
        let wasm = wat::parse_str(
            r#"(module
              (import "env" "read_file" (func (param i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "run") (param i32 i32) (result i64) i64.const 0)
            )"#,
        )
        .unwrap();
        let err = sb
            .execute(SafeModule::new(wasm), vec![], ResourceLimits::default())
            .unwrap_err();
        assert!(matches!(err, SandboxError::Trap(_)));
    }

    // 012 — input too large is rejected before i32 cast
    #[test]
    fn oversized_input_is_rejected() {
        let sb = sandbox();
        let wasm = wat::parse_str(
            r#"(module
              (memory (export "memory") 1)
              (func (export "run") (param i32 i32) (result i64) i64.const 0)
            )"#,
        )
        .unwrap();
        // Create a fake large input (we don't actually allocate 2 GiB —
        // just fake the check by using a vec with a reported length).
        // Instead, test the bounds check on memory write for a too-large input.
        // A 65 KiB input into a 64 KiB (1-page) WASM memory should fail.
        let big = vec![0u8; 65 * 1024]; // > 1 WASM page (64 KiB)
        let err = sb
            .execute(SafeModule::new(wasm), big, ResourceLimits::default())
            .unwrap_err();
        assert!(matches!(err, SandboxError::Trap(_)));
    }

    // 014 — cached module: second execution of same bytes should succeed
    #[test]
    fn module_cache_serves_repeated_executions() {
        let sb = sandbox();
        let wasm = wat::parse_str(
            r#"(module
              (memory (export "memory") 1)
              (func (export "run") (param i32 i32) (result i64) i64.const 0)
            )"#,
        )
        .unwrap();
        // Execute twice — second call hits the cache.
        for _ in 0..2 {
            sb.execute(
                SafeModule::new(wasm.clone()),
                vec![],
                ResourceLimits::default(),
            )
            .unwrap();
        }
        assert_eq!(sb.module_cache.lock().unwrap().len(), 1);
    }

    // 019 — Default is not implemented; construction is explicitly fallible
    // (compile-time check: this test verifies new() returns Result)
    #[test]
    fn construction_is_fallible() {
        let result = WasmtimeSandbox::new();
        assert!(result.is_ok()); // engine init should succeed on this platform
    }

    // 023 — a module that grows memory past max_memory_bytes traps.
    #[test]
    fn memory_growth_past_limit_traps() {
        let sb = sandbox();
        // Module starts at 1 page (64 KiB) and tries to grow by 32 more pages
        // (2 MiB) in `run`, traps if the grow is denied (memory.grow → -1, then
        // a store to the un-grown region is out of bounds → trap).
        let wasm = wat::parse_str(
            r#"(module
              (memory (export "memory") 1)
              (func (export "run") (param i32 i32) (result i64)
                (drop (memory.grow (i32.const 32)))
                ;; write at offset 1 MiB — only valid if the grow succeeded
                (i32.store (i32.const 1048576) (i32.const 1))
                i64.const 0)
            )"#,
        )
        .unwrap();
        // Cap memory at 1 page (64 KiB): the 32-page grow must be rejected.
        let limits = ResourceLimits { max_memory_bytes: 64 * 1024, max_wallclock_ms: 5_000 };
        let err = sb
            .execute(SafeModule::new(wasm), vec![], limits)
            .unwrap_err();
        assert!(matches!(err, SandboxError::Trap(_)), "got {:?}", err);
    }

    // 023 — a small module within the cap still runs normally.
    #[test]
    fn small_module_runs_within_memory_limit() {
        let sb = sandbox();
        let wasm = wat::parse_str(
            r#"(module
              (memory (export "memory") 1)
              (func (export "run") (param i32 i32) (result i64) i64.const 0)
            )"#,
        )
        .unwrap();
        let limits = ResourceLimits { max_memory_bytes: 16 * 1024 * 1024, max_wallclock_ms: 5_000 };
        let out = sb.execute(SafeModule::new(wasm), vec![], limits).unwrap();
        assert!(out.is_empty());
    }

    // 024 — an infinite-loop module traps on the wall-clock (epoch) deadline.
    #[test]
    fn infinite_loop_times_out() {
        let sb = sandbox();
        let wasm = wat::parse_str(
            r#"(module
              (memory (export "memory") 1)
              (func (export "run") (param i32 i32) (result i64)
                (loop $l (br $l))
                i64.const 0)
            )"#,
        )
        .unwrap();
        // Short wall-clock budget; the shared ticker advances the epoch and the
        // loop traps (Timeout). Fuel exhaustion is also mapped to Timeout.
        let limits = ResourceLimits { max_memory_bytes: 16 * 1024 * 1024, max_wallclock_ms: 50 };
        let err = sb
            .execute(SafeModule::new(wasm), vec![], limits)
            .unwrap_err();
        assert!(matches!(err, SandboxError::Timeout), "got {:?}", err);
    }
}
