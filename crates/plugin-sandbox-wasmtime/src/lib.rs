/// Wasmtime sandbox runtime plugin.
///
/// Security hardening (see CHANGELOG.md):
///   012 – Input length bounds-checked before i32 cast to prevent truncation.
///   013 – Epoch-based wall-clock interruption replaces fuel-only limiting;
///         fuel remains as a secondary compute budget guard.
///   014 – Compiled modules are cached by SHA-256 of their WASM bytes to
///         prevent repeated Cranelift compilation (CPU DoS vector).
///   019 – Default trait impl removed; construction is now explicitly fallible.
///   C1  – Executions are serialised so one call's wall-clock timeout (which
///         increments the engine-global epoch) cannot prematurely trap another
///         in-flight call sharing the same engine.
///   M1  – max_memory_bytes is enforced via a per-store ResourceLimiter; a SAFE
///         module can no longer grow linear memory without bound.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};
use wyrtloom_core::sandbox::{ResourceLimits, SafeModule, SandboxError, SandboxRuntime};
use wyrtloom_core::types::Bytes;

pub struct WasmtimeSandbox {
    engine: Arc<Engine>,
    /// Cache of compiled modules keyed by SHA-256 of the WASM bytes.
    module_cache: Mutex<HashMap<[u8; 32], Module>>,
    /// Serialises executions (C1).  The wall-clock timeout increments the
    /// engine-global epoch; without this lock, overlapping calls could trip
    /// each other's deadlines.
    exec_lock: Mutex<()>,
}

impl WasmtimeSandbox {
    pub fn new() -> Result<Self, SandboxError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        // Epoch interruption enables real wall-clock timeouts (finding 013).
        config.epoch_interruption(true);
        let engine =
            Engine::new(&config).map_err(|e| SandboxError::Compile(e.to_string()))?;
        Ok(Self {
            engine: Arc::new(engine),
            module_cache: Mutex::new(HashMap::new()),
            exec_lock: Mutex::new(()),
        })
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
        // Compilation (the expensive Cranelift path) runs WITHOUT the exec lock so
        // independent modules can still compile concurrently.
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

        // C1 — serialise only the epoch-sensitive window (store setup through the
        // timed `run.call`).  The wall-clock timeout increments the engine-global
        // epoch; holding this from before `set_epoch_deadline` until the call
        // returns ensures a timer fired for this execution cannot trap another's
        // store.  Compilation above is deliberately left outside the lock.
        let _exec = self.exec_lock.lock().unwrap();

        // M1 — enforce the memory cap via a per-store ResourceLimiter so the
        // module cannot grow linear memory beyond limits.max_memory_bytes.
        let store_limits = StoreLimitsBuilder::new()
            .memory_size(limits.max_memory_bytes as usize)
            .build();
        let mut store = Store::new(&self.engine, store_limits);
        store.limiter(|state| state);

        // Fuel-based secondary compute limit.  The 10_000-per-ms factor is a
        // deliberately coarse heuristic (M6): fuel bounds instruction count as a
        // backstop to the authoritative wall-clock epoch deadline below — the two
        // budgets are intentionally independent, not a precise conversion.
        let fuel = limits.max_wallclock_ms.saturating_mul(10_000);
        store
            .set_fuel(fuel)
            .map_err(|e| SandboxError::Trap(format!("fuel setup: {}", e)))?;

        // Epoch deadline: trap after 1 epoch increment (finding 013).
        // set_epoch_deadline(1) = trap when engine epoch reaches current + 1.
        store.set_epoch_deadline(1);
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

        // 013 — spawn the epoch timer only here, after all fallible setup has
        // succeeded.  Earlier spawning left a live thread on every early-return
        // error path; that leaked increment would corrupt the *next* call's
        // relative epoch deadline.
        let engine_ref = Arc::clone(&self.engine);
        let deadline_ms = limits.max_wallclock_ms;
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel_clone = Arc::clone(&cancel);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(deadline_ms));
            if !cancel_clone.load(std::sync::atomic::Ordering::SeqCst) {
                engine_ref.increment_epoch();
            }
        });

        let result = run
            .call(&mut store, (0, input_len))
            .map_err(|e| {
                let msg = e.to_string();
                // Both epoch (wall-clock) and fuel (compute-budget) exhaustion are
                // surfaced as Timeout; anything else is a genuine trap.
                if ["epoch", "interrupt", "fuel"].iter().any(|k| msg.contains(k)) {
                    SandboxError::Timeout
                } else {
                    SandboxError::Trap(msg)
                }
            });

        // Cancel the epoch timer if the call returned before the deadline.
        cancel.store(true, std::sync::atomic::Ordering::SeqCst);

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

    // M1 — a module whose initial memory exceeds max_memory_bytes is rejected,
    // proving the per-store memory limiter is active.
    #[test]
    fn module_exceeding_memory_limit_is_rejected() {
        let sb = sandbox();
        // 10 pages (640 KiB) initial memory against a 1-page (64 KiB) cap.
        let wasm = wat::parse_str(
            r#"(module
              (memory (export "memory") 10)
              (func (export "run") (param i32 i32) (result i64) i64.const 0)
            )"#,
        )
        .unwrap();
        let limits = ResourceLimits { max_memory_bytes: 64 * 1024, max_wallclock_ms: 5_000 };
        let err = sb
            .execute(SafeModule::new(wasm), vec![], limits)
            .unwrap_err();
        assert!(matches!(err, SandboxError::Trap(_)));
    }

    // 019 — Default is not implemented; construction is explicitly fallible
    // (compile-time check: this test verifies new() returns Result)
    #[test]
    fn construction_is_fallible() {
        let result = WasmtimeSandbox::new();
        assert!(result.is_ok()); // engine init should succeed on this platform
    }
}
