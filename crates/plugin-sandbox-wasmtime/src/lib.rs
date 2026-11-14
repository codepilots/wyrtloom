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
///   030 – The compiled-module cache is bounded (module count and total WASM
///         bytes) with least-recently-used eviction, so a stream of distinct
///         modules can no longer grow memory without limit.
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use wasmtime::{Config, Engine, Linker, Module, ResourceLimiter, Store};
use wyrtloom_core::sandbox::{CompileLimits, ResourceLimits, SafeModule, SandboxError, SandboxRuntime};
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

/// Bounds on the compiled-module cache (finding 030).
///
/// Both limits apply; the least-recently-used module is evicted until a new one
/// fits. Eviction only costs a recompile if that module is executed again.
///
/// `max_wasm_bytes` counts the modules' *source* WASM bytes, which is a proxy
/// for retained memory, not a measurement: compiled code is typically several
/// times larger than its source. Size the limit with that in mind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleCacheLimits {
    /// Maximum number of cached modules. 0 disables caching.
    pub max_modules: usize,
    /// Maximum total source WASM bytes across cached modules. A single module
    /// larger than this is compiled and run but never cached.
    pub max_wasm_bytes: usize,
}

impl Default for ModuleCacheLimits {
    /// 64 modules / 64 MiB of source WASM: ample for a fixed plugin set.
    fn default() -> Self {
        Self { max_modules: 64, max_wasm_bytes: 64 * 1024 * 1024 }
    }
}

struct CacheEntry<V> {
    value: V,
    size: usize,
    last_used: u64,
}

/// A small LRU cache bounded by entry count and total declared size. Generic
/// over the value so the eviction logic is testable without compiling WASM.
/// Eviction scans for the oldest entry; the cache is small by construction.
struct BoundedCache<V> {
    limits: ModuleCacheLimits,
    entries: HashMap<[u8; 32], CacheEntry<V>>,
    total_size: usize,
    /// Logical clock: bumped on every hit and insert to order entries by use.
    clock: u64,
}

impl<V: Clone> BoundedCache<V> {
    fn new(limits: ModuleCacheLimits) -> Self {
        Self { limits, entries: HashMap::new(), total_size: 0, clock: 0 }
    }

    fn get(&mut self, key: &[u8; 32]) -> Option<V> {
        self.clock += 1;
        let clock = self.clock;
        self.entries.get_mut(key).map(|e| {
            e.last_used = clock;
            e.value.clone()
        })
    }

    /// Insert `value`, evicting least-recently-used entries until it fits. A
    /// value that can never fit (caching disabled, or larger than the whole
    /// byte budget) is simply not cached, and evicts nothing.
    fn insert(&mut self, key: [u8; 32], value: V, size: usize) {
        if self.limits.max_modules == 0 || size > self.limits.max_wasm_bytes {
            return;
        }
        if let Some(old) = self.entries.remove(&key) {
            self.total_size -= old.size;
        }
        while self.entries.len() >= self.limits.max_modules
            || self.total_size + size > self.limits.max_wasm_bytes
        {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_used)
                .map(|(k, _)| *k);
            match oldest {
                Some(k) => {
                    if let Some(e) = self.entries.remove(&k) {
                        self.total_size -= e.size;
                    }
                }
                None => break,
            }
        }
        self.clock += 1;
        self.entries.insert(key, CacheEntry { value, size, last_used: self.clock });
        self.total_size += size;
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn contains(&self, key: &[u8; 32]) -> bool {
        self.entries.contains_key(key)
    }
}

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

/// Compile-rate limiting (roadmap item: a rapid stream of *distinct* modules
/// forces repeated Cranelift compilation — a CPU-DoS. Cache hits are free and
/// never counted; this budgets only fresh compiles).
struct CompileRateLimiter {
    window_secs: u64,
    max_per_window: usize,
    /// Timestamps (Instant::now) of admitted compiles within the current
    /// window. Evicted as they age out; bounded by `max_per_window`.
    admits: VecDeque<Instant>,
}

impl CompileRateLimiter {
    fn new(limits: CompileLimits) -> Self {
        Self {
            window_secs: limits.window_secs,
            max_per_window: limits.max_compiles_per_window,
            admits: VecDeque::new(),
        }
    }

    /// Attempt to admit one fresh compile. Returns Ok(()) if within budget;
    /// Err(CompileRateExceeded) otherwise. Never counts a cache hit.
    fn try_admit(&mut self, now: Instant) -> Result<(), SandboxError> {
        if self.max_per_window == 0 {
            return Err(SandboxError::CompileRateExceeded);
        }
        let window = Duration::from_secs(self.window_secs);
        // Drop any admits that fell out of the window.
        while let Some(&first) = self.admits.front() {
            if now.duration_since(first) >= window {
                self.admits.pop_front();
            } else {
                break;
            }
        }
        if self.admits.len() >= self.max_per_window {
            return Err(SandboxError::CompileRateExceeded);
        }
        self.admits.push_back(now);
        Ok(())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.admits.len()
    }
}

pub struct WasmtimeSandbox {
    engine: Arc<Engine>,
    /// Bounded LRU cache of compiled modules keyed by SHA-256 of the WASM bytes.
    module_cache: Mutex<BoundedCache<Module>>,
    /// Per-module compile-size cap + fresh-compile rate limit.
    compile_limits: CompileLimits,
    /// Fresh-compile admission budget (mirrors `compile_limits`).
    compile_limiter: Mutex<CompileRateLimiter>,
    /// Set on drop to stop the background epoch ticker thread.
    ticker_stop: Arc<AtomicBool>,
    /// Handle to the background epoch ticker, joined on Drop so the thread and
    /// its `Arc<Engine>` are released deterministically.
    ticker: Option<JoinHandle<()>>,
}

impl WasmtimeSandbox {
    /// Create a sandbox with the default module-cache and compile limits
    /// ([`ModuleCacheLimits::default`], [`CompileLimits::default`]).
    pub fn new() -> Result<Self, SandboxError> {
        Self::with_limits(ModuleCacheLimits::default(), CompileLimits::default())
    }

    /// Create a sandbox with explicit module-cache bounds. Compile limits use
    /// their defaults. Lower cache limits when modules come from untrusted
    /// tenants; raise them for a large fixed set.
    pub fn with_cache_limits(cache_limits: ModuleCacheLimits) -> Result<Self, SandboxError> {
        Self::with_limits(cache_limits, CompileLimits::default())
    }

    /// Create a sandbox with explicit module-cache and compile limits.
    pub fn with_limits(
        cache_limits: ModuleCacheLimits,
        compile_limits: CompileLimits,
    ) -> Result<Self, SandboxError> {
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
            module_cache: Mutex::new(BoundedCache::new(cache_limits)),
            compile_limits,
            compile_limiter: Mutex::new(CompileRateLimiter::new(compile_limits)),
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
            let m = if let Some(m) = cache.get(&module.content_hash) {
                m
            } else {
                // Per-module compile-size gate (roadmap: a single very large
                // module must be refused BEFORE Cranelift burns CPU/memory —
                // merely "run but not cached" still compiles it).
                if module.wasm_bytes.len() > self.compile_limits.max_module_bytes {
                    return Err(SandboxError::ModuleTooLarge(
                        module.wasm_bytes.len(),
                        self.compile_limits.max_module_bytes,
                    ));
                }
                // Fresh-compile rate limit (roadmap: a rapid stream of distinct
                // modules forces repeated compiles — a CPU-DoS). Cache hits are
                // free; only a genuine compile is admitted and counted.
                {
                    let now = Instant::now();
                    let mut limiter = self.compile_limiter.lock().unwrap();
                    limiter.try_admit(now)?;
                }
                let m = Module::new(&self.engine, &module.wasm_bytes)
                    .map_err(|e| SandboxError::Compile(e.to_string()))?;
                drop(cache);
                // 030 — bounded insert: may evict the least-recently-used
                // modules, or skip caching a module too large for the budget.
                self.module_cache
                    .lock()
                    .unwrap()
                    .insert(module.content_hash, m.clone(), module.wasm_bytes.len());
                m
            };
            m
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

    // ── 030 — bounded module cache ──────────────────────────────────────────

    fn key(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn cache(max_modules: usize, max_wasm_bytes: usize) -> BoundedCache<u32> {
        BoundedCache::new(ModuleCacheLimits { max_modules, max_wasm_bytes })
    }

    #[test]
    fn cache_never_exceeds_module_count() {
        let mut c = cache(3, usize::MAX);
        for n in 0..50u8 {
            c.insert(key(n), n as u32, 10);
            assert!(c.len() <= 3);
        }
        // The three most recent survive.
        assert!(c.contains(&key(47)) && c.contains(&key(48)) && c.contains(&key(49)));
        assert_eq!(c.total_size, 30);
    }

    #[test]
    fn cache_evicts_least_recently_used_not_oldest_inserted() {
        let mut c = cache(2, usize::MAX);
        c.insert(key(1), 1, 10);
        c.insert(key(2), 2, 10);
        // Touch 1 so that 2 becomes the least recently used.
        assert_eq!(c.get(&key(1)), Some(1));
        c.insert(key(3), 3, 10);
        assert!(c.contains(&key(1)));
        assert!(!c.contains(&key(2)));
        assert!(c.contains(&key(3)));
    }

    #[test]
    fn cache_never_exceeds_byte_budget() {
        let mut c = cache(100, 100);
        c.insert(key(1), 1, 40);
        c.insert(key(2), 2, 40);
        // 60 more would make 140: both older entries must go to fit it.
        c.insert(key(3), 3, 60);
        assert!(c.total_size <= 100);
        assert!(!c.contains(&key(1)));
        assert!(c.contains(&key(3)));
        // Size accounting stays exact after evictions.
        let sum: usize = c.entries.values().map(|e| e.size).sum();
        assert_eq!(c.total_size, sum);
    }

    #[test]
    fn oversized_entry_is_not_cached_and_evicts_nothing() {
        let mut c = cache(100, 100);
        c.insert(key(1), 1, 50);
        c.insert(key(2), 2, 101);
        assert!(c.contains(&key(1)), "an uncacheable module must not flush the cache");
        assert!(!c.contains(&key(2)));
        assert_eq!(c.total_size, 50);
    }

    #[test]
    fn zero_capacity_disables_caching() {
        let mut c = cache(0, usize::MAX);
        c.insert(key(1), 1, 10);
        assert_eq!(c.len(), 0);
        assert_eq!(c.get(&key(1)), None);
    }

    #[test]
    fn reinserting_a_key_does_not_double_count_its_size() {
        let mut c = cache(4, 100);
        c.insert(key(1), 1, 30);
        c.insert(key(1), 2, 30);
        assert_eq!(c.len(), 1);
        assert_eq!(c.total_size, 30);
        assert_eq!(c.get(&key(1)), Some(2));
    }

    /// A distinct, valid module per `n` (the constant changes the bytes).
    fn distinct_module(n: u32) -> Vec<u8> {
        wat::parse_str(format!(
            r#"(module
              (memory (export "memory") 1)
              (func (export "unused") (result i32) i32.const {n})
              (func (export "run") (param i32 i32) (result i64) i64.const 0)
            )"#
        ))
        .unwrap()
    }

    // The headline: a stream of distinct modules leaves the cache at its cap.
    #[test]
    fn stream_of_distinct_modules_keeps_cache_bounded() {
        let sb = WasmtimeSandbox::with_cache_limits(ModuleCacheLimits {
            max_modules: 4,
            max_wasm_bytes: usize::MAX,
        })
        .unwrap();
        for n in 0..20 {
            sb.execute(SafeModule::new(distinct_module(n)), vec![], ResourceLimits::default())
                .unwrap();
            assert!(sb.module_cache.lock().unwrap().len() <= 4);
        }
        assert_eq!(sb.module_cache.lock().unwrap().len(), 4);
    }

    // An evicted module is recompiled on demand and still runs correctly.
    #[test]
    fn evicted_module_still_executes() {
        let sb = WasmtimeSandbox::with_cache_limits(ModuleCacheLimits {
            max_modules: 1,
            max_wasm_bytes: usize::MAX,
        })
        .unwrap();
        let first = SafeModule::new(distinct_module(1));
        let first_hash = first.content_hash;
        sb.execute(first, vec![], ResourceLimits::default()).unwrap();
        sb.execute(SafeModule::new(distinct_module(2)), vec![], ResourceLimits::default())
            .unwrap();
        assert!(!sb.module_cache.lock().unwrap().contains(&first_hash));
        sb.execute(SafeModule::new(distinct_module(1)), vec![], ResourceLimits::default())
            .unwrap();
        assert!(sb.module_cache.lock().unwrap().contains(&first_hash));
    }

    #[test]
    fn caching_disabled_still_executes() {
        let sb = WasmtimeSandbox::with_cache_limits(ModuleCacheLimits {
            max_modules: 0,
            max_wasm_bytes: 0,
        })
        .unwrap();
        for _ in 0..2 {
            sb.execute(SafeModule::new(distinct_module(7)), vec![], ResourceLimits::default())
                .unwrap();
        }
        assert_eq!(sb.module_cache.lock().unwrap().len(), 0);
    }

    // A module that fails to compile must not occupy a cache slot.
    #[test]
    fn failed_compile_is_not_cached() {
        let sb = sandbox();
        let _ = sb.execute(
            SafeModule::new(b"not wasm at all".to_vec()),
            vec![],
            ResourceLimits::default(),
        );
        assert_eq!(sb.module_cache.lock().unwrap().len(), 0);
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

    // ── Per-module compile-size gate (roadmap #3) ──────────────────────────

    #[test]
    fn oversized_module_is_refused_before_compile() {
        // A module bigger than the per-module cap must be rejected even though
        // it is a valid, executable module: "run but not cached" would still
        // compile it and burn CPU (the failing behaviour we are closing).
        let sb = WasmtimeSandbox::with_limits(
            ModuleCacheLimits::default(),
            CompileLimits { max_module_bytes: 32, max_compiles_per_window: 4, window_secs: 10 },
        )
        .unwrap();
        // Real, runnable module — larger than the 32-byte cap.
        let wasm = wat::parse_str(
            r#"(module
              (memory (export "memory") 1)
              (func (export "run") (param i32 i32) (result i64) i64.const 0)
            )"#,
        )
        .unwrap();
        let err = sb
            .execute(SafeModule::new(wasm), vec![], ResourceLimits::default())
            .unwrap_err();
        match err {
            SandboxError::ModuleTooLarge(len, cap) => {
                assert!(len > cap, "wasm was unexpectedly under the cap");
            }
            other => panic!("expected ModuleTooLarge, got {other:?}"),
        }
    }

    // ── Fresh-compile rate limit (roadmap #3) ──────────────────────────────

    #[test]
    fn distinct_stream_hits_compile_rate_limit() {
        // Tight budget: 2 compiles per 1 s. Cache hits are free, so repeating a
        // module beyond the budget must still succeed, while a 3rd distinct
        // module (a fresh compile) is refused.
        let sb = WasmtimeSandbox::with_limits(
            ModuleCacheLimits::default(),
            CompileLimits { max_module_bytes: 1 << 20, max_compiles_per_window: 2, window_secs: 1 },
        )
        .unwrap();
        // Two distinct modules compile fine.
        for n in 0..2u32 {
            sb.execute(
                SafeModule::new(distinct_module(n)),
                vec![],
                ResourceLimits::default(),
            )
            .unwrap();
        }
        // A third distinct module exceeds the budget and is refused.
        let err = sb
            .execute(SafeModule::new(distinct_module(7)), vec![], ResourceLimits::default())
            .unwrap_err();
        assert!(matches!(err, SandboxError::CompileRateExceeded));
    }

    #[test]
    fn cache_hits_do_not_count_against_compile_budget() {
        let sb = WasmtimeSandbox::with_limits(
            ModuleCacheLimits::default(),
            CompileLimits { max_module_bytes: 1 << 20, max_compiles_per_window: 1, window_secs: 60 },
        )
        .unwrap();
        let module = SafeModule::new(distinct_module(3));
        // First run compiles (1/1 budget used).
        sb.execute(module.clone(), vec![], ResourceLimits::default()).unwrap();
        // Second run is a cache hit — must succeed, never counted.
        for _ in 0..5 {
            sb.execute(module.clone(), vec![], ResourceLimits::default()).unwrap();
        }
    }

    // ── CompileRateLimiter unit tests (no WASM) ────────────────────────────

    #[test]
    fn limiter_zero_budget_refuses_everything() {
        let mut l = CompileRateLimiter::new(CompileLimits {
            max_module_bytes: 0,
            max_compiles_per_window: 0,
            window_secs: 10,
        });
        let e = l.try_admit(Instant::now()).unwrap_err();
        assert!(matches!(e, SandboxError::CompileRateExceeded));
    }

    #[test]
    fn limiter_evicts_expired_admits_in_window() {
        let mut l = CompileRateLimiter::new(CompileLimits {
            max_module_bytes: 0,
            max_compiles_per_window: 1,
            window_secs: 10,
        });
        let t0 = Instant::now();
        l.try_admit(t0).unwrap();
        // 11 s later the single admit has expired — admissible again.
        let t = t0 + Duration::from_secs(11);
        l.try_admit(t).unwrap();
        assert_eq!(l.len(), 1);
    }
}
