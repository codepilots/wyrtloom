use crate::plugin::Capability;
use crate::types::Bytes;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub max_memory_bytes: u64,
    pub max_wallclock_ms: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self { max_memory_bytes: 16 * 1024 * 1024, max_wallclock_ms: 5_000 }
    }
}

/// Opaque handle to a compiled safe WASM module.
/// The `content_hash` is the SHA-256 of `wasm_bytes`, computed once at
/// construction so the sandbox can key its module cache without re-hashing.
#[derive(Debug, Clone)]
pub struct SafeModule {
    pub wasm_bytes: Bytes,
    pub content_hash: [u8; 32],
}

impl SafeModule {
    pub fn new(wasm_bytes: Bytes) -> Self {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(&wasm_bytes);
        Self { wasm_bytes, content_hash: h.finalize().into() }
    }
}

/// Limits on sandbox *compilation*, complementing [`ModuleCacheLimits`] (in the
/// wasmtime plugin). The cache bounds retained memory, but compilation itself
/// is the CPU-DoS surface: a single very large module is still compiled on
/// demand, and a rapid stream of distinct modules forces repeated Cranelift
/// compiles. These two limits gate compilation up-front.
///
/// - `max_module_bytes` — a module whose source WASM bytes exceed this is
///   refused *before* Cranelift runs, never merely "run but not cached".
/// - `max_compiles_per_window` — at most this many fresh compilations are
///   admitted per `window_secs`; cache hits are free. A burst beyond the
///   budget is refused (rate-limited) rather than burning CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompileLimits {
    pub max_module_bytes: usize,
    pub max_compiles_per_window: usize,
    pub window_secs: u64,
}

impl Default for CompileLimits {
    /// 16 MiB source WASM per module (well above any legit SAFE plugin), and
    /// 32 fresh compiles per 10 s — ample for a fixed plugin set, and a hard
    /// brake on a hostile stream of distinct modules.
    fn default() -> Self {
        Self { max_module_bytes: 16 * 1024 * 1024, max_compiles_per_window: 32, window_secs: 10 }
    }
}

#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("memory limit exceeded")]
    MemoryExceeded,
    #[error("execution timed out")]
    Timeout,
    #[error("module too large: {0} bytes exceeds per-module limit of {1}")]
    ModuleTooLarge(usize, usize),
    #[error("compile rate limit exceeded")]
    CompileRateExceeded,
    #[error("sandboxed code attempted to access host capability: {0:?}")]
    HostAccessAttempted(Capability),
    #[error("wasm trap: {0}")]
    Trap(String),
    #[error("compile error: {0}")]
    Compile(String),
}

/// Contract for the sandbox runtime.  The implementation (wasmtime) is a
/// core-controlled plugin — loaded before any untrusted code, never
/// replaceable by untrusted code.
pub trait SandboxRuntime: Send + Sync {
    fn execute(
        &self,
        module: SafeModule,
        input: Bytes,
        limits: ResourceLimits,
    ) -> Result<Bytes, SandboxError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_limits_have_sensible_defaults() {
        let lim = ResourceLimits::default();
        assert!(lim.max_memory_bytes > 0);
        assert!(lim.max_wallclock_ms > 0);
    }

    #[test]
    fn compile_limits_have_sensible_defaults() {
        let lim = CompileLimits::default();
        assert!(lim.max_module_bytes > 0);
        assert!(lim.max_compiles_per_window > 0);
        assert!(lim.window_secs > 0);
    }

    #[test]
    fn sandbox_errors_are_typed() {
        let e = SandboxError::MemoryExceeded;
        assert!(e.to_string().contains("memory"));

        let e = SandboxError::Timeout;
        assert!(e.to_string().contains("timed out"));

        let e = SandboxError::HostAccessAttempted(Capability::Shell);
        assert!(e.to_string().contains("Shell"));
    }
}
