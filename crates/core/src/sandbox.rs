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
pub struct SafeModule {
    pub wasm_bytes: Bytes,
}

#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("memory limit exceeded")]
    MemoryExceeded,
    #[error("execution timed out")]
    Timeout,
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
    fn sandbox_errors_are_typed() {
        let e = SandboxError::MemoryExceeded;
        assert!(e.to_string().contains("memory"));

        let e = SandboxError::Timeout;
        assert!(e.to_string().contains("timed out"));

        let e = SandboxError::HostAccessAttempted(Capability::Shell);
        assert!(e.to_string().contains("Shell"));
    }
}
