//! Canonical, unambiguous byte encoding for signing and MAC verification.
//!
//! Several components must produce *identical* bytes for a signature to verify
//! across process and crate boundaries — the client signer, the client-auth
//! plugin, and the API server all sign/verify the same request; the gate engine
//! signs and later re-verifies a token. The Ecosystem Lens says this shared
//! agreement is a core primitive, not something each plugin reinvents.
//!
//! The encoding is **length-prefixed**: every field is written as an 8-byte
//! big-endian length followed by its bytes, under a leading domain-separation
//! tag. Because each field carries its own length, no field boundary can be
//! shifted without changing the bytes (e.g. `actor="a"` + `task="bX"` and
//! `actor="ab"` + `task="X"` encode differently). Different domains never collide.

/// Builder for a canonical, length-prefixed byte string.
pub struct CanonicalEncoder {
    buf: Vec<u8>,
}

impl CanonicalEncoder {
    /// Begin an encoding under a domain-separation tag (itself length-prefixed),
    /// so encodings for different purposes can never be confused or replayed
    /// across domains even under the same key.
    pub fn new(domain: &str) -> Self {
        let mut e = Self { buf: Vec::new() };
        e.write(domain.as_bytes());
        e
    }

    /// Append a positional length-prefixed field.
    pub fn field(mut self, bytes: &[u8]) -> Self {
        self.write(bytes);
        self
    }

    /// Append a positional length-prefixed string field.
    pub fn str_field(self, s: &str) -> Self {
        self.field(s.as_bytes())
    }

    /// Append a named field: both the tag and the value are length-prefixed, so
    /// neither a tag/value nor a value/value boundary can shift.
    pub fn tagged(mut self, tag: &str, bytes: &[u8]) -> Self {
        self.write(tag.as_bytes());
        self.write(bytes);
        self
    }

    fn write(&mut self, f: &[u8]) {
        self.buf.extend_from_slice(&(f.len() as u64).to_be_bytes());
        self.buf.extend_from_slice(f);
    }

    /// Consume the builder and return the canonical bytes.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_boundaries_are_unambiguous() {
        let a = CanonicalEncoder::new("d").str_field("a").str_field("bX").finish();
        let b = CanonicalEncoder::new("d").str_field("ab").str_field("X").finish();
        assert_ne!(a, b, "shifting a field boundary must change the bytes");
    }

    #[test]
    fn domain_separation_changes_output() {
        let a = CanonicalEncoder::new("domain-1").str_field("x").finish();
        let b = CanonicalEncoder::new("domain-2").str_field("x").finish();
        assert_ne!(a, b);
    }

    #[test]
    fn tagged_is_deterministic_and_boundary_safe() {
        let a = CanonicalEncoder::new("d").tagged("from", b"a").tagged("to", b"bX").finish();
        let b = CanonicalEncoder::new("d").tagged("from", b"ab").tagged("to", b"X").finish();
        assert_ne!(a, b);
        // Same inputs → same bytes.
        let c = CanonicalEncoder::new("d").tagged("from", b"a").tagged("to", b"bX").finish();
        assert_eq!(a, c);
    }
}
