//! Shared utilities promoted to core so every plugin applies the same audited
//! logic (Ecosystem Lens). Security controls that each implementation must apply
//! identically — like stripping terminal-injection sequences from untrusted text
//! — belong here rather than copy-pasted per plugin.

/// True for Unicode bidirectional/format control codepoints that are *not* caught
/// by [`char::is_control`] (which only covers C0/C1). These (e.g. U+202E
/// RIGHT-TO-LEFT OVERRIDE, the isolates, zero-width chars) enable "Trojan
/// Source"-style visual spoofing in logs and terminals.
pub fn is_bidi_or_format(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}'   // zero-width space/joiners + LRM/RLM marks
        | '\u{202A}'..='\u{202E}' // bidi embeddings/overrides
        | '\u{2060}'..='\u{2064}' // word joiner + invisible operators
        | '\u{2066}'..='\u{2069}' // bidi isolates
        | '\u{FEFF}'              // zero-width no-break space / BOM
    )
}

/// Strip ANSI escape sequences and control characters from untrusted text before
/// it is shown on a terminal or embedded in a prompt, while preserving the
/// legitimate whitespace `\n`, `\r`, `\t`. Prevents terminal-injection from a
/// malicious or compromised source.
///
/// This is the canonical implementation; provider plugins re-export it rather
/// than vendoring a copy.
pub fn strip_control(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip until the terminating ASCII letter of the escape sequence.
            while let Some(&nc) = chars.peek() {
                chars.next();
                if nc.is_ascii_alphabetic() {
                    break;
                }
            }
        } else if (c.is_control() && c != '\n' && c != '\r' && c != '\t')
            || is_bidi_or_format(c)
        {
            // Drop other control characters and bidi/format codepoints.
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_ansi_keeps_whitespace() {
        assert_eq!(strip_control("\x1b[31mred\x1b[0m text"), "red text");
        assert_eq!(strip_control("a\nb\tc\r\n"), "a\nb\tc\r\n");
        assert_eq!(strip_control("bell\x07here"), "bellhere");
    }

    #[test]
    fn strips_unicode_bidi_and_zero_width() {
        // Trojan-Source style override + zero-width are removed.
        assert_eq!(strip_control("admin\u{202e}nimda"), "adminnimda");
        assert_eq!(strip_control("a\u{200b}b\u{feff}c"), "abc");
    }
}
