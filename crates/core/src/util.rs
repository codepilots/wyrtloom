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
/// Consume the body of a string-terminated control sequence (OSC, DCS, etc.).
/// Terminates on ST (`ESC \`) — both bytes consumed — or, when `allow_bel` is
/// set (OSC only), on BEL (0x07). A bare ESC that is NOT the start of an ST is
/// left UNconsumed so the outer state machine reprocesses it as a fresh escape;
/// this prevents a crafted unterminated OSC followed by a real CSI (e.g.
/// `ESC ] … ESC [ 31 m`) from leaking the trailing `[31m` into the output.
fn consume_string_terminated(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    allow_bel: bool,
) {
    while let Some(&nc) = chars.peek() {
        if allow_bel && nc == '\u{07}' {
            chars.next(); // consume BEL terminator
            return;
        }
        if nc == '\x1b' {
            // Lookahead for ST (`ESC \`) without committing the ESC.
            let mut clone = chars.clone();
            clone.next(); // the ESC
            if clone.peek() == Some(&'\\') {
                // Real ST: consume both bytes and finish.
                chars.next();
                chars.next();
                return;
            }
            // Not an ST: stop here and leave the ESC for the outer loop to
            // reprocess as a new escape sequence (so it is stripped, not leaked).
            return;
        }
        chars.next(); // ordinary sequence byte — drop it
    }
}

pub fn strip_control(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // A small state machine over the common escape-sequence forms. The
            // old "skip until an ASCII letter" logic mishandled OSC/DCS (which
            // end in BEL/ST, not a letter) and 2-char `ESC X` forms — it either
            // over-consumed benign following text or leaked the payload.
            match chars.peek() {
                // CSI: `ESC [` … parameter/intermediate bytes, then a final
                // byte in 0x40..=0x7E.
                Some('[') => {
                    chars.next(); // consume '['
                    for nc in chars.by_ref() {
                        if ('\u{40}'..='\u{7E}').contains(&nc) {
                            break;
                        }
                    }
                }
                // OSC: `ESC ]` … terminated by BEL (0x07) or ST (`ESC \`).
                Some(']') => {
                    chars.next(); // consume ']'
                    consume_string_terminated(&mut chars, true);
                }
                // DCS/SOS/PM/APC: `ESC P` / `ESC X` / `ESC ^` / `ESC _` …
                // terminated by ST (`ESC \`).
                Some('P') | Some('X') | Some('^') | Some('_') => {
                    chars.next(); // consume the introducer
                    consume_string_terminated(&mut chars, false);
                }
                // Any other 2-char escape `ESC X`: drop ESC and the next char.
                Some(_) => {
                    chars.next();
                }
                // Lone trailing ESC: drop it.
                None => {}
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

    // 029 — OSC sequence terminated by BEL is fully dropped, not over-consumed.
    #[test]
    fn strips_osc_terminated_by_bel() {
        assert_eq!(strip_control("\x1b]0;title\x07after"), "after");
    }

    // 029 — OSC terminated by ST (`ESC \`).
    #[test]
    fn strips_osc_terminated_by_st() {
        assert_eq!(strip_control("\x1b]0;title\x1b\\after"), "after");
    }

    // 029 — a 2-char `ESC X` form drops exactly ESC + one char, keeping the rest.
    #[test]
    fn strips_two_char_escape_keeps_following_text() {
        assert_eq!(strip_control("\x1b7keep"), "keep");
    }

    // 029 — bracketed-paste CSI (`ESC [ 200 ~`) is handled (consumed up to '~').
    #[test]
    fn handles_bracketed_paste_csi() {
        assert_eq!(strip_control("\x1b[200~paste"), "paste");
    }

    // 029 — DCS terminated by ST is dropped.
    #[test]
    fn strips_dcs_terminated_by_st() {
        assert_eq!(strip_control("\x1bP1;2;3qpayload\x1b\\after"), "after");
    }

    // 029 — an UNTERMINATED OSC immediately followed by a real CSI must NOT leak
    // the CSI text: the embedded ESC is reprocessed as a new escape, not eaten
    // as a malformed ST. Regression for the "[31m leak" bug.
    #[test]
    fn unterminated_osc_then_csi_does_not_leak() {
        assert_eq!(strip_control("\x1b]0;title\x1b[31mred"), "red");
        // Followed by plain text after the CSI's final byte.
        assert_eq!(strip_control("\x1b]9;\x1b[2Jwiped"), "wiped");
    }
}
