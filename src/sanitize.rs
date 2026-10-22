//! Neutralises text that comes from the input before it reaches a terminal.
//!
//! Calldata, JSON files and address books are attacker-controlled. Printed
//! raw, they could carry ANSI escape sequences that move the cursor, recolour
//! or erase lines (hiding a finding), or Unicode controls that reorder text
//! (`U+202E` right-to-left override) or hide it (zero-width characters).
//! Every input-derived string goes through [`sanitize`] before it is printed.

use std::fmt::Write;

/// Longest excerpt of a bad input value quoted in an error message.
pub const EXCERPT_CHARS: usize = 80;

/// Returns `s` with every control or invisible formatting character replaced
/// by a visible escape such as `\u{1b}`.
///
/// Printable text, including non-ASCII letters, is kept as is. Newlines and
/// tabs are escaped too: an input value always prints on one line. The
/// function is idempotent: its output contains no character it would escape.
pub fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if is_unsafe(c) {
            // Writing to a String cannot fail.
            let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

/// Like [`sanitize`], but keeps line breaks: each line is sanitised on its
/// own. For multi-line messages produced from input, such as argument
/// parser errors.
pub fn sanitize_lines(s: &str) -> String {
    s.split('\n').map(sanitize).collect::<Vec<_>>().join("\n")
}

/// A sanitised excerpt of `s` for error messages: at most [`EXCERPT_CHARS`]
/// characters, followed by the total length when cut.
///
/// Only for values that failed to parse. Valid addresses and hashes are never
/// shortened anywhere in blindsight.
pub fn excerpt(s: &str) -> String {
    let count = s.chars().count();
    if count <= EXCERPT_CHARS {
        sanitize(s)
    } else {
        let head: String = s.chars().take(EXCERPT_CHARS).collect();
        format!("{}… ({count} characters)", sanitize(&head))
    }
}

/// Control characters (C0, DEL, C1), Unicode format characters that change
/// how surrounding text is displayed, and characters that render as blank
/// space, which could make two different names look the same.
fn is_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'                    // soft hyphen
            | '\u{034F}'                  // combining grapheme joiner
            | '\u{115F}'..='\u{1160}'     // Hangul choseong/jungseong fillers
            | '\u{17B4}'..='\u{17B5}'     // Khmer inherent vowels (invisible)
            | '\u{061C}'                  // Arabic letter mark
            | '\u{180E}'                  // Mongolian vowel separator
            | '\u{200B}'..='\u{200F}'     // zero-width space/joiners, LRM, RLM
            | '\u{2028}'..='\u{2029}'     // line and paragraph separators
            | '\u{202A}'..='\u{202E}'     // bidi embeddings and overrides
            | '\u{2060}'..='\u{2064}'     // word joiner, invisible operators
            | '\u{2066}'..='\u{206F}'     // bidi isolates, deprecated formats
            | '\u{2800}'                  // braille pattern blank
            | '\u{3164}'                  // Hangul filler
            | '\u{FE00}'..='\u{FE0F}'     // variation selectors
            | '\u{FEFF}'                  // zero-width no-break space (BOM)
            | '\u{FFA0}'                  // halfwidth Hangul filler
            | '\u{FFF9}'..='\u{FFFB}'     // interlinear annotations
            | '\u{E0000}'..='\u{E007F}'   // tag characters
            | '\u{E0100}'..='\u{E01EF}' // variation selectors supplement
        )
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn escapes_ansi_sequences() {
        let attack = "\u{1b}[2K\u{1b}[1A\rCRITICAL hidden\u{7}";
        let clean = sanitize(attack);
        assert_eq!(clean, "\\u{1b}[2K\\u{1b}[1A\\u{d}CRITICAL hidden\\u{7}");
        assert!(!clean.contains('\u{1b}'));
    }

    #[test]
    fn escapes_bidi_and_invisible_characters() {
        assert_eq!(sanitize("abc\u{202E}fed"), "abc\\u{202e}fed");
        assert_eq!(sanitize("a\u{200B}b"), "a\\u{200b}b");
        assert_eq!(sanitize("\u{FEFF}x"), "\\u{feff}x");
        assert_eq!(sanitize("a\nb\tc"), "a\\u{a}b\\u{9}c");
        assert_eq!(sanitize("\u{9b}31m"), "\\u{9b}31m"); // C1 CSI
    }

    #[test]
    fn escapes_characters_that_render_blank() {
        for c in [
            '\u{034F}',
            '\u{115F}',
            '\u{1160}',
            '\u{17B4}',
            '\u{2800}',
            '\u{3164}',
            '\u{FE0F}',
            '\u{FFA0}',
            '\u{E0100}',
        ] {
            let text = format!("Treasury{c}");
            assert_ne!(sanitize(&text), text, "U+{:04X}", u32::from(c));
        }
    }

    #[test]
    fn keeps_printable_text() {
        let text = "Transfer 1.5 USDC to Zoë — 0xAbC… ✓ 日本";
        assert_eq!(sanitize(text), text);
    }

    #[test]
    fn sanitize_lines_keeps_line_breaks_only() {
        assert_eq!(
            sanitize_lines("error: bad\u{1b}[2J\n\ttip\r"),
            "error: bad\\u{1b}[2J\n\\u{9}tip\\u{d}"
        );
    }

    #[test]
    fn excerpt_cuts_long_values_and_says_so() {
        let long = "z".repeat(200);
        let e = excerpt(&long);
        assert!(e.starts_with(&"z".repeat(EXCERPT_CHARS)));
        assert!(e.ends_with("… (200 characters)"));
        assert_eq!(excerpt("short"), "short");
    }

    proptest! {
        #[test]
        fn output_never_contains_unsafe_characters(s in any::<String>()) {
            prop_assert!(!sanitize(&s).chars().any(is_unsafe));
        }

        #[test]
        fn sanitize_is_idempotent(s in any::<String>()) {
            let once = sanitize(&s);
            prop_assert_eq!(sanitize(&once), once);
        }
    }
}
