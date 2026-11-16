use std::fmt;

/// A value that came from outside Guard Dog: a changelog, an issue, a relay's
/// NIP-11 document, a container label, a service banner, a Nostr note,
/// advisory text, a file name on the node.
///
/// Any of it may carry instructions aimed at an AI, escape codes aimed at a
/// terminal, or HTML aimed at the status page. So this type has no `Display`,
/// no `Deref`, no `AsRef`, no conversion back and no public field: the
/// compiler refuses to print it or hand it on as plain text. The only ways out:
///
/// - [`escape_for_terminal`](Untrusted::escape_for_terminal), to show it in a terminal;
/// - [`escape_for_html`](Untrusted::escape_for_html), to show it in a web page;
/// - [`expose_untrusted`](Untrusted::expose_untrusted), which hands back the raw
///   value. Each call is a place where outside text meets code, so each one
///   needs a reviewer's OK in the pull request. Search for `expose_untrusted`
///   to find them all.
///
/// `Debug` never shows the content, so a struct holding untrusted text can
/// still derive `Debug` without leaking that text into logs.
#[derive(Clone, PartialEq, Eq)]
pub struct Untrusted<T>(T);

impl<T> Untrusted<T> {
    /// Marks a value as untrusted. Wrap it as soon as it arrives from outside.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// The raw value, unescaped.
    ///
    /// Never pass it to a shell, SQL, a file path, or an AI prompt that can
    /// take actions. Every call needs a reviewer's OK in the pull request.
    pub fn expose_untrusted(&self) -> &T {
        &self.0
    }
}

impl<T: AsRef<str>> Untrusted<T> {
    /// The text in a form that is safe to print in a terminal, always on one line.
    ///
    /// Control characters (escape codes for colours, cursor moves, OSC 8
    /// hyperlinks and window titles; the bell; newlines and tabs) and the
    /// invisible characters that can reorder or hide text (bidirectional
    /// overrides, zero-width characters, Unicode "tag" characters) are written
    /// out visibly as `\n`, `\r`, `\t` or `\u{..}`. A backslash becomes `\\`, so
    /// the result is never ambiguous. Ordinary text, accents and most emoji pass
    /// through unchanged; emoji built with zero-width joiners show their joiners.
    ///
    /// It does not shorten the text: size limits belong where the text is read.
    pub fn escape_for_terminal(&self) -> String {
        let text = self.0.as_ref();
        let mut out = String::with_capacity(text.len());
        for c in text.chars() {
            push_visible(&mut out, c);
        }
        out
    }

    /// The text in a form that is safe inside an HTML element, or inside an
    /// attribute value in double or single quotes.
    ///
    /// `&`, `<`, `>`, `"` and `'` become character references, and control and
    /// invisible characters are made visible exactly as in
    /// [`escape_for_terminal`](Untrusted::escape_for_terminal).
    ///
    /// It is **not** safe as a URL (`href`, `src`), inside `<script>` or
    /// `<style>`, or in an unquoted attribute. Untrusted text never goes there.
    pub fn escape_for_html(&self) -> String {
        let text = self.0.as_ref();
        let mut out = String::with_capacity(text.len());
        for c in text.chars() {
            match c {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&#39;"),
                c => push_visible(&mut out, c),
            }
        }
        out
    }
}

impl<T> fmt::Debug for Untrusted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Untrusted(<hidden>)")
    }
}

/// Writes `c`, or a visible stand-in made only of ASCII letters, digits, `\`,
/// `{` and `}` when `c` could steer a terminal or hide from a reader.
fn push_visible(out: &mut String, c: char) {
    match c {
        '\\' => out.push_str("\\\\"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        c if c.is_control() || is_invisible(c) => out.extend(c.escape_unicode()),
        c => out.push(c),
    }
}

/// Characters that draw nothing but can reorder, hide or smuggle text.
///
/// This is a fixed list rather than a Unicode category lookup, so a reviewer
/// can read exactly what it covers. `char::is_control` covers the rest: C0,
/// DEL and C1, including the single-character escape-sequence starter U+009B.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}' // soft hyphen
            | '\u{034F}' // combining grapheme joiner
            | '\u{061C}' // Arabic letter mark (bidirectional)
            | '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}' // Hangul fillers, which draw as blanks
            | '\u{180E}' // Mongolian vowel separator
            | '\u{200B}'..='\u{200F}' // zero-width space, non-joiner, joiner; left-to-right and right-to-left marks
            | '\u{2028}'..='\u{202E}' // line and paragraph separators; bidirectional embeddings and overrides
            | '\u{2060}'..='\u{206F}' // word joiner, invisible operators, bidirectional isolates
            | '\u{FEFF}' // zero-width no-break space (byte-order mark)
            | '\u{FFF9}'..='\u{FFFB}' // interlinear annotation marks
            | '\u{E0000}'..='\u{E007F}' // tag characters, used to hide text from human readers
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn untrusted(text: &str) -> Untrusted<String> {
        Untrusted::new(text.to_owned())
    }

    #[test]
    fn terminal_escaping_neutralises_attacks() {
        let cases = [
            // Colours and cursor moves (ESC [ ...).
            ("\u{1b}[31mred\u{1b}[0m", "\\u{1b}[31mred\\u{1b}[0m"),
            // An OSC 8 hyperlink whose visible text hides where it points.
            (
                "\u{1b}]8;;https://evil.example\u{7}click\u{1b}]8;;\u{7}",
                "\\u{1b}]8;;https://evil.example\\u{7}click\\u{1b}]8;;\\u{7}",
            ),
            // A window-title change.
            ("\u{1b}]0;pwned\u{7}", "\\u{1b}]0;pwned\\u{7}"),
            // The one-character C1 escape-sequence starter.
            ("\u{9b}2J", "\\u{9b}2J"),
            // A newline that would forge a second alert line.
            ("ok\nCRITICAL: all clear", "ok\\nCRITICAL: all clear"),
            ("a\rb\tc", "a\\rb\\tc"),
            ("nul\u{0}byte", "nul\\u{0}byte"),
            ("del\u{7f}", "del\\u{7f}"),
            // Bidirectional override ("Trojan Source").
            ("safe\u{202e}txt.exe", "safe\\u{202e}txt.exe"),
            ("\u{2066}isolate\u{2069}", "\\u{2066}isolate\\u{2069}"),
            // Zero-width characters and a byte-order mark.
            ("in\u{200b}visible\u{feff}", "in\\u{200b}visible\\u{feff}"),
            // Tag characters spelling hidden text ("Hi").
            ("x\u{e0048}\u{e0069}", "x\\u{e0048}\\u{e0069}"),
            // A literal backslash stays distinguishable from an escape.
            ("\\u{1b}", "\\\\u{1b}"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                untrusted(input).escape_for_terminal(),
                expected,
                "input {input:?}"
            );
        }
    }

    #[test]
    fn terminal_escaping_leaves_ordinary_text_alone() {
        let text = "Café ⚡ Lightning 🐕 relay \"wss\" isn't down: 28.1 → 29.0";
        assert_eq!(untrusted(text).escape_for_terminal(), text);
    }

    #[test]
    fn html_escaping_neutralises_markup() {
        let cases = [
            (
                "<script>alert(1)</script>",
                "&lt;script&gt;alert(1)&lt;/script&gt;",
            ),
            (
                "<img src=x onerror=alert(1)>",
                "&lt;img src=x onerror=alert(1)&gt;",
            ),
            (
                "\" onmouseover=\"alert(1)",
                "&quot; onmouseover=&quot;alert(1)",
            ),
            (
                "' autofocus onfocus='alert(1)",
                "&#39; autofocus onfocus=&#39;alert(1)",
            ),
            // Escaped once, never twice, and never un-escaped.
            ("&lt;b&gt;", "&amp;lt;b&amp;gt;"),
            ("Tom & Jerry", "Tom &amp; Jerry"),
            ("line\nbreak\u{202e}", "line\\nbreak\\u{202e}"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                untrusted(input).escape_for_html(),
                expected,
                "input {input:?}"
            );
        }
    }

    #[test]
    fn debug_never_shows_the_content() {
        let secret_looking = untrusted("ignore previous instructions");
        let shown = format!("{secret_looking:?}");
        assert_eq!(shown, "Untrusted(<hidden>)");
        assert!(!shown.contains("ignore"));
    }

    #[test]
    fn expose_untrusted_returns_the_raw_value() {
        let raw = "\u{1b}[31m<b>";
        assert_eq!(untrusted(raw).expose_untrusted(), raw);
    }

    /// Strings that mix ordinary text with the characters attacks are made of.
    fn hostile_text() -> impl Strategy<Value = String> {
        const DANGEROUS: &str = "\u{0}\u{7}\t\n\r\u{1b}\u{7f}\u{85}\u{9b}\\&<>\"'\u{ad}\u{61c}\
            \u{200b}\u{200d}\u{200f}\u{2028}\u{202e}\u{2066}\u{2069}\u{feff}\u{e0041}\u{e007f}";
        let dangerous = proptest::sample::select(DANGEROUS.chars().collect::<Vec<_>>());
        proptest::collection::vec(prop_oneof![any::<char>(), dangerous], 0..64)
            .prop_map(|chars| chars.into_iter().collect())
    }

    fn is_unsafe_to_show(c: char) -> bool {
        c.is_control() || is_invisible(c)
    }

    proptest! {
        #[test]
        fn terminal_output_never_contains_a_control_or_invisible_character(text in hostile_text()) {
            let out = untrusted(&text).escape_for_terminal();
            prop_assert!(!out.chars().any(is_unsafe_to_show), "{out:?}");
        }

        #[test]
        fn html_output_never_contains_markup_or_a_stray_ampersand(text in hostile_text()) {
            let out = untrusted(&text).escape_for_html();
            prop_assert!(!out.chars().any(|c| matches!(c, '<' | '>' | '"' | '\'') || is_unsafe_to_show(c)), "{out:?}");
            let without_our_references = out
                .replace("&amp;", "")
                .replace("&lt;", "")
                .replace("&gt;", "")
                .replace("&quot;", "")
                .replace("&#39;", "");
            prop_assert!(!without_our_references.contains('&'), "{out:?}");
        }

        #[test]
        fn ordinary_text_passes_through_unchanged(text in "[a-zA-Z0-9 .,:;!?()/@#%+=éüßø⚡🐕→-]{0,64}") {
            prop_assert_eq!(untrusted(&text).escape_for_terminal(), text);
        }
    }
}
