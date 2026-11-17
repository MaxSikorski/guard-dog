use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A value that came from outside Guard Dog: a changelog, an issue, a relay's
/// NIP-11 document, a container label, a service banner, a Nostr note,
/// advisory text, a file name on the node.
///
/// Any of it may carry instructions aimed at an AI, escape codes aimed at a
/// terminal, or HTML aimed at the status page. So this type has no `Display`,
/// no `Deref`, no `AsRef`, no `Borrow`, no `==`, no conversion back and no
/// public field: the compiler refuses to print it, compare it or hand it on as
/// plain text. The only ways out (four, all greppable):
///
/// - [`escape_for_terminal`](Untrusted::escape_for_terminal), to show it in a terminal;
/// - [`escape_for_html`](Untrusted::escape_for_html), to show it in a web page;
/// - [`expose_untrusted`](Untrusted::expose_untrusted), which hands back the raw
///   value. Each call is a place where outside text meets code, so each one
///   needs a reviewer's OK in the pull request. Search for `expose_untrusted`
///   to find them all;
/// - the `Serialize` impl below, which writes it as `{"untrusted": "<raw>"}`
///   for the store and JSON output. That is the raw text, unescaped, in a
///   wrapper that marks it; a new caller of `serde_json::to_*` on facts outside
///   `gd-store` and the JSON output needs a reviewer's OK too.
///
/// JSON meant for people or pages must go through [`crate::to_ascii_json`]: plain
/// `serde_json` leaves C1 controls, bidi overrides and `</script>` raw.
///
/// `Debug` never shows the content, so a struct holding untrusted text can
/// still derive `Debug` without leaking that text into logs. `Clone` runs the
/// wrapped type's own `clone`, which is trusted code: wrap plain data types
/// such as `String`, never a type with side effects.
#[derive(Clone)]
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
    /// How many bytes the text has. A size check that never shows the text.
    pub fn byte_len(&self) -> usize {
        self.0.as_ref().len()
    }

    /// The text in a form that is safe to print in a UTF-8 terminal.
    ///
    /// These are written out visibly, as `\n`, `\r`, `\t` or `\u{..}`:
    ///
    /// - every control character: escape codes for colours, cursor moves,
    ///   OSC 8 hyperlinks and window titles; the bell; newlines and tabs;
    /// - every character that draws nothing but can reorder, hide or smuggle
    ///   text: bidirectional controls, zero-width characters, Unicode "tag"
    ///   characters, variation selectors (one directly after a visible
    ///   character is kept, so emoji still look right), and the rest of
    ///   Unicode's default-ignorable and format characters;
    /// - a combining mark at the very start, which would otherwise join onto
    ///   whatever Guard Dog printed just before it.
    ///
    /// A backslash becomes `\\`, so the result is never ambiguous. Ordinary
    /// text, accents, right-to-left scripts and most emoji pass through
    /// unchanged; emoji built with zero-width joiners show their joiners.
    ///
    /// What the code that prints the result still owns:
    ///
    /// - **Right-to-left text** (Hebrew, Arabic, Persian) is kept, but in a
    ///   terminal that lays out bidirectional text it can reorder Guard Dog's
    ///   own words and version numbers printed beside it. Print each value
    ///   isolated, between U+2068 and U+2069.
    /// - **Width.** The result has no line breaks, but a long value still wraps
    ///   onto the next screen line. Truncate it to the space available. Size
    ///   limits on the input belong where the text is read.
    /// - **Look-alikes.** Letters from other scripts that look like Latin ones,
    ///   and stacks of combining marks, pass through.
    pub fn escape_for_terminal(&self) -> String {
        escape(self.0.as_ref(), Context::Terminal)
    }

    /// The text in a form that is safe as the text of an HTML element, or as
    /// the quoted value of a plain-text attribute such as `title`, `alt`,
    /// `value` or `data-*`.
    ///
    /// `&`, `<`, `>`, `"` and `'` become character references, and control and
    /// invisible characters are made visible exactly as in
    /// [`escape_for_terminal`](Untrusted::escape_for_terminal).
    ///
    /// It is **not** safe in an event-handler attribute (`onclick` and the
    /// rest), `style`, `srcdoc`, a URL (`href`, `src`, `action`), inside
    /// `<script>` or `<style>`, or in an unquoted attribute: there the browser
    /// decodes the references and then runs or parses the value. Untrusted text
    /// never goes there. Put each value in its own `<bdi>` element, so
    /// right-to-left text can't reorder the page's own text around it.
    pub fn escape_for_html(&self) -> String {
        escape(self.0.as_ref(), Context::Html)
    }
}

/// How untrusted text appears in JSON: always `{"untrusted": "<raw>"}`, never a
/// bare string, so every JSON reader (the store, `--json`, a web API) can see
/// it is untrusted. This is the second way out of the type after
/// [`Untrusted::expose_untrusted`]: a new caller of `serde_json::to_*` on facts
/// outside `gd-store` and the JSON output needs a reviewer's OK.
#[derive(Serialize)]
struct WireRef<'a, T> {
    untrusted: &'a T,
}

impl<T: Serialize> Serialize for Untrusted<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        WireRef { untrusted: &self.0 }.serialize(serializer)
    }
}

/// Reads only a map with exactly one key, `untrusted` (not a list, not a bare value).
struct WireVisitor<T>(std::marker::PhantomData<T>);

impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for WireVisitor<T> {
    type Value = Untrusted<T>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object {\"untrusted\": ...}")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut found = None;
        while let Some(key) = map.next_key::<String>()? {
            if key != "untrusted" || found.is_some() {
                return Err(serde::de::Error::custom("unexpected key"));
            }
            found = Some(map.next_value::<T>()?);
        }
        found
            .map(Untrusted)
            .ok_or_else(|| serde::de::Error::missing_field("untrusted"))
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Untrusted<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(WireVisitor(std::marker::PhantomData))
    }
}

impl<T> fmt::Debug for Untrusted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Untrusted(<hidden>)")
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Context {
    Terminal,
    Html,
}

/// Writes `text`, replacing every character that could steer a terminal, hide
/// text or join onto Guard Dog's own text with a visible stand-in made only of
/// ASCII letters, digits, `\`, `{` and `}`. In HTML it also replaces the five
/// HTML-special characters with character references.
fn escape(text: &str, context: Context) -> String {
    let html = context == Context::Html;
    let mut out = String::with_capacity(text.len());
    // The previous character, when it was written unchanged.
    let mut previous_kept: Option<char> = None;
    for (position, c) in text.chars().enumerate() {
        let mut kept = false;
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '&' if html => out.push_str("&amp;"),
            '<' if html => out.push_str("&lt;"),
            '>' if html => out.push_str("&gt;"),
            '"' if html => out.push_str("&quot;"),
            '\'' if html => out.push_str("&#39;"),
            // One emoji (or text) presentation selector right after a visible
            // character, as in "❤️". A second one in a row is escaped.
            '\u{FE0E}' | '\u{FE0F}'
                if previous_kept.is_some_and(|p| !matches!(p, '\u{FE0E}' | '\u{FE0F}')) =>
            {
                out.push(c);
                kept = true;
            }
            c if c.is_control() || is_hidden(c) => out.extend(c.escape_unicode()),
            c if position == 0 && joins_previous(c) => out.extend(c.escape_unicode()),
            c => {
                out.push(c);
                kept = true;
            }
        }
        previous_kept = kept.then_some(c);
    }
    out
}

/// Characters that draw nothing (or only a blank) but can reorder, hide or
/// smuggle text: Unicode 16's `Default_Ignorable_Code_Point` and format (`Cf`)
/// characters, the line and paragraph separators, and the blank braille
/// pattern. It is a fixed list, so a reviewer can read exactly what it covers.
/// Control characters (C0, DEL and C1, including the one-character escape
/// starter U+009B and NEL U+0085) are caught separately by `char::is_control`.
fn is_hidden(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}' // soft hyphen
            | '\u{034F}' // combining grapheme joiner
            | '\u{0600}'..='\u{0605}' // Arabic number signs (format)
            | '\u{061C}' // Arabic letter mark (bidirectional)
            | '\u{06DD}' | '\u{070F}' | '\u{0890}'..='\u{0891}' | '\u{08E2}' // Arabic and Syriac format marks
            | '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}' // Hangul fillers, which draw as blanks
            | '\u{17B4}' | '\u{17B5}' // Khmer inherent vowels
            | '\u{180B}'..='\u{180F}' // Mongolian variation selectors and vowel separator
            | '\u{200B}'..='\u{200F}' // zero-width space, non-joiner, joiner; left-to-right and right-to-left marks
            | '\u{2028}'..='\u{202E}' // line and paragraph separators; bidirectional embeddings and overrides
            | '\u{2060}'..='\u{206F}' // word joiner, invisible operators, bidirectional isolates
            | '\u{2800}' // blank braille pattern
            | '\u{FE00}'..='\u{FE0F}' // variation selectors
            | '\u{FEFF}' // zero-width no-break space (byte-order mark)
            | '\u{FFF0}'..='\u{FFFB}' // unassigned specials; interlinear annotation marks
            | '\u{110BD}' | '\u{110CD}' // Kaithi number signs (format)
            | '\u{13430}'..='\u{1343F}' // Egyptian hieroglyph format controls
            | '\u{1BCA0}'..='\u{1BCA3}' // shorthand format controls
            | '\u{1D173}'..='\u{1D17A}' // musical symbol format controls
            | '\u{E0000}'..='\u{E0FFF}' // tag characters; variation selectors supplement
    )
}

/// Combining marks and other characters that join onto the character before
/// them; at the start of a value, that character is Guard Dog's own text.
/// Rust's own `char::escape_debug` escapes exactly these (along with characters
/// handled before this check, and the quote marks, which are excluded here).
fn joins_previous(c: char) -> bool {
    !matches!(c, '"' | '\'') && c.escape_debug().len() > 1
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
            // The one-character C1 escape-sequence starter, and NEL.
            ("\u{9b}2J\u{85}", "\\u{9b}2J\\u{85}"),
            // A newline that would forge a second alert line.
            ("ok\nCRITICAL: all clear", "ok\\nCRITICAL: all clear"),
            ("a\rb\tc", "a\\rb\\tc"),
            ("nul\u{0}byte", "nul\\u{0}byte"),
            ("del\u{7f}", "del\\u{7f}"),
            // Bidirectional override ("Trojan Source") and isolates.
            ("safe\u{202e}txt.exe", "safe\\u{202e}txt.exe"),
            ("\u{2066}isolate\u{2069}", "\\u{2066}isolate\\u{2069}"),
            // Zero-width characters and a byte-order mark.
            ("in\u{200b}visible\u{feff}", "in\\u{200b}visible\\u{feff}"),
            // Tag characters spelling hidden text ("Hi").
            ("x\u{e0048}\u{e0069}", "x\\u{e0048}\\u{e0069}"),
            // Variation selectors smuggling bytes after a visible character.
            ("OK\u{e0100}\u{e0101}", "OK\\u{e0100}\\u{e0101}"),
            ("🐕\u{fe00}\u{fe01}", "🐕\\u{fe00}\\u{fe01}"),
            ("❤\u{fe0f}\u{fe0f}", "❤\u{fe0f}\\u{fe0f}"),
            ("\u{fe0f}start", "\\u{fe0f}start"),
            // Blanks that look like nothing at all.
            ("\u{2800}\u{3164}", "\\u{2800}\\u{3164}"),
            ("a\u{1d173}b\u{180b}c", "a\\u{1d173}b\\u{180b}c"),
            // A combining slash at the start would turn Guard Dog's "=" into "≠".
            ("\u{338}OK", "\\u{338}OK"),
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
        let texts = [
            "Café ⚡ Lightning 🐕 relay \"wss\" isn't down: 28.1 → 29.0",
            "❤\u{fe0f} emoji with its presentation selector",
            "e\u{301} (a combining accent after its letter)",
            "שלום עולם and مرحبا (right-to-left scripts)",
        ];
        for text in texts {
            assert_eq!(untrusted(text).escape_for_terminal(), text);
        }
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

    /// The characters that must never be shown as they are, written out here
    /// independently of `is_hidden` from Unicode 16.0's DerivedCoreProperties
    /// (`Default_Ignorable_Code_Point`) and UnicodeData (`Cf`, `Zl`, `Zp`),
    /// plus the blank braille pattern. If the two lists ever disagree, the
    /// test below fails.
    const MUST_ESCAPE: &[(u32, u32)] = &[
        (0x00AD, 0x00AD),
        (0x034F, 0x034F),
        (0x0600, 0x0605),
        (0x061C, 0x061C),
        (0x06DD, 0x06DD),
        (0x070F, 0x070F),
        (0x0890, 0x0891),
        (0x08E2, 0x08E2),
        (0x115F, 0x1160),
        (0x17B4, 0x17B5),
        (0x180B, 0x180F),
        (0x200B, 0x200F),
        (0x2028, 0x202E),
        (0x2060, 0x206F),
        (0x2800, 0x2800),
        (0x3164, 0x3164),
        (0xFE00, 0xFE0F),
        (0xFEFF, 0xFEFF),
        (0xFFA0, 0xFFA0),
        (0xFFF0, 0xFFFB),
        (0x110BD, 0x110BD),
        (0x110CD, 0x110CD),
        (0x13430, 0x1343F),
        (0x1BCA0, 0x1BCA3),
        (0x1D173, 0x1D17A),
        (0xE0000, 0xE0FFF),
    ];

    #[test]
    fn exactly_the_listed_characters_are_escaped_after_a_letter() {
        for c in (0..=u32::from(char::MAX)).filter_map(char::from_u32) {
            let listed = MUST_ESCAPE
                .iter()
                .any(|&(first, last)| (first..=last).contains(&u32::from(c)));
            let emoji_selector = matches!(c, '\u{FE0E}' | '\u{FE0F}');
            let expected = c == '\\' || c.is_control() || (listed && !emoji_selector);
            let input = format!("a{c}");
            let escaped = untrusted(&input).escape_for_terminal() != input;
            assert_eq!(escaped, expected, "U+{:04X}", u32::from(c));
        }
    }

    /// Reverses `escape_for_terminal`, to prove nothing is lost or ambiguous.
    fn unescape_terminal(escaped: &str) -> String {
        let mut out = String::new();
        let mut chars = escaped.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next() {
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('u') => {
                    assert_eq!(chars.next(), Some('{'), "in {escaped:?}");
                    let hex: String = chars.by_ref().take_while(|&h| h != '}').collect();
                    let code = u32::from_str_radix(&hex, 16).expect("hex");
                    out.push(char::from_u32(code).expect("a character"));
                }
                other => panic!("unexpected escape {other:?} in {escaped:?}"),
            }
        }
        out
    }

    /// Reverses `escape_for_html`'s character references; `None` when an `&`
    /// starts anything other than one of the five references it writes.
    fn unescape_html(escaped: &str) -> Option<String> {
        const REFERENCES: [(&str, char); 5] = [
            ("&amp;", '&'),
            ("&lt;", '<'),
            ("&gt;", '>'),
            ("&quot;", '"'),
            ("&#39;", '\''),
        ];
        let mut out = String::new();
        let mut rest = escaped;
        while let Some(at) = rest.find('&') {
            out.push_str(&rest[..at]);
            rest = &rest[at..];
            let (reference, c) = REFERENCES
                .iter()
                .find(|(reference, _)| rest.starts_with(reference))?;
            out.push(*c);
            rest = &rest[reference.len()..];
        }
        out.push_str(rest);
        Some(out)
    }

    /// Strings that mix ordinary text with the characters attacks are made of.
    fn hostile_text() -> impl Strategy<Value = String> {
        const DANGEROUS: &str = "\u{0}\u{7}\t\n\r\u{1b}\u{7f}\u{85}\u{9b}\\&<>\"'\u{ad}\u{61c}\
            \u{200b}\u{200d}\u{200f}\u{2028}\u{202e}\u{2066}\u{2069}\u{2800}\u{feff}\u{fe0f}\
            \u{e0041}\u{e007f}\u{e0100}\u{338}\u{301}\u{1d173}";
        let dangerous = proptest::sample::select(DANGEROUS.chars().collect::<Vec<_>>());
        proptest::collection::vec(prop_oneof![any::<char>(), dangerous], 0..64)
            .prop_map(|chars| chars.into_iter().collect())
    }

    fn must_not_appear(c: char) -> bool {
        c.is_control() || is_hidden(c) && !matches!(c, '\u{FE0E}' | '\u{FE0F}')
    }

    /// The seed every property test uses unless `GD_PROPTEST_SEED` says otherwise.
    const DEFAULT_PROPTEST_SEED: u64 = 0x6764_5f70_726f_7074;

    /// Property tests run on a fixed seed, so the same commit gives the same result.
    /// `GD_PROPTEST_SEED=<number>` explores a different one (meant for nightly runs).
    /// Failing cases are saved under `crates/gd-core/proptest-regressions/`.
    fn proptest_config() -> ProptestConfig {
        static ANNOUNCE: std::sync::Once = std::sync::Once::new();
        let seed = std::env::var("GD_PROPTEST_SEED")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_PROPTEST_SEED);
        ANNOUNCE.call_once(|| eprintln!("GD_PROPTEST_SEED={seed} (property test seed in use)"));
        ProptestConfig {
            rng_seed: proptest::test_runner::RngSeed::Fixed(seed),
            ..ProptestConfig::default()
        }
    }

    proptest! {
        #![proptest_config(proptest_config())]

        #[test]
        fn terminal_output_is_safe_and_reversible(text in hostile_text()) {
            let out = untrusted(&text).escape_for_terminal();
            prop_assert!(!out.chars().any(must_not_appear), "{out:?}");
            prop_assert_eq!(unescape_terminal(&out), text);
        }

        #[test]
        fn html_output_is_safe_and_reversible(text in hostile_text()) {
            let out = untrusted(&text).escape_for_html();
            prop_assert!(!out.chars().any(|c| matches!(c, '<' | '>' | '"' | '\'') || must_not_appear(c)), "{out:?}");
            let references_undone = unescape_html(&out);
            prop_assert!(references_undone.is_some(), "stray & in {out:?}");
            prop_assert_eq!(unescape_terminal(&references_undone.unwrap_or_default()), text);
        }

        #[test]
        fn ordinary_text_passes_through_unchanged(text in "[a-zA-Z0-9 .,:;!?()/@#%+=éüßø⚡🐕→-]{0,64}") {
            prop_assert_eq!(untrusted(&text).escape_for_terminal(), text);
        }
    }
}
