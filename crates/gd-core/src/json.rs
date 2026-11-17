//! JSON for people and for pages.
//!
//! `serde_json` escapes only `"`, `\` and characters below U+0020, so a plain
//! `to_string` of untrusted text still carries raw C1 controls (an 8-bit CSI),
//! bidirectional overrides, U+2028 and `</script>`. JSON that a person might
//! read in a terminal, or that a page might inline, must come from
//! [`to_ascii_json`] instead: every character outside printable ASCII, and
//! `<`, `>` and `&`, is written as `\uXXXX`. The result is plain ASCII with the
//! same meaning to any JSON reader. The store may keep plain `serde_json`
//! output, because nothing displays it.

use std::io;

use serde::Serialize;
use serde_json::ser::{Formatter, Serializer};

struct AsciiFormatter;

impl Formatter for AsciiFormatter {
    fn write_string_fragment<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()> {
        let mut units = [0u16; 2];
        for c in fragment.chars() {
            if (' '..='~').contains(&c) && !matches!(c, '<' | '>' | '&') {
                writer.write_all(&[c as u8])?;
            } else {
                for unit in c.encode_utf16(&mut units) {
                    write!(writer, "\\u{unit:04x}")?;
                }
            }
        }
        Ok(())
    }
}

/// `value` as JSON that is pure ASCII and contains no `<`, `>` or `&`.
pub fn to_ascii_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let mut out = Vec::new();
    let mut serializer = Serializer::with_formatter(&mut out, AsciiFormatter);
    value.serialize(&mut serializer)?;
    // Only ASCII was written, so this cannot fail; if it ever did, say so.
    String::from_utf8(out).map_err(serde::ser::Error::custom)
}
