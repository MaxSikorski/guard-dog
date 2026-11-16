//! Judge D: the injection corpus.
//!
//! Feeds every hostile payload in `fixtures/injection/<channel>/<family>-<NN>.txt`
//! through `Untrusted`'s two renderers and checks the result. No network, no
//! clock, no randomness: files are visited in sorted order and the summary is
//! the same on every run.
//!
//! It tests only through the public API. Checks that need code that does not
//! exist yet are counted as "not yet applicable" in the summary, never as passes.
//! The same checks also run against a naive renderer (the text returned
//! unchanged) and hand-made broken renderings, to show they have teeth.

use gd_core::Untrusted;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const CHANNELS: [&str; 10] = [
    "advisory-details",
    "banner",
    "changelog",
    "container-label",
    "git-tag",
    "issue-body",
    "nip11",
    "nostr-note",
    "release-notes",
    "repo-name",
];

/// File-name prefix and label of each payload family.
const FAMILIES: [(&str, &str); 4] = [
    ("ai", "a (AI instructions)"),
    ("terminal", "b (terminal escapes)"),
    ("html", "c (HTML and JavaScript)"),
    ("structure", "d (structure-breaking)"),
];

/// Payloads per family, numbered 01 up to this. It changes together with
/// `generate.py`, `NAIVE_PASSES` and the baseline in `tests/README.md`.
const PER_FAMILY: u32 = 12;

struct Payload {
    /// `<channel>/<file name>`.
    path: String,
    family: &'static str,
    text: String,
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/injection")
}

/// Splits `ai-07.txt` into its family label and the number 7.
fn parse_name(name: &str) -> Option<(&'static str, u32)> {
    let (prefix, number) = name.strip_suffix(".txt")?.split_once('-')?;
    let &(_, family) = FAMILIES.iter().find(|(p, _)| *p == prefix)?;
    if number.len() != 2 || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((family, number.parse().ok()?))
}

/// Loads every payload and checks the corpus is whole: exactly the ten channel
/// folders, every file named `<family>-<NN>.txt`, each family numbered 01 to
/// `PER_FAMILY` with no gap or repeat, every channel holding all four families,
/// and no empty payload. Deleting, emptying or misplacing a file fails here
/// instead of quietly shrinking the judge.
fn load_corpus() -> Vec<Payload> {
    let root = corpus_root();
    let mut folders: Vec<String> = fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", root.display()))
        .map(|entry| entry.expect("directory entry"))
        .filter(|entry| entry.file_type().expect("file type").is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    folders.sort();
    assert_eq!(
        folders, CHANNELS,
        "the channel folders in fixtures/injection"
    );

    let mut payloads = Vec::new();
    let mut numbers: BTreeMap<&str, Vec<u32>> = BTreeMap::new();
    for channel in CHANNELS {
        let dir = root.join(channel);
        let mut files: Vec<PathBuf> = fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
            .map(|entry| entry.expect("directory entry").path())
            .collect();
        files.sort();
        let mut families_here = BTreeSet::new();
        for path in files {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let (family, number) = parse_name(&name)
                .unwrap_or_else(|| panic!("{channel}/{name} is not named <family>-<NN>.txt"));
            let bytes = fs::read(&path).expect("read payload");
            let text = String::from_utf8(bytes)
                .unwrap_or_else(|_| panic!("{channel}/{name} is not valid UTF-8"));
            assert!(!text.is_empty(), "{channel}/{name} is empty");
            families_here.insert(family);
            numbers.entry(family).or_default().push(number);
            payloads.push(Payload {
                path: format!("{channel}/{name}"),
                family,
                text,
            });
        }
        assert_eq!(
            families_here.len(),
            FAMILIES.len(),
            "{channel} lacks a family"
        );
    }
    for (_, family) in FAMILIES {
        let mut found = numbers.remove(family).unwrap_or_default();
        found.sort_unstable();
        assert_eq!(
            found,
            (1..=PER_FAMILY).collect::<Vec<_>>(),
            "payload numbers of family {family}"
        );
    }
    payloads
}

const REFERENCES: [(&str, char); 5] = [
    ("&amp;", '&'),
    ("&lt;", '<'),
    ("&gt;", '>'),
    ("&quot;", '"'),
    ("&#39;", '\''),
];

/// Reads a rendering back into the original text, one character at a time,
/// with whether the renderer wrote that character as itself (`true`) or as an
/// escape (`false`). Undoes the five HTML references (when `html`), then `\\`,
/// `\n`, `\r`, `\t` and `\u{..}`. `None` when no correct renderer could have
/// written it, so nothing can be lost or made ambiguous unnoticed.
fn read_back(rendered: &str, html: bool) -> Option<Vec<(char, bool)>> {
    let mut out = Vec::new();
    let mut rest = rendered;
    while let Some(c) = rest.chars().next() {
        let (decoded, len) = if html && c == '&' {
            let (reference, text) = REFERENCES.iter().find(|(r, _)| rest.starts_with(r))?;
            (*text, reference.len())
        } else if c == '\\' {
            match rest[1..].chars().next()? {
                '\\' => ('\\', 2),
                'n' => ('\n', 2),
                'r' => ('\r', 2),
                't' => ('\t', 2),
                'u' => {
                    let body = rest.strip_prefix("\\u{")?;
                    let end = body.find('}')?;
                    let hex = &body[..end];
                    if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                        return None;
                    }
                    let code = u32::from_str_radix(hex, 16).ok()?;
                    (char::from_u32(code)?, "\\u{".len() + end + 1)
                }
                _ => return None,
            }
        } else {
            out.push((c, true));
            rest = &rest[c.len_utf8()..];
            continue;
        };
        out.push((decoded, false));
        rest = &rest[len..];
    }
    Some(out)
}

fn read_back_text(rendered: &str, html: bool) -> Option<String> {
    read_back(rendered, html).map(|chars| chars.into_iter().map(|(c, _)| c).collect())
}

/// Characters that draw nothing but can reorder, hide or smuggle text: Unicode
/// 16.0 `Default_Ignorable_Code_Point` (DerivedCoreProperties), `Cf`, `Zl` and
/// `Zp` (UnicodeData), plus the blank braille pattern U+2800. A copy of the
/// reference table `MUST_ESCAPE` in `crates/gd-core/src/untrusted.rs`, not of
/// the escaper's own `is_hidden`, so a mistake in the escaper is not repeated
/// silently here.
const INVISIBLE: &[(u32, u32)] = &[
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

fn in_table(table: &[(u32, u32)], c: char) -> bool {
    table
        .iter()
        .any(|&(first, last)| (first..=last).contains(&u32::from(c)))
}

/// Code points in the Unicode 16.0 general categories `Mn` and `Me`
/// (nonspacing and enclosing marks), which draw on top of the character before
/// them: 2,033 code points, as pairs of first and last. Generated from Python
/// 3.14's `unicodedata` (Unicode 16.0.0), independently of the escaper, which
/// relies on Rust's `char::escape_debug`.
const MARKS: &[u32] = &[
    0x0300, 0x036F, 0x0483, 0x0489, 0x0591, 0x05BD, 0x05BF, 0x05BF, 0x05C1, 0x05C2, 0x05C4, 0x05C5,
    0x05C7, 0x05C7, 0x0610, 0x061A, 0x064B, 0x065F, 0x0670, 0x0670, 0x06D6, 0x06DC, 0x06DF, 0x06E4,
    0x06E7, 0x06E8, 0x06EA, 0x06ED, 0x0711, 0x0711, 0x0730, 0x074A, 0x07A6, 0x07B0, 0x07EB, 0x07F3,
    0x07FD, 0x07FD, 0x0816, 0x0819, 0x081B, 0x0823, 0x0825, 0x0827, 0x0829, 0x082D, 0x0859, 0x085B,
    0x0897, 0x089F, 0x08CA, 0x08E1, 0x08E3, 0x0902, 0x093A, 0x093A, 0x093C, 0x093C, 0x0941, 0x0948,
    0x094D, 0x094D, 0x0951, 0x0957, 0x0962, 0x0963, 0x0981, 0x0981, 0x09BC, 0x09BC, 0x09C1, 0x09C4,
    0x09CD, 0x09CD, 0x09E2, 0x09E3, 0x09FE, 0x09FE, 0x0A01, 0x0A02, 0x0A3C, 0x0A3C, 0x0A41, 0x0A42,
    0x0A47, 0x0A48, 0x0A4B, 0x0A4D, 0x0A51, 0x0A51, 0x0A70, 0x0A71, 0x0A75, 0x0A75, 0x0A81, 0x0A82,
    0x0ABC, 0x0ABC, 0x0AC1, 0x0AC5, 0x0AC7, 0x0AC8, 0x0ACD, 0x0ACD, 0x0AE2, 0x0AE3, 0x0AFA, 0x0AFF,
    0x0B01, 0x0B01, 0x0B3C, 0x0B3C, 0x0B3F, 0x0B3F, 0x0B41, 0x0B44, 0x0B4D, 0x0B4D, 0x0B55, 0x0B56,
    0x0B62, 0x0B63, 0x0B82, 0x0B82, 0x0BC0, 0x0BC0, 0x0BCD, 0x0BCD, 0x0C00, 0x0C00, 0x0C04, 0x0C04,
    0x0C3C, 0x0C3C, 0x0C3E, 0x0C40, 0x0C46, 0x0C48, 0x0C4A, 0x0C4D, 0x0C55, 0x0C56, 0x0C62, 0x0C63,
    0x0C81, 0x0C81, 0x0CBC, 0x0CBC, 0x0CBF, 0x0CBF, 0x0CC6, 0x0CC6, 0x0CCC, 0x0CCD, 0x0CE2, 0x0CE3,
    0x0D00, 0x0D01, 0x0D3B, 0x0D3C, 0x0D41, 0x0D44, 0x0D4D, 0x0D4D, 0x0D62, 0x0D63, 0x0D81, 0x0D81,
    0x0DCA, 0x0DCA, 0x0DD2, 0x0DD4, 0x0DD6, 0x0DD6, 0x0E31, 0x0E31, 0x0E34, 0x0E3A, 0x0E47, 0x0E4E,
    0x0EB1, 0x0EB1, 0x0EB4, 0x0EBC, 0x0EC8, 0x0ECE, 0x0F18, 0x0F19, 0x0F35, 0x0F35, 0x0F37, 0x0F37,
    0x0F39, 0x0F39, 0x0F71, 0x0F7E, 0x0F80, 0x0F84, 0x0F86, 0x0F87, 0x0F8D, 0x0F97, 0x0F99, 0x0FBC,
    0x0FC6, 0x0FC6, 0x102D, 0x1030, 0x1032, 0x1037, 0x1039, 0x103A, 0x103D, 0x103E, 0x1058, 0x1059,
    0x105E, 0x1060, 0x1071, 0x1074, 0x1082, 0x1082, 0x1085, 0x1086, 0x108D, 0x108D, 0x109D, 0x109D,
    0x135D, 0x135F, 0x1712, 0x1714, 0x1732, 0x1733, 0x1752, 0x1753, 0x1772, 0x1773, 0x17B4, 0x17B5,
    0x17B7, 0x17BD, 0x17C6, 0x17C6, 0x17C9, 0x17D3, 0x17DD, 0x17DD, 0x180B, 0x180D, 0x180F, 0x180F,
    0x1885, 0x1886, 0x18A9, 0x18A9, 0x1920, 0x1922, 0x1927, 0x1928, 0x1932, 0x1932, 0x1939, 0x193B,
    0x1A17, 0x1A18, 0x1A1B, 0x1A1B, 0x1A56, 0x1A56, 0x1A58, 0x1A5E, 0x1A60, 0x1A60, 0x1A62, 0x1A62,
    0x1A65, 0x1A6C, 0x1A73, 0x1A7C, 0x1A7F, 0x1A7F, 0x1AB0, 0x1ACE, 0x1B00, 0x1B03, 0x1B34, 0x1B34,
    0x1B36, 0x1B3A, 0x1B3C, 0x1B3C, 0x1B42, 0x1B42, 0x1B6B, 0x1B73, 0x1B80, 0x1B81, 0x1BA2, 0x1BA5,
    0x1BA8, 0x1BA9, 0x1BAB, 0x1BAD, 0x1BE6, 0x1BE6, 0x1BE8, 0x1BE9, 0x1BED, 0x1BED, 0x1BEF, 0x1BF1,
    0x1C2C, 0x1C33, 0x1C36, 0x1C37, 0x1CD0, 0x1CD2, 0x1CD4, 0x1CE0, 0x1CE2, 0x1CE8, 0x1CED, 0x1CED,
    0x1CF4, 0x1CF4, 0x1CF8, 0x1CF9, 0x1DC0, 0x1DFF, 0x20D0, 0x20F0, 0x2CEF, 0x2CF1, 0x2D7F, 0x2D7F,
    0x2DE0, 0x2DFF, 0x302A, 0x302D, 0x3099, 0x309A, 0xA66F, 0xA672, 0xA674, 0xA67D, 0xA69E, 0xA69F,
    0xA6F0, 0xA6F1, 0xA802, 0xA802, 0xA806, 0xA806, 0xA80B, 0xA80B, 0xA825, 0xA826, 0xA82C, 0xA82C,
    0xA8C4, 0xA8C5, 0xA8E0, 0xA8F1, 0xA8FF, 0xA8FF, 0xA926, 0xA92D, 0xA947, 0xA951, 0xA980, 0xA982,
    0xA9B3, 0xA9B3, 0xA9B6, 0xA9B9, 0xA9BC, 0xA9BD, 0xA9E5, 0xA9E5, 0xAA29, 0xAA2E, 0xAA31, 0xAA32,
    0xAA35, 0xAA36, 0xAA43, 0xAA43, 0xAA4C, 0xAA4C, 0xAA7C, 0xAA7C, 0xAAB0, 0xAAB0, 0xAAB2, 0xAAB4,
    0xAAB7, 0xAAB8, 0xAABE, 0xAABF, 0xAAC1, 0xAAC1, 0xAAEC, 0xAAED, 0xAAF6, 0xAAF6, 0xABE5, 0xABE5,
    0xABE8, 0xABE8, 0xABED, 0xABED, 0xFB1E, 0xFB1E, 0xFE00, 0xFE0F, 0xFE20, 0xFE2F, 0x101FD,
    0x101FD, 0x102E0, 0x102E0, 0x10376, 0x1037A, 0x10A01, 0x10A03, 0x10A05, 0x10A06, 0x10A0C,
    0x10A0F, 0x10A38, 0x10A3A, 0x10A3F, 0x10A3F, 0x10AE5, 0x10AE6, 0x10D24, 0x10D27, 0x10D69,
    0x10D6D, 0x10EAB, 0x10EAC, 0x10EFC, 0x10EFF, 0x10F46, 0x10F50, 0x10F82, 0x10F85, 0x11001,
    0x11001, 0x11038, 0x11046, 0x11070, 0x11070, 0x11073, 0x11074, 0x1107F, 0x11081, 0x110B3,
    0x110B6, 0x110B9, 0x110BA, 0x110C2, 0x110C2, 0x11100, 0x11102, 0x11127, 0x1112B, 0x1112D,
    0x11134, 0x11173, 0x11173, 0x11180, 0x11181, 0x111B6, 0x111BE, 0x111C9, 0x111CC, 0x111CF,
    0x111CF, 0x1122F, 0x11231, 0x11234, 0x11234, 0x11236, 0x11237, 0x1123E, 0x1123E, 0x11241,
    0x11241, 0x112DF, 0x112DF, 0x112E3, 0x112EA, 0x11300, 0x11301, 0x1133B, 0x1133C, 0x11340,
    0x11340, 0x11366, 0x1136C, 0x11370, 0x11374, 0x113BB, 0x113C0, 0x113CE, 0x113CE, 0x113D0,
    0x113D0, 0x113D2, 0x113D2, 0x113E1, 0x113E2, 0x11438, 0x1143F, 0x11442, 0x11444, 0x11446,
    0x11446, 0x1145E, 0x1145E, 0x114B3, 0x114B8, 0x114BA, 0x114BA, 0x114BF, 0x114C0, 0x114C2,
    0x114C3, 0x115B2, 0x115B5, 0x115BC, 0x115BD, 0x115BF, 0x115C0, 0x115DC, 0x115DD, 0x11633,
    0x1163A, 0x1163D, 0x1163D, 0x1163F, 0x11640, 0x116AB, 0x116AB, 0x116AD, 0x116AD, 0x116B0,
    0x116B5, 0x116B7, 0x116B7, 0x1171D, 0x1171D, 0x1171F, 0x1171F, 0x11722, 0x11725, 0x11727,
    0x1172B, 0x1182F, 0x11837, 0x11839, 0x1183A, 0x1193B, 0x1193C, 0x1193E, 0x1193E, 0x11943,
    0x11943, 0x119D4, 0x119D7, 0x119DA, 0x119DB, 0x119E0, 0x119E0, 0x11A01, 0x11A0A, 0x11A33,
    0x11A38, 0x11A3B, 0x11A3E, 0x11A47, 0x11A47, 0x11A51, 0x11A56, 0x11A59, 0x11A5B, 0x11A8A,
    0x11A96, 0x11A98, 0x11A99, 0x11C30, 0x11C36, 0x11C38, 0x11C3D, 0x11C3F, 0x11C3F, 0x11C92,
    0x11CA7, 0x11CAA, 0x11CB0, 0x11CB2, 0x11CB3, 0x11CB5, 0x11CB6, 0x11D31, 0x11D36, 0x11D3A,
    0x11D3A, 0x11D3C, 0x11D3D, 0x11D3F, 0x11D45, 0x11D47, 0x11D47, 0x11D90, 0x11D91, 0x11D95,
    0x11D95, 0x11D97, 0x11D97, 0x11EF3, 0x11EF4, 0x11F00, 0x11F01, 0x11F36, 0x11F3A, 0x11F40,
    0x11F40, 0x11F42, 0x11F42, 0x11F5A, 0x11F5A, 0x13440, 0x13440, 0x13447, 0x13455, 0x1611E,
    0x16129, 0x1612D, 0x1612F, 0x16AF0, 0x16AF4, 0x16B30, 0x16B36, 0x16F4F, 0x16F4F, 0x16F8F,
    0x16F92, 0x16FE4, 0x16FE4, 0x1BC9D, 0x1BC9E, 0x1CF00, 0x1CF2D, 0x1CF30, 0x1CF46, 0x1D167,
    0x1D169, 0x1D17B, 0x1D182, 0x1D185, 0x1D18B, 0x1D1AA, 0x1D1AD, 0x1D242, 0x1D244, 0x1DA00,
    0x1DA36, 0x1DA3B, 0x1DA6C, 0x1DA75, 0x1DA75, 0x1DA84, 0x1DA84, 0x1DA9B, 0x1DA9F, 0x1DAA1,
    0x1DAAF, 0x1E000, 0x1E006, 0x1E008, 0x1E018, 0x1E01B, 0x1E021, 0x1E023, 0x1E024, 0x1E026,
    0x1E02A, 0x1E08F, 0x1E08F, 0x1E130, 0x1E136, 0x1E2AE, 0x1E2AE, 0x1E2EC, 0x1E2EF, 0x1E4EC,
    0x1E4EF, 0x1E5EE, 0x1E5EF, 0x1E8D0, 0x1E8D6, 0x1E944, 0x1E94A, 0xE0100, 0xE01EF,
];

fn is_mark(c: char) -> bool {
    MARKS
        .as_chunks::<2>()
        .0
        .iter()
        .any(|&[first, last]| (first..=last).contains(&u32::from(c)))
}

/// True when the rendering shows an invisible character, or starts with a
/// combining mark. One U+FE0E or U+FE0F is allowed directly after a visible
/// character that was itself written as it is (it keeps emoji looking right),
/// never after an escape such as `\u{e0100}`, whose closing `}` is the
/// renderer's, not the input's.
fn shows_invisible(rendered: &str, html: bool) -> bool {
    // A rendering that can't be read back is judged as if every character were
    // written as itself; the round-trip checks fail it anyway.
    let read =
        read_back(rendered, html).unwrap_or_else(|| rendered.chars().map(|c| (c, true)).collect());
    if read
        .first()
        .is_some_and(|&(c, as_itself)| as_itself && is_mark(c))
    {
        return true;
    }
    let mut previous: Option<(char, bool)> = None;
    for &(c, as_itself) in &read {
        if as_itself && in_table(INVISIBLE, c) {
            let selector = matches!(c, '\u{FE0E}' | '\u{FE0F}');
            let after_visible =
                previous.is_some_and(|(p, p_as_itself)| p_as_itself && !in_table(INVISIBLE, p));
            if !(selector && after_visible) {
                return true;
            }
        }
        previous = Some((c, as_itself));
    }
    false
}

const LINE_BREAKS: [char; 5] = ['\n', '\r', '\u{85}', '\u{2028}', '\u{2029}'];

const TERMINAL_CONTROL: &str = "terminal: no control character or ESC";
const TERMINAL_LINE_BREAK: &str = "terminal: no line break";
const HTML_MARKUP: &str = "html: no < > \" '";
const HTML_CONTROL: &str = "html: no control character or line break";
const BOTH_INVISIBLE: &str = "both: no invisible character or leading combining mark";
const TERMINAL_ROUND_TRIP: &str = "terminal: round-trips";
const HTML_ROUND_TRIP: &str = "html: round-trips";
const CHECKS: [&str; 7] = [
    TERMINAL_CONTROL,
    TERMINAL_LINE_BREAK,
    HTML_MARKUP,
    HTML_CONTROL,
    BOTH_INVISIBLE,
    TERMINAL_ROUND_TRIP,
    HTML_ROUND_TRIP,
];

/// Every failed check, empty when both renderings of `payload` are safe.
fn failed_checks(payload: &str, terminal: &str, html: &str) -> Vec<&'static str> {
    let mut failed = Vec::new();
    if terminal.chars().any(|c| c.is_control()) {
        failed.push(TERMINAL_CONTROL);
    }
    if terminal.contains(LINE_BREAKS) {
        failed.push(TERMINAL_LINE_BREAK);
    }
    if html.contains(['<', '>', '"', '\'']) {
        failed.push(HTML_MARKUP);
    }
    if html.chars().any(|c| c.is_control()) || html.contains(LINE_BREAKS) {
        failed.push(HTML_CONTROL);
    }
    if shows_invisible(terminal, false) || shows_invisible(html, true) {
        failed.push(BOTH_INVISIBLE);
    }
    if read_back_text(terminal, false).as_deref() != Some(payload) {
        failed.push(TERMINAL_ROUND_TRIP);
    }
    if read_back_text(html, true).as_deref() != Some(payload) {
        failed.push(HTML_ROUND_TRIP);
    }
    failed
}

fn failed_checks_for_untrusted(payload: &str) -> Vec<&'static str> {
    let untrusted = Untrusted::new(payload.to_owned());
    failed_checks(
        payload,
        &untrusted.escape_for_terminal(),
        &untrusted.escape_for_html(),
    )
}

fn is_rtl_or_bidi(c: char) -> bool {
    matches!(c, '\u{0590}'..='\u{08FF}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

#[test]
fn judge_d_injection_corpus() {
    let generator = fs::read_to_string(corpus_root().join("generate.py")).expect("generate.py");
    assert!(
        generator.is_ascii(),
        "generate.py must be plain ASCII (write hostile characters as escapes), so a reviewer sees every character it writes"
    );
    let corpus = load_corpus();

    let mut per_family: BTreeMap<&str, usize> = BTreeMap::new();
    let mut per_check_failures: BTreeMap<&str, usize> = BTreeMap::new();
    let mut family_failures: BTreeMap<&str, usize> = BTreeMap::new();
    let mut failures = Vec::new();
    // "Not yet applicable": needs code that does not exist yet.
    let mut no_action = 0; // a: no action proposed (Phase 2/8)
    let mut no_prompt = 0; // a: no untrusted bytes in a privileged prompt (Phase 6)
    let mut width = 0; // d: display-width truncation (CLI renderer)
    let mut bidi = 0; // d: bidi isolation (CLI and status-page renderers)

    for p in &corpus {
        *per_family.entry(p.family).or_default() += 1;
        let failed = failed_checks_for_untrusted(&p.text);
        for check in &failed {
            *per_check_failures.entry(check).or_default() += 1;
        }
        if !failed.is_empty() {
            *family_failures.entry(p.family).or_default() += 1;
            failures.push(format!("{} [{}]: {}", p.path, p.family, failed.join("; ")));
        }
        if p.family.starts_with('a') {
            no_action += 1;
            no_prompt += 1;
        }
        if p.family.starts_with('d') {
            if p.text.chars().count() > 200 {
                width += 1;
            }
            if p.text.chars().any(is_rtl_or_bidi) {
                bidi += 1;
            }
        }
    }

    println!("JUDGE D BASELINE");
    println!("payloads: {}", corpus.len());
    for (family, count) in &per_family {
        println!(
            "  family {family}: {count} payloads, {} failing",
            family_failures.get(family).unwrap_or(&0)
        );
    }
    for check in CHECKS {
        let failing = per_check_failures.get(check).unwrap_or(&0);
        println!(
            "  check {check}: {} pass, {failing} fail",
            corpus.len() - failing
        );
    }
    println!("not yet applicable:");
    println!("  a, no action proposed (Phase 2/8): {no_action}");
    println!("  a, no untrusted bytes in a privileged prompt (Phase 6): {no_prompt}");
    println!("  d, display-width truncation (CLI renderer): {width}");
    println!("  d, bidi isolation (CLI and status-page renderers): {bidi}");

    assert!(
        failures.is_empty(),
        "{} payloads failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The payloads a naive renderer (the text returned unchanged) still gets past
/// every check, in corpus order: family a's plain-text instructions, family c's
/// Markdown link (it holds no HTML-special character), and family d's 100,000
/// letters, Hebrew beside version numbers, and 200 spaces of padding. They wait
/// for the checks that need later code. Every other payload must fail.
const NAIVE_PASSES: [&str; 12] = [
    "advisory-details/ai-08.txt",
    "advisory-details/structure-08.txt",
    "banner/ai-06.txt",
    "git-tag/ai-10.txt",
    "issue-body/ai-03.txt",
    "issue-body/structure-03.txt",
    "nip11/ai-04.txt",
    "nip11/html-04.txt",
    "nostr-note/ai-07.txt",
    "release-notes/ai-02.txt",
    "repo-name/ai-09.txt",
    "repo-name/structure-09.txt",
];

#[test]
fn a_naive_renderer_fails_the_judge() {
    let corpus = load_corpus();
    let mut passes = Vec::new();
    let mut failing: BTreeMap<&str, usize> = BTreeMap::new();
    for p in &corpus {
        if failed_checks(&p.text, &p.text, &p.text).is_empty() {
            passes.push(p.path.as_str());
        } else {
            *failing.entry(p.family).or_default() += 1;
        }
    }
    println!("JUDGE D NAIVE RENDERER (text returned unchanged)");
    println!(
        "payloads: {}, failing: {}",
        corpus.len(),
        corpus.len() - passes.len()
    );
    for (family, count) in &failing {
        println!("  family {family}: {count} failing");
    }
    assert_eq!(passes, NAIVE_PASSES, "payloads a naive renderer gets past");
    for (_, family) in FAMILIES {
        assert!(
            failing.contains_key(family),
            "no payload in family {family} fails a naive renderer"
        );
    }
}

/// Broken renderings that still read back to their input, so only the
/// invisible-character check stands between them and a pass.
#[test]
fn the_checks_catch_subtle_mistakes() {
    // A leading Hebrew point (U+05B0), outside the main combining blocks, left as it is.
    let text = "\u{5b0}OK";
    assert_eq!(failed_checks(text, text, text), [BOTH_INVISIBLE]);

    // A presentation selector left raw after an escaped variation selector: it
    // would sit after the escape's `}` instead of after a visible character.
    let text = "x\u{e0100}\u{fe0f}";
    let untrusted = Untrusted::new(text.to_owned());
    let terminal = untrusted.escape_for_terminal();
    let broken = terminal.replacen("\\u{fe0f}", "\u{fe0f}", 1);
    assert_ne!(broken, terminal);
    assert_eq!(
        failed_checks(text, &broken, &untrusted.escape_for_html()),
        [BOTH_INVISIBLE]
    );
}

#[test]
fn every_leading_mark_is_escaped() {
    let (pairs, leftover) = MARKS.as_chunks::<2>();
    assert!(leftover.is_empty(), "MARKS must hold whole pairs");
    let mut count = 0;
    for &[first, last] in pairs {
        assert!(first <= last, "MARKS pair {first:X}..{last:X}");
        for c in (first..=last).filter_map(char::from_u32) {
            count += 1;
            let untrusted = Untrusted::new(format!("{c}x"));
            for rendering in [untrusted.escape_for_terminal(), untrusted.escape_for_html()] {
                assert!(
                    rendering.starts_with("\\u{"),
                    "U+{:04X} at the start is not escaped",
                    u32::from(c)
                );
            }
        }
    }
    assert_eq!(count, 2033, "MARKS holds every Unicode 16.0 Mn and Me");
}
