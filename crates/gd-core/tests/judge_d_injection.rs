//! Judge D: the injection corpus.
//!
//! Feeds every hostile payload in `fixtures/injection/<channel>/<family>-<NN>.txt`
//! through `Untrusted`'s two renderers and checks the result. No network, no
//! clock, no randomness: files are visited in sorted order and the summary is
//! the same on every run.
//!
//! It tests only through the public API. Checks that need code that does not
//! exist yet are counted as "not yet applicable" in the summary, never as passes.

use gd_core::Untrusted;
use std::collections::BTreeMap;
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

fn family_of(file_name: &str) -> &'static str {
    match file_name.split('-').next() {
        Some("ai") => "a (AI instructions)",
        Some("terminal") => "b (terminal escapes)",
        Some("html") => "c (HTML and JavaScript)",
        Some("structure") => "d (structure-breaking)",
        _ => panic!("payload {file_name} does not start with a known family"),
    }
}

struct Payload {
    channel: String,
    name: String,
    family: &'static str,
    text: String,
}

fn load_corpus() -> Vec<Payload> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/injection");
    let mut payloads = Vec::new();
    for channel in CHANNELS {
        let dir = root.join(channel);
        let mut files: Vec<PathBuf> = fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
            .map(|entry| entry.expect("directory entry").path())
            .collect();
        files.sort();
        for path in files {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let bytes = fs::read(&path).expect("read payload");
            let text = String::from_utf8(bytes)
                .unwrap_or_else(|_| panic!("{channel}/{name} is not valid UTF-8"));
            payloads.push(Payload {
                channel: channel.to_owned(),
                family: family_of(&name),
                name,
                text,
            });
        }
    }
    payloads
}

/// Undoes both renderers: the five HTML references, then `\\`, `\n`, `\r`,
/// `\t` and `\u{..}`. Used to prove nothing was lost or made ambiguous.
fn unescape(rendered: &str, html: bool) -> Option<String> {
    let mut out = String::new();
    let mut rest = rendered;
    while let Some(c) = rest.chars().next() {
        if html && c == '&' {
            let (text, len) = [
                ("&amp;", "&"),
                ("&lt;", "<"),
                ("&gt;", ">"),
                ("&quot;", "\""),
                ("&#39;", "'"),
            ]
            .iter()
            .find(|(reference, _)| rest.starts_with(reference))
            .map(|(reference, text)| (*text, reference.len()))?;
            out.push_str(text);
            rest = &rest[len..];
        } else if c == '\\' {
            let after = &rest[1..];
            let next = after.chars().next()?;
            match next {
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let body = after.strip_prefix("u{")?;
                    let end = body.find('}')?;
                    let code = u32::from_str_radix(&body[..end], 16).ok()?;
                    out.push(char::from_u32(code)?);
                    rest = &body[end + 1..];
                    continue;
                }
                _ => return None,
            }
            rest = &after[next.len_utf8()..];
        } else {
            out.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    Some(out)
}

/// Characters that draw nothing but can reorder, hide or smuggle text: Unicode
/// 16.0 `Default_Ignorable_Code_Point` (DerivedCoreProperties), `Cf`, `Zl` and
/// `Zp` (UnicodeData), plus the blank braille pattern U+2800. Copied as data
/// from `MUST_ESCAPE` in `crates/gd-core/src/untrusted.rs`, so a mistake there
/// is not repeated silently here.
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

/// Main combining-mark blocks, for the "does not start with a combining mark" check.
const COMBINING: &[(u32, u32)] = &[
    (0x0300, 0x036F),
    (0x1AB0, 0x1AFF),
    (0x1DC0, 0x1DFF),
    (0x20D0, 0x20FF),
    (0xFE20, 0xFE2F),
];

fn in_table(table: &[(u32, u32)], c: char) -> bool {
    table
        .iter()
        .any(|&(first, last)| (first..=last).contains(&u32::from(c)))
}

/// True when the rendering shows an invisible character, or starts with a
/// combining mark. One U+FE0E or U+FE0F directly after a visible character is
/// allowed (it keeps emoji looking right).
fn shows_invisible(rendered: &str) -> bool {
    if rendered
        .chars()
        .next()
        .is_some_and(|c| in_table(COMBINING, c))
    {
        return true;
    }
    let mut previous: Option<char> = None;
    for c in rendered.chars() {
        if in_table(INVISIBLE, c) {
            let selector = matches!(c, '\u{FE0E}' | '\u{FE0F}');
            if !(selector && previous.is_some_and(|p| !in_table(INVISIBLE, p))) {
                return true;
            }
        }
        previous = Some(c);
    }
    false
}

const LINE_BREAKS: [char; 5] = ['\n', '\r', '\u{85}', '\u{2028}', '\u{2029}'];

/// Every failed check as "check name", empty when the rendering is safe.
fn failed_checks(
    payload: &str,
    render_terminal: &dyn Fn(&Untrusted<String>) -> String,
    render_html: &dyn Fn(&Untrusted<String>) -> String,
) -> Vec<&'static str> {
    let untrusted = Untrusted::new(payload.to_owned());
    let terminal = render_terminal(&untrusted);
    let html = render_html(&untrusted);
    let mut failed = Vec::new();
    if terminal.chars().any(|c| c.is_control()) {
        failed.push("terminal: no control character or ESC");
    }
    if terminal.contains(LINE_BREAKS) {
        failed.push("terminal: no line break");
    }
    if html.contains(['<', '>', '"', '\'']) {
        failed.push("html: no < > \" '");
    }
    if html.chars().any(|c| c.is_control()) || html.contains(LINE_BREAKS) {
        failed.push("html: no control character or line break");
    }
    if shows_invisible(&terminal) || shows_invisible(&html) {
        failed.push("both: no invisible character or leading combining mark");
    }
    if unescape(&terminal, false).as_deref() != Some(payload) {
        failed.push("terminal: round-trips");
    }
    if unescape(&html, true).as_deref() != Some(payload) {
        failed.push("html: round-trips");
    }
    failed
}

fn is_rtl_or_bidi(c: char) -> bool {
    matches!(c, '\u{0590}'..='\u{08FF}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

#[test]
fn judge_d_injection_corpus() {
    let corpus = load_corpus();
    assert!(
        corpus.len() >= 40,
        "the corpus has {} payloads, expected at least 40",
        corpus.len()
    );

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
        let failed = failed_checks(&p.text, &|u| u.escape_for_terminal(), &|u| {
            u.escape_for_html()
        });
        for check in &failed {
            *per_check_failures.entry(check).or_default() += 1;
        }
        if !failed.is_empty() {
            *family_failures.entry(p.family).or_default() += 1;
            failures.push(format!(
                "{}/{} [{}]: {}",
                p.channel,
                p.name,
                p.family,
                failed.join("; ")
            ));
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
    let checks = [
        "terminal: no control character or ESC",
        "terminal: no line break",
        "html: no < > \" '",
        "html: no control character or line break",
        "both: no invisible character or leading combining mark",
        "terminal: round-trips",
        "html: round-trips",
    ];
    for check in checks {
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
