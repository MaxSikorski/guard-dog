//! The credential-shape scan that runs at compile time on every embedded
//! catalog file (`catalog_files.rs`) and again when an entry is loaded.
//!
//! Everything here is a `const fn` over bytes: no regex, no allocation, no
//! indexing, no slicing, so the compiler itself can run it. A catalog file with
//! a credential-shaped line stops the build before a binary exists, whether or
//! not anyone runs the tests. The fixed message of the build error never shows
//! file text; the line number is reported when an entry is loaded (the catalog test).
//!
//! Four scans run over the text. The *line view* is the file as written. The
//! *continuation view* joins a line ending in `\` to the next, as TOML does for a
//! multi-line string. The seed rule W2 also runs over the whole text, with
//! whitespace, newlines, `\`, quotes, brackets, braces, `:`, `,` and `;` as
//! separators. The *comment stream* is everything after the first `#` on each line, all
//! lines joined in file order, so a secret split across several comment lines
//! (with value lines or blank lines between them) is one token again. The
//! rules (T0 to T13, W1, W2) are in `catalog/README.md` and in the spec this
//! file implements; each one is linear in the length of the text.

/// Largest text this scan accepts, in bytes; a bigger text reports line 1.
pub const MAX_SCAN_BYTES: usize = 32 * 1024;

const NONE: usize = usize::MAX;

// Byte classes.
const HEX: u8 = 0;
const B64: u8 = 1;
const B58: u8 = 2;
const BECH: u8 = 3;
const TOKEN_DASH: u8 = 4; // [A-Za-z0-9_-]
const ALNUM: u8 = 5;
const ALNUM_UNDER: u8 = 6;
const UPPER_DIGIT: u8 = 7;
const MIX: u8 = 8; // [A-Za-z0-9+=_-]
const LOWER: u8 = 9;
const ALPHA: u8 = 10;
const DIGIT: u8 = 11;
const UPPER_SPACE: u8 = 12;

const fn is_word(c: u8) -> bool {
    matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_')
}

const fn in_class(c: u8, class: u8) -> bool {
    match class {
        HEX => c.is_ascii_hexdigit(),
        B64 => {
            matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'_' | b'=' | b'-')
        }
        B58 => {
            matches!(c, b'1'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'Z' | b'a'..=b'k' | b'm'..=b'z')
        }
        BECH => matches!(c, b'0' | b'2'..=b'9' | b'a' | b'c'..=b'h' | b'j'..=b'n' | b'p'..=b'z'),
        TOKEN_DASH => matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'),
        ALNUM => c.is_ascii_alphanumeric(),
        ALNUM_UNDER => is_word(c),
        UPPER_DIGIT => matches!(c, b'0'..=b'9' | b'A'..=b'Z'),
        MIX => matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'=' | b'_' | b'-'),
        LOWER => c.is_ascii_lowercase(),
        ALPHA => c.is_ascii_alphabetic(),
        DIGIT => c.is_ascii_digit(),
        UPPER_SPACE => matches!(c, b'A'..=b'Z' | b' '),
        _ => false,
    }
}

/// The byte at `i`, if there is one. Never panics, never indexes.
const fn at(b: &[u8], i: usize) -> Option<u8> {
    match b.split_at_checked(i) {
        Some((_, rest)) => match rest.first() {
            Some(x) => Some(*x),
            None => None,
        },
        None => None,
    }
}

/// Writes `v` at `i` when `i` is in range.
const fn set(buf: &mut [u8], i: usize, v: u8) {
    if let Some((_, rest)) = buf.split_at_mut_checked(i)
        && let Some(x) = rest.first_mut()
    {
        *x = v;
    }
}

/// The first `n` bytes of `b` (all of it when `n` is too big).
const fn head(b: &[u8], n: usize) -> &[u8] {
    match b.split_at_checked(n) {
        Some((h, _)) => h,
        None => b,
    }
}

const fn min(a: usize, b: usize) -> usize {
    if a < b { a } else { b }
}

/// How many bytes from `start` are in `class`, counting at most `cap`.
const fn count_class(v: &[u8], start: usize, class: u8, cap: usize) -> usize {
    let mut n = 0;
    while n < cap {
        match at(v, start + n) {
            Some(c) if in_class(c, class) => n += 1,
            _ => break,
        }
    }
    n
}

/// Does `v` hold `pat` at `i`? `fold` ignores ASCII case.
const fn starts_with(v: &[u8], i: usize, pat: &[u8], fold: bool) -> bool {
    let mut k = 0;
    while k < pat.len() {
        let (Some(a), Some(b)) = (at(v, i + k), at(pat, k)) else {
            return false;
        };
        let a = if fold { a.to_ascii_lowercase() } else { a };
        if a != b {
            return false;
        }
        k += 1;
    }
    true
}

/// Is the byte before `i` not a word byte (or is there none)?
const fn boundary_before(v: &[u8], i: usize) -> bool {
    match i.checked_sub(1) {
        None => true,
        Some(p) => match at(v, p) {
            Some(c) => !is_word(c),
            None => true,
        },
    }
}

/// Is the byte at `j` not a word byte (or is there none)?
const fn boundary_after(v: &[u8], j: usize) -> bool {
    match at(v, j) {
        Some(c) => !is_word(c),
        None => true,
    }
}

/// `prefix` at `i`, then at least `need` bytes of `class`: the index of the
/// byte that completes the minimal match, or `NONE`.
const fn prefix_run(v: &[u8], i: usize, prefix: &[u8], class: u8, need: usize) -> usize {
    if !starts_with(v, i, prefix, false) {
        return NONE;
    }
    let after = i + prefix.len();
    if count_class(v, after, class, need) == need {
        after + need - 1
    } else {
        NONE
    }
}

/// The end of the earliest-ending prefix-shaped credential that starts at `i`
/// (rules T3 to T12), or `NONE`.
const fn prefix_hit(v: &[u8], i: usize, c: u8) -> usize {
    let mut best = NONE;
    match c {
        b'A' => {
            // T3: Ag then E or F, then 30 of base64-ish.
            if starts_with(v, i, b"AgE", false) {
                best = min(best, prefix_run(v, i, b"AgE", B64, 30));
            }
            if starts_with(v, i, b"AgF", false) {
                best = min(best, prefix_run(v, i, b"AgF", B64, 30));
            }
            // T9: AKIA, exactly 16, then a boundary.
            if boundary_before(v, i)
                && starts_with(v, i, b"AKIA", false)
                && count_class(v, i + 4, UPPER_DIGIT, 16) == 16
                && boundary_after(v, i + 20)
            {
                best = min(best, i + 19);
            }
        }
        b'x' | b'y' | b'z' | b't' | b'u' | b'v' | b'X' | b'Y' | b'Z' | b'T' | b'U' | b'V' => {
            // T4: extended keys.
            let kind_ok =
                starts_with(v, i + 1, b"pub", false) || starts_with(v, i + 1, b"prv", false);
            if kind_ok && count_class(v, i + 4, B58, 20) == 20 {
                best = min(best, i + 23);
            }
        }
        b'n' => {
            // T5: nsec1.
            best = min(best, prefix_run(v, i, b"nsec1", BECH, 20));
        }
        b'-' => {
            // T6: a private key block header.
            if starts_with(v, i, b"-----BEGIN ", false) {
                let start = i + 11;
                let run = count_class(v, start, UPPER_SPACE, MAX_SCAN_BYTES);
                let mut k = 0;
                while k <= run {
                    if starts_with(v, start + k, b"PRIVATE KEY", false) {
                        best = min(best, start + k + 10);
                        break;
                    }
                    k += 1;
                }
            }
        }
        b'c' => {
            // T7: Cashu tokens.
            if boundary_before(v, i) {
                best = min(best, prefix_run(v, i, b"cashuA", TOKEN_DASH, 10));
                best = min(best, prefix_run(v, i, b"cashuB", TOKEN_DASH, 10));
            }
        }
        b'g' => {
            // T8: GitHub tokens.
            if boundary_before(v, i) {
                best = min(best, prefix_run(v, i, b"ghp_", ALNUM, 30));
                best = min(best, prefix_run(v, i, b"gho_", ALNUM, 30));
                best = min(best, prefix_run(v, i, b"ghs_", ALNUM, 30));
                best = min(best, prefix_run(v, i, b"ghu_", ALNUM, 30));
            }
            best = min(best, prefix_run(v, i, b"github_pat_", ALNUM_UNDER, 20));
        }
        b's' => {
            // T10: sk- keys.
            if boundary_before(v, i) {
                best = min(best, prefix_run(v, i, b"sk-", TOKEN_DASH, 20));
            }
        }
        b'l' => {
            // T11: Lightning invoices.
            if boundary_before(v, i) && starts_with(v, i, b"ln", false) {
                let mut k = 0;
                while k < 3 {
                    let net: &[u8] = match k {
                        0 => b"bc",
                        1 => b"tb",
                        _ => b"bcrt",
                    };
                    if starts_with(v, i + 2, net, false)
                        && count_class(v, i + 2 + net.len(), DIGIT, 1) == 1
                    {
                        best = min(best, i + 2 + net.len());
                    }
                    k += 1;
                }
            }
        }
        // T12: onion addresses, any case, then a boundary.
        b'.' if starts_with(v, i, b".onion", true) && boundary_after(v, i + 6) => {
            best = min(best, i + 5);
        }
        _ => {}
    }
    best
}

/// The end of the earliest-ending token credential (T1 or T2, T3 to T13) in
/// `v`, or `NONE`. `hexmin` is 64 on the line view and 40 on the comment stream.
const fn scan_tokens(v: &[u8], hexmin: usize) -> usize {
    let mut best = NONE;
    let mut i = 0;
    let mut hexrun = 0;
    let mut mix = 0;
    let (mut up, mut lo, mut dg) = (false, false, false);
    while i < v.len() {
        if i > best {
            break;
        }
        let Some(c) = at(v, i) else { break };
        // T1 / T2: a run of hex.
        if in_class(c, HEX) {
            hexrun += 1;
            if hexrun == hexmin {
                best = min(best, i);
            }
        } else {
            hexrun = 0;
        }
        // T13: a maximal run of 40 or more that mixes upper, lower and digits.
        if in_class(c, MIX) {
            mix += 1;
            up |= c.is_ascii_uppercase();
            lo |= c.is_ascii_lowercase();
            dg |= c.is_ascii_digit();
        } else {
            if mix >= 40 && up && lo && dg {
                best = min(best, i - 1);
            }
            mix = 0;
            (up, lo, dg) = (false, false, false);
        }
        best = min(best, prefix_hit(v, i, c));
        i += 1;
    }
    if mix >= 40 && up && lo && dg && i > 0 {
        best = min(best, i - 1);
    }
    best
}

/// W1 on the line view: 12 or more consecutive maximal word tokens, each
/// `[a-z]{3,8}`, separated by exactly one space. The end of the 12th, or `NONE`.
const fn seed_words(v: &[u8]) -> usize {
    let mut i = 0;
    let mut count = 0;
    let mut prev_end = NONE;
    while i < v.len() {
        let Some(c) = at(v, i) else { break };
        if !is_word(c) {
            i += 1;
            continue;
        }
        let s = i;
        while let Some(d) = at(v, i) {
            if !is_word(d) {
                break;
            }
            i += 1;
        }
        let len = i - s;
        let seed = len >= 3 && len <= 8 && count_class(v, s, LOWER, 9) == len;
        if seed {
            let adjacent =
                prev_end != NONE && prev_end + 1 == s && matches!(at(v, prev_end), Some(b' '));
            count = if adjacent { count + 1 } else { 1 };
            prev_end = i;
            if count >= 12 {
                return i - 1;
            }
        } else {
            count = 0;
            prev_end = NONE;
        }
    }
    NONE
}

const fn is_sep(c: u8) -> bool {
    matches!(
        c,
        b' ' | b'\t'
            | b'\n'
            | b'\r'
            | b'\\'
            | b','
            | b';'
            | b'"'
            | b'\''
            | b'['
            | b']'
            | b'{'
            | b'}'
            | b':'
            | 0
    )
}

/// W2 on a stream (JOIN is the byte 0; whitespace, newlines, `\`, quotes, brackets,
/// braces, `:`, `,` and `;` all separate tokens): 12 or more seed-like tokens
/// in a row, skipping numbering tokens. The end of the 12th, or `NONE`.
const fn seed_stream(v: &[u8]) -> usize {
    let mut i = 0;
    let mut count = 0;
    while i < v.len() {
        let Some(c) = at(v, i) else { break };
        if is_sep(c) {
            i += 1;
            continue;
        }
        let s = i;
        while let Some(d) = at(v, i) {
            if is_sep(d) {
                break;
            }
            i += 1;
        }
        let len = i - s;
        let digits = count_class(v, s, DIGIT, 2);
        let last = at(v, i - 1);
        let numbering = digits >= 1
            && (len == digits || (len == digits + 1 && matches!(last, Some(b'.' | b')'))));
        if numbering {
            continue;
        }
        if len >= 3 && len <= 8 && count_class(v, s, ALPHA, 9) == len {
            count += 1;
            if count >= 12 {
                return i - 1;
            }
        } else {
            count = 0;
        }
    }
    NONE
}

/// The continuation view: `t` with every line-ending `\` (only blanks after it,
/// then a newline) removed together with the newline and all whitespace that
/// follows, which is how TOML joins a multi-line string. Writes it to `c` and
/// returns its length, and the byte of `t` that view byte `target` came from
/// (`NONE` when `target` is out of range).
const fn build_view(t: &[u8], c: &mut [u8], target: usize) -> (usize, usize) {
    let mut i = 0;
    let mut n = 0;
    let mut orig = NONE;
    while i < t.len() {
        let Some(b) = at(t, i) else { break };
        if b == b'\\' {
            let mut k = i + 1;
            while matches!(at(t, k), Some(b' ' | b'\t' | b'\r')) {
                k += 1;
            }
            if matches!(at(t, k), Some(b'\n')) {
                k += 1;
                while matches!(at(t, k), Some(b' ' | b'\t' | b'\r' | b'\n')) {
                    k += 1;
                }
                i = k;
                continue;
            }
        }
        set(c, n, b);
        if n == target {
            orig = i;
        }
        n += 1;
        i += 1;
    }
    (n, orig)
}

/// T0: the first byte below 0x20 other than tab, newline and carriage return.
const fn control_byte(v: &[u8]) -> usize {
    let mut i = 0;
    while let Some(c) = at(v, i) {
        if c < 0x20 && c != b'\t' && c != b'\n' && c != b'\r' {
            return i;
        }
        i += 1;
    }
    NONE
}

/// 1-based line of the byte at `idx` in `t`.
const fn line_of(t: &[u8], idx: usize) -> usize {
    let mut line = 1;
    let mut i = 0;
    while i < idx {
        if matches!(at(t, i), Some(b'\n')) {
            line += 1;
        }
        i += 1;
    }
    line
}

/// The line starting at `ls`: its end (the index of `\n`, or the text's end) and,
/// when it has a `#`, the comment part `(start, end)` (leading blanks after the
/// `#` and trailing blanks and `\r` dropped).
const fn line_part(t: &[u8], ls: usize) -> (usize, Option<(usize, usize)>) {
    let mut le = ls;
    let mut hash = NONE;
    while let Some(c) = at(t, le) {
        if c == b'\n' {
            break;
        }
        if c == b'#' && hash == NONE {
            hash = le;
        }
        le += 1;
    }
    if hash == NONE {
        return (le, None);
    }
    let mut cs = hash + 1;
    while cs < le && matches!(at(t, cs), Some(b' ' | b'\t')) {
        cs += 1;
    }
    let mut ce = le;
    while ce > cs && matches!(at(t, ce - 1), Some(b' ' | b'\t' | b'\r')) {
        ce -= 1;
    }
    (le, Some((cs, ce)))
}

/// Builds the comment stream twice: `a` with a JOIN byte (0) after each comment
/// part, `b` with no JOIN at all. Returns both lengths.
const fn build_streams(t: &[u8], a: &mut [u8], b: &mut [u8]) -> (usize, usize) {
    let (mut la, mut lb) = (0, 0);
    let mut ls = 0;
    while ls < t.len() {
        let (le, part) = line_part(t, ls);
        if let Some((cs, ce)) = part {
            let mut k = cs;
            while k < ce {
                let Some(c) = at(t, k) else { break };
                set(a, la, c);
                set(b, lb, c);
                la += 1;
                lb += 1;
                k += 1;
            }
            set(a, la, 0);
            la += 1;
        }
        ls = le + 1;
    }
    (la, lb)
}

/// The line holding stream byte `idx`; `join` is 1 for the stream with JOIN
/// bytes and 0 for the one without.
const fn stream_line(t: &[u8], idx: usize, join: usize) -> usize {
    let mut line = 1;
    let mut acc = 0;
    let mut ls = 0;
    while ls < t.len() {
        let (le, part) = line_part(t, ls);
        if let Some((cs, ce)) = part {
            let len = ce - cs;
            if idx < acc + len {
                return line;
            }
            acc += len + join;
        }
        line += 1;
        ls = le + 1;
    }
    1
}

const fn earliest(best: usize, line: usize) -> usize {
    if line != 0 && (best == 0 || line < best) {
        line
    } else {
        best
    }
}

/// The 1-based line of the first credential-shaped text in `text`, or 0 when none.
/// A `const fn`, so `catalog_files.rs` runs it at compile time on every embedded file.
#[must_use]
pub const fn credential_line(text: &str) -> usize {
    let t = text.as_bytes();
    if t.len() > MAX_SCAN_BYTES {
        return 1;
    }
    let mut best = 0;
    // The line view.
    let end = min(min(control_byte(t), scan_tokens(t, 64)), seed_words(t));
    if end != NONE {
        best = earliest(best, line_of(t, end));
    }
    // The seed stream over the whole text, not only comments.
    let end = seed_stream(t);
    if end != NONE {
        best = earliest(best, line_of(t, end));
    }
    // The continuation view: a value joined by line-ending backslashes.
    let mut c = [0u8; MAX_SCAN_BYTES];
    let (lc, _) = build_view(t, &mut c, NONE);
    let end = scan_tokens(head(&c, lc), 64);
    if end != NONE {
        let (_, orig) = build_view(t, &mut c, end);
        best = earliest(best, line_of(t, if orig == NONE { 0 } else { orig }));
    }
    // The comment stream, with and without JOIN bytes.
    let mut a = [0u8; MAX_SCAN_BYTES];
    let mut b = [0u8; MAX_SCAN_BYTES];
    let (la, lb) = build_streams(t, &mut a, &mut b);
    let end = scan_tokens(head(&b, lb), 40);
    if end != NONE {
        best = earliest(best, stream_line(t, end, 0));
    }
    let end = seed_stream(head(&a, la));
    if end != NONE {
        best = earliest(best, stream_line(t, end, 1));
    }
    best
}
