//! The firewall and routing rules the sealed box really ended up with, as
//! dumped after setup, compared with the reviewed list. If they differ, the
//! capture cannot be trusted.

/// Drops comments and per-rule counters (` [n:m]`), trims trailing spaces and
/// removes empty lines, so only the rules themselves are compared.
pub fn normalize(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .map(strip_counters)
        .map(|line| line.trim_end().to_string())
        .filter(|line| !line.is_empty())
        .collect()
}

fn strip_counters(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(open) = rest.find(" [") {
        let (before, after) = rest.split_at(open);
        let inner = after.get(2..).unwrap_or("");
        match inner.find(']') {
            Some(close) if inner.get(..close).is_some_and(is_counter) => {
                out.push_str(before);
                rest = inner.get(close + 1..).unwrap_or("");
            }
            _ => {
                out.push_str(before);
                out.push_str(" [");
                rest = inner;
            }
        }
    }
    out.push_str(rest);
    out
}

fn is_counter(inner: &str) -> bool {
    inner.split_once(':').is_some_and(|(a, b)| {
        !a.is_empty() && !b.is_empty() && a.bytes().chain(b.bytes()).all(|c| c.is_ascii_digit())
    })
}

/// Whether the dumped rules equal the expected ones once normalised.
pub fn same(actual: &str, expected: &str) -> bool {
    normalize(actual) == normalize(expected)
}
