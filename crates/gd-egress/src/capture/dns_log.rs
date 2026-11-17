//! The resolver log. CoreDNS writes one `[INFO] GDQ {type} {class} {name} {proto} {rcode}`
//! line per query; everything else is ignored unless it is an error.

use std::collections::BTreeSet;

/// One logged query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// Query type, for example `A`.
    pub qtype: String,
    /// The name, decoded, lowercase, without the trailing dot.
    pub name: String,
}

/// The parsed log.
#[derive(Debug, Clone, Default)]
pub struct DnsLog {
    /// Every `GDQ` line.
    pub records: Vec<DnsRecord>,
    /// Problem codes found (`bad-line`).
    pub errors: BTreeSet<&'static str>,
}

/// Decodes the `\DDD` (decimal) and `\X` escapes CoreDNS uses in names.
fn decode_name(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&c) = bytes.get(i) {
        if c != b'\\' {
            out.push(c);
            i += 1;
            continue;
        }
        let digits: Vec<u8> = bytes.iter().skip(i + 1).take(3).copied().collect();
        let value = (digits.len() == 3 && digits.iter().all(u8::is_ascii_digit))
            .then(|| {
                digits
                    .iter()
                    .fold(0u32, |acc, d| acc * 10 + u32::from(d - b'0'))
            })
            .and_then(|v| u8::try_from(v).ok());
        match (value, bytes.get(i + 1)) {
            (Some(v), _) => {
                out.push(v);
                i += 4;
            }
            (None, Some(&next)) => {
                out.push(next);
                i += 2;
            }
            (None, None) => i += 1,
        }
    }
    let name = String::from_utf8_lossy(&out).to_ascii_lowercase();
    name.strip_suffix('.').unwrap_or(&name).to_string()
}

/// Parses a resolver log.
pub fn parse(bytes: &[u8]) -> DnsLog {
    let text = String::from_utf8_lossy(bytes);
    let mut log = DnsLog::default();
    for line in text.lines() {
        if line.starts_with("[ERROR]") || line.starts_with("[FATAL]") {
            log.errors.insert("bad-line");
        } else if let Some(rest) = line.strip_prefix("[INFO] GDQ ") {
            let fields: Vec<&str> = rest.split(' ').collect();
            match fields.as_slice() {
                [qtype, _class, name, _proto, _rcode] => log.records.push(DnsRecord {
                    qtype: (*qtype).to_string(),
                    name: decode_name(name),
                }),
                _ => {
                    log.errors.insert("bad-line");
                }
            }
        } else if line.contains("GDQ") {
            log.errors.insert("bad-line");
        }
    }
    log
}
