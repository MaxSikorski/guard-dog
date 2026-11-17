//! The decimal number type every scheme shares.
//!
//! Numbers are never converted to machine integers: they are validated decimal
//! strings, compared by length and then bytes, so no input can overflow and no
//! bigint dependency is needed.

use std::cmp::Ordering;
use std::fmt;

/// The most dot-separated components any scheme reads (design 2.1, section 1).
pub(crate) const MAX_COMPONENTS: usize = 64;

/// A non-negative decimal number of any size, stored with no leading zeros
/// (`0` is `"0"`). Compared by length, then bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Num(String);

impl Num {
    /// ASCII digits only, nonempty, and no leading zero (`0` alone is fine).
    /// This is the strict reading: SemVer and CLN refuse `01`.
    pub(crate) fn strict(s: &str) -> Option<Self> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if s.len() > 1 && s.starts_with('0') {
            return None;
        }
        Some(Self(s.to_string()))
    }

    /// ASCII digits only, nonempty, any number of leading zeros; the stored form
    /// has none. This is the lenient reading PEP 440 and CLN's two-digit year
    /// and month need.
    pub(crate) fn trimmed(s: &str) -> Option<Self> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let t = s.trim_start_matches('0');
        Some(Self(if t.is_empty() {
            "0".to_string()
        } else {
            t.to_string()
        }))
    }

    pub(crate) fn zero() -> Self {
        Self("0".to_string())
    }

    pub(crate) fn one() -> Self {
        Self("1".to_string())
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.0 == "0"
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// This number plus one.
    pub(crate) fn plus_one(&self) -> Self {
        let mut digits: Vec<u8> = self.0.bytes().collect();
        let mut i = digits.len();
        loop {
            match i.checked_sub(1) {
                Some(j) => {
                    if let Some(d) = digits.get_mut(j) {
                        if *d == b'9' {
                            *d = b'0';
                        } else {
                            *d += 1;
                            break;
                        }
                    }
                    i = j;
                }
                None => {
                    digits.insert(0, b'1');
                    break;
                }
            }
        }
        Self(String::from_utf8_lossy(&digits).into_owned())
    }
}

impl Ord for Num {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.as_bytes().cmp(other.0.as_bytes()))
    }
}

impl PartialOrd for Num {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Num {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
