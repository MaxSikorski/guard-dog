//! Readers for the three independent capture sources: the resolver log
//! (`dns_log`), the recorder's decrypted flows (`mitm`) and the kernel-level
//! packet capture (`pcap`). Each reader reports problems as short codes and
//! carries on, so one unreadable source never hides what the others saw.

pub mod dns_log;
pub mod mitm;
pub mod pcap;

use std::fs;
use std::path::Path;

/// The five files of a capture directory, read but not yet parsed.
/// An `Err` holds the reason a file could not be used.
#[derive(Debug, Clone)]
pub struct RawCapture {
    /// `dns.log`
    pub dns_log: Result<Vec<u8>, &'static str>,
    /// `mitm/capture.jsonl`
    pub mitm: Result<Vec<u8>, &'static str>,
    /// `pcap/all.pcap`
    pub pcap: Result<Vec<u8>, &'static str>,
    /// `pcap/links.txt`
    pub links: Result<Vec<u8>, &'static str>,
    /// `pcap/rules.txt`
    pub rules: Result<Vec<u8>, &'static str>,
}

/// Capture files larger than this are refused (parsers of outside data set limits).
const MAX_BIG: u64 = 256 * 1024 * 1024;
/// Small text files (resolver log excepted) are refused above this.
const MAX_SMALL: u64 = 16 * 1024 * 1024;

fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>, &'static str> {
    let meta = fs::metadata(path).map_err(|_| "missing-file")?;
    if !meta.is_file() {
        return Err("missing-file");
    }
    if meta.len() > limit {
        return Err("too-large");
    }
    fs::read(path).map_err(|_| "missing-file")
}

impl RawCapture {
    /// Reads the capture directory layout that the lab's `run.sh` produces.
    pub fn load(dir: &Path) -> RawCapture {
        RawCapture {
            dns_log: read_limited(&dir.join("dns.log"), MAX_SMALL),
            mitm: read_limited(&dir.join("mitm/capture.jsonl"), MAX_BIG),
            pcap: read_limited(&dir.join("pcap/all.pcap"), MAX_BIG),
            links: read_limited(&dir.join("pcap/links.txt"), MAX_SMALL),
            rules: read_limited(&dir.join("pcap/rules.txt"), MAX_SMALL),
        }
    }
}
