//! The planted files: an Umbrel-shaped tree holding every canary, and the
//! side files the lab scripts need. The answer key (`canaries.json`) is never
//! inside the tree that Guard Dog is allowed to read.

use crate::canary::{CanarySet, Class};
use std::fs;
use std::io;
use std::path::{Component, Path};

const UMBREL: &str = "home/umbrel/umbrel/app-data";

/// Every planted file as (path under the root, content), in a fixed order.
pub fn placements(set: &CanarySet) -> Vec<(String, Vec<u8>)> {
    let t = |class: Class| set.text(class);
    let line = |s: String| (s + "\n").into_bytes();
    vec![
        (
            "home/umbrel/seed.txt".into(),
            line(t(Class::SeedPhrase).into()),
        ),
        (
            format!("{UMBREL}/nostr-relay/data/.env"),
            line(format!("RELAY_NSEC={}", t(Class::Nsec))),
        ),
        (
            format!("{UMBREL}/sparrow/wallets/watch.json"),
            line(format!(
                "{{\"label\":\"watch-only\",\"xpub\":\"{}\"}}",
                t(Class::Xpub)
            )),
        ),
        (
            format!("{UMBREL}/lightning/data/lnd/data/chain/bitcoin/mainnet/admin.macaroon"),
            set.macaroon_bytes().to_vec(),
        ),
        (
            format!("{UMBREL}/lightning/.env"),
            line(format!("LND_MACAROON_HEX={}", t(Class::Macaroon))),
        ),
        (
            "var/lib/tor/bitcoin/hostname".into(),
            line(t(Class::Onion).into()),
        ),
        (
            format!("{UMBREL}/bitcoin/data/bitcoin/bitcoin.conf"),
            line(format!(
                "rpcuser=umbrel\nrpcpassword={}\nexternalip={}\nexternalip={}",
                t(Class::RpcPassword),
                t(Class::Ipv4),
                t(Class::Ipv6)
            )),
        ),
        (
            format!("{UMBREL}/core-lightning/.env"),
            line(format!("CLN_RUNE={}", t(Class::ClnRune))),
        ),
        (
            "var/lib/gd-egress/replies/lnd-getinfo.json".into(),
            line(format!(
                "{{\"identity_pubkey\":\"{}\",\"alias\":\"umbrel\"}}",
                t(Class::NodePubkey)
            )),
        ),
        ("etc/hostname".into(), line(t(Class::Hostname).into())),
    ]
}

/// A path is safe when every component is an ordinary name: no `..`, no root, no prefix.
pub fn is_safe_relative(path: &str) -> bool {
    !path.is_empty()
        && Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

fn write_file(base: &Path, relative: &str, content: &[u8]) -> io::Result<()> {
    if !is_safe_relative(relative) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsafe path"));
    }
    let target = base.join(relative);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(target, content)
}

/// Writes the planted tree into `root`.
pub fn write_root(root: &Path, set: &CanarySet) -> io::Result<()> {
    for (path, content) in placements(set) {
        write_file(root, &path, &content)?;
    }
    Ok(())
}

/// Writes `judge/canaries.json`, `root/**`, `teeth/leak.env` and `control.env` under `out`.
/// Refuses if `judge` or `root` already exists.
pub fn write_all(out: &Path, set: &CanarySet) -> io::Result<()> {
    for name in ["judge", "root"] {
        if out.join(name).exists() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{name} already exists"),
            ));
        }
    }
    let leak = set
        .leak_env()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_file(out, "judge/canaries.json", set.to_json().as_bytes())?;
    write_root(&out.join("root"), set)?;
    write_file(out, "teeth/leak.env", leak.as_bytes())?;
    write_file(out, "control.env", set.control_env().as_bytes())
}
