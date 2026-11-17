//! The canary generator and the planted file tree.

// Test-only crate: see `crates/gd-core/tests/judge_d_injection.rs` for why helpers need this.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use gd_egress::bip39;
use gd_egress::canary::{Class, generate};
use gd_egress::setup;
use regex::Regex;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn temp(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("gd-egress-canaries-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn files_under(dir: &Path) -> BTreeSet<String> {
    fn walk(dir: &Path, base: &Path, out: &mut BTreeSet<String>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, base, out);
            } else {
                out.insert(
                    path.strip_prefix(base)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(dir, dir, &mut out);
    out
}

#[test]
fn canaries_are_stable_for_a_seed() {
    let golden = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/egress/golden/canaries-seed-1.json"
    ))
    .unwrap();
    assert_eq!(generate(1).to_json(), golden);
    assert_eq!(generate(1), generate(1));
    let back = gd_egress::canary::CanarySet::from_json(&golden).unwrap();
    assert_eq!(
        back,
        generate(1),
        "canaries.json reads back to the same set"
    );
}

#[test]
fn canaries_differ_between_seeds() {
    for class in Class::ALL {
        let values: BTreeSet<String> = (1..=1000u64)
            .map(|seed| generate(seed).text(class).to_string())
            .collect();
        if class == Class::Ipv4 {
            assert!(
                values.len() >= 200,
                "ipv4 has only {} distinct values",
                values.len()
            );
        } else {
            assert_eq!(values.len(), 1000, "{} repeats", class.name());
        }
    }
    let tokens: BTreeSet<String> = (1..=1000u64).map(|s| generate(s).control_token).collect();
    assert_eq!(tokens.len(), 1000);
}

#[test]
fn every_canary_has_its_shape() {
    let shapes = [
        (Class::Nsec, r"^nsec1[02-9ac-hj-np-z]{58}$"),
        (Class::Xpub, r"^xpub[1-9A-HJ-NP-Za-km-z]{107,108}$"),
        (Class::Macaroon, r"^0201036c6e64[0-9a-f]{188}$"),
        (Class::Onion, r"^[a-z2-7]{55}d\.onion$"),
        (Class::RpcPassword, r"^gdlabcanary-[0-9a-f]{64}$"),
        (Class::NodePubkey, r"^0[23][0-9a-f]{64}$"),
        (Class::ClnRune, r"^[A-Za-z0-9_-]{64}$"),
        (Class::Hostname, r"^gdcanary-host-[a-z2-7]{10}$"),
        (
            Class::Ipv4,
            r"^198\.51\.100\.([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-4])$",
        ),
        (Class::Ipv6, r"^2001:db8:"),
    ];
    let words: BTreeSet<&str> = bip39::words().into_iter().collect();
    let token = Regex::new(r"^gdctl[a-z2-7]{20}$").unwrap();
    for seed in 1..=50u64 {
        let set = generate(seed);
        for (class, pattern) in &shapes {
            assert!(
                Regex::new(pattern).unwrap().is_match(set.text(*class)),
                "{} seed {seed}: {}",
                class.name(),
                set.text(*class)
            );
        }
        let phrase: Vec<&str> = set.text(Class::SeedPhrase).split(' ').collect();
        assert_eq!(phrase.len(), 24);
        assert!(phrase.iter().all(|w| words.contains(w)));
        assert!(token.is_match(&set.control_token));
        assert_eq!(set.macaroon_bytes().len(), 100);
    }
}

#[test]
fn setup_root_holds_exactly_the_placements() {
    let out = temp("placements");
    let set = generate(1);
    setup::write_all(&out, &set).unwrap();
    let root = out.join("root");
    let expected: BTreeSet<String> = [
        "etc/hostname",
        "home/umbrel/seed.txt",
        "home/umbrel/umbrel/app-data/bitcoin/data/bitcoin/bitcoin.conf",
        "home/umbrel/umbrel/app-data/core-lightning/.env",
        "home/umbrel/umbrel/app-data/lightning/.env",
        "home/umbrel/umbrel/app-data/lightning/data/lnd/data/chain/bitcoin/mainnet/admin.macaroon",
        "home/umbrel/umbrel/app-data/nostr-relay/data/.env",
        "home/umbrel/umbrel/app-data/sparrow/wallets/watch.json",
        "var/lib/gd-egress/replies/lnd-getinfo.json",
        "var/lib/tor/bitcoin/hostname",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(files_under(&root), expected);
    let all: Vec<Vec<u8>> = expected
        .iter()
        .map(|p| fs::read(root.join(p)).unwrap())
        .collect();
    for canary in &set.canaries {
        let needle = if canary.class == Class::Macaroon {
            canary.bytes.clone().unwrap()
        } else {
            canary.text.clone().into_bytes()
        };
        assert!(
            all.iter()
                .any(|f| f.windows(needle.len()).any(|w| w == needle.as_slice())),
            "{} is not planted",
            canary.class.name()
        );
    }
    assert_eq!(
        fs::read(root.join("var/lib/tor/bitcoin/hostname")).unwrap(),
        format!("{}\n", set.text(Class::Onion)).into_bytes()
    );
    assert_eq!(
        files_under(&out).len(),
        expected.len() + 3,
        "judge, teeth and control.env only"
    );
    assert!(setup::is_safe_relative("a/b/c"));
    assert!(!setup::is_safe_relative("../x"));
    assert!(!setup::is_safe_relative("/etc/passwd"));
    assert!(!setup::is_safe_relative("a/../b"));
    fs::remove_dir_all(&out).unwrap();
}

#[test]
fn the_answer_key_is_never_inside_the_root() {
    let out = temp("answer-key");
    let set = generate(3);
    setup::write_all(&out, &set).unwrap();
    let root = out.join("root");
    for path in files_under(&root) {
        let bytes = fs::read(root.join(&path)).unwrap();
        let token = set.control_token.as_bytes();
        assert!(
            !bytes.windows(token.len()).any(|w| w == token),
            "{path} holds the control token"
        );
    }
    assert!(
        !files_under(&root)
            .iter()
            .any(|p| p.contains("canaries.json"))
    );
    assert!(
        out.join("judge/canaries.json").exists()
            && !out.join("judge/canaries.json").starts_with(&root)
    );
    fs::remove_dir_all(&out).unwrap();
}
