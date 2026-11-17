//! The watchdog demo, run headless: every scene must end "caught".
//!
//! Also keeps the demo honest: the browser's JSON carries the same events, no
//! whole secret is printed, and the committed browser engine is the one the
//! README pins by hash. (That a broken check says MISSED is tested next to the
//! scenes, in `src/lib.rs`.)

use gd_demo::{Event, all_caught, caught, missed, run, scenes, to_json, todos};
use gd_egress::canary::{Class, generate};
use gd_egress::encode::{base64, base64_decode, hex, sha256};
use std::path::{Path, PathBuf};

fn repo_file(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

#[test]
fn every_scene_is_caught() {
    let events = run();
    assert_eq!(scenes(&events), 5, "five scenes run today");
    assert_eq!(
        missed(&events),
        0,
        "a check missed its planted case: {events:#?}"
    );
    assert_eq!(
        caught(&events),
        5,
        "each scene ends in exactly one 'caught'"
    );
    assert!(all_caught(&events));
    // Every scene ends with its verdict, in order.
    let mut open = false;
    for e in &events {
        match e {
            Event::Scene { .. } => {
                assert!(!open, "a scene started before the last one ended");
                open = true;
            }
            Event::Caught(_) | Event::Missed(_) => {
                assert!(open, "a verdict with no scene");
                open = false;
            }
            _ => {}
        }
    }
    assert!(!open, "the last scene has no verdict");
}

#[test]
fn the_not_yet_slots_are_listed_and_are_not_passes() {
    let events = run();
    let slots: Vec<&str> = events
        .iter()
        .filter_map(|e| match e {
            Event::Todo { title, .. } => Some(title.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        slots,
        [
            "A seed phrase hidden in a gzip body",
            "An xpub re-encoded as a zpub",
            "An affected version flagged"
        ],
        "when one of these lands, turn it into a scene and update this list"
    );
    assert_eq!(todos(&events), 3);
    assert_eq!(caught(&events), 5, "a to-do slot never counts as caught");
}

#[test]
fn nothing_secret_is_printed_whole_and_the_ip_is_documentation_only() {
    let set = generate(gd_demo::SEED);
    let text = to_json(&run());
    for class in [Class::Nsec, Class::Xpub, Class::SeedPhrase, Class::Macaroon] {
        assert!(
            !text.contains(set.text(class)),
            "the demo printed a whole {} value",
            class.name()
        );
    }
    // The nsec's base64 in every spelling: the demo shortens it, never prints it whole.
    let nsec = set.text(Class::Nsec).as_bytes();
    for (url, pad) in [(false, true), (false, false), (true, true), (true, false)] {
        let full = base64(nsec, url, pad);
        assert!(
            !text.contains(&full),
            "the demo printed the whole base64 nsec"
        );
    }
    // The one address it prints sits in 198.51.100.0/24 (documentation range).
    let after = text
        .split("from=")
        .nth(1)
        .expect("the URL scene prints its address");
    let addr: String = after
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let octets: Vec<u8> = addr.split('.').map(|o| o.parse().unwrap()).collect();
    assert_eq!(octets.len(), 4, "not an IPv4 address: {addr}");
    assert_eq!(
        octets[..3],
        [198, 51, 100],
        "outside 198.51.100.0/24: {addr}"
    );
}

#[test]
fn the_browser_json_carries_the_same_events() {
    let events = run();
    let parsed: serde_json::Value = serde_json::from_str(&to_json(&events)).unwrap();
    let array = parsed.as_array().unwrap();
    assert_eq!(array.len(), events.len());
    let kinds = |t: &str| array.iter().filter(|v| v["t"] == t).count();
    assert_eq!(kinds("scene"), scenes(&events));
    assert_eq!(kinds("caught"), caught(&events));
    assert_eq!(kinds("missed"), 0);
    assert_eq!(kinds("todo"), 3);
}

/// Two hashes are pinned in `docs/demo/README.md`, and each catches something different.
///
/// 1. `watchdog.wasm`: the module inside the committed `docs/demo/watchdog.wasm.js` must be the one
///    the README names. This catches the script file being edited or replaced by hand. It does not
///    prove the module was built from this source.
/// 2. `events.json`: the SHA-256 of the events JSON the scenes produce from source (what the engine
///    hands the page). This catches a change to a scene's text or verdict: it fails until someone
///    rebuilds the engine with `docs/demo/build.sh` and pins the new hashes. It does not prove the
///    committed module produces that JSON; only a rebuild and compare does (by hand at release time).
#[test]
fn the_committed_browser_engine_matches_the_pinned_hash() {
    let js = std::fs::read_to_string(repo_file("docs/demo/watchdog.wasm.js")).unwrap();
    let b64 = js
        .split("window.GD_WASM_BASE64=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("watchdog.wasm.js has the base64 engine");
    let wasm = base64_decode(b64).expect("the engine is valid base64");
    assert_eq!(&wasm[..4], b"\0asm", "the engine is a WebAssembly module");
    let actual = hex(&sha256(&wasm));

    let readme = std::fs::read_to_string(repo_file("docs/demo/README.md")).unwrap();
    let pin = |name: &str| -> String {
        let suffix = format!("  {name}");
        let found: Vec<&str> = readme
            .lines()
            .filter_map(|l| l.strip_suffix(suffix.as_str()))
            .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
            .collect();
        assert_eq!(
            found.len(),
            1,
            "docs/demo/README.md pins exactly one {name} hash"
        );
        found[0].to_string()
    };
    assert_eq!(
        actual,
        pin("watchdog.wasm"),
        "docs/demo/watchdog.wasm.js is not the module the README pins: run docs/demo/build.sh and update the README"
    );
    let events = hex(&sha256(to_json(&run()).as_bytes()));
    assert_eq!(
        events,
        pin("events.json"),
        "the scenes' events changed: rebuild the engine with docs/demo/build.sh and pin the new hashes in docs/demo/README.md"
    );
}
