//! The lab-only relay allowlist.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use gd_notify::relay::RelayUrl;

#[test]
fn the_five_lab_hosts_on_port_7777_are_allowed() {
    for host in ["bitcoind", "lnd", "cln", "strfry", "nutshell"] {
        let url = RelayUrl::parse(&format!("ws://{host}:7777")).unwrap();
        assert_eq!(url.host(), host);
        assert_eq!(url.port(), 7777);
    }
}

#[test]
fn everything_else_is_refused() {
    for bad in [
        "",
        "ws://strfry:7777/",
        "ws://strfry:7777/path",
        "ws://strfry:7778",
        "ws://strfry",
        "ws://strfry:",
        "ws://strfry:07777",
        "wss://strfry:7777",
        "http://strfry:7777",
        "ws://relay.damus.io:7777",
        "ws://127.0.0.1:7777",
        "ws://localhost:7777",
        "ws://[::1]:7777",
        "ws://10.0.0.5:7777",
        "ws://STRFRY:7777",
        "ws://strfry.:7777",
        "ws://strfry.example.com:7777",
        "ws://user@strfry:7777",
        "ws://user:pw@strfry:7777",
        "ws://strfry:7777?x=1",
        "ws://strfry:7777#x",
        " ws://strfry:7777",
        "ws://strfry:7777 ",
        "ws://strfry:7777\n",
        "ws://evil:7777@strfry:7777",
        "ws://strfry@evil:7777",
        "ws:///strfry:7777",
        "ws//strfry:7777",
        "WS://strfry:7777",
    ] {
        assert!(RelayUrl::parse(bad).is_err(), "accepted {bad:?}");
    }
}

#[test]
fn the_refusal_names_what_is_allowed() {
    let err = RelayUrl::parse("ws://relay.example:7777").unwrap_err();
    let text = err.to_string();
    assert!(text.contains("strfry"), "{text}");
    assert!(
        !text.contains("relay.example"),
        "must not echo input: {text}"
    );
}
