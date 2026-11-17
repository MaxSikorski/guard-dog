//! Judge: `only_a_proved_narrow_credential_is_accepted` and
//! `privilege_check_refuses_each_unsafe_start` (the process part).
//!
//! Macaroons and runes are built here by small test-only encoders, so the
//! decoders under test are checked against a second, independent writer.

use gd_core::privilege::bitcoind::{self, BitcoindRefusal, CanaryReply, CanaryRpc};
use gd_core::privilege::macaroon::{self, MacaroonRefusal};
use gd_core::privilege::rune::{self, RuneRefusal};
use gd_core::privilege::{self, ProcessFacts, Refusal};
use proptest::prelude::*;
use proptest::test_runner::{RngAlgorithm, RngSeed};

// ---------------------------------------------------------------- encoders

fn varint(mut n: u64, out: &mut Vec<u8>) {
    loop {
        let low = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

fn pb_bytes(field: u64, data: &[u8], out: &mut Vec<u8>) {
    varint(field << 3 | 2, out);
    varint(data.len() as u64, out);
    out.extend_from_slice(data);
}

fn pb_op(entity: &str, actions: &[&str]) -> Vec<u8> {
    let mut op = Vec::new();
    pb_bytes(1, entity.as_bytes(), &mut op);
    for action in actions {
        pb_bytes(2, action.as_bytes(), &mut op);
    }
    op
}

const NONCE: &[u8] = b"CANARYNONCE-0123";
const STORAGE_ID: &[u8] = b"canary-storage-id";

/// LND's macaroon identifier: version 3, then the protobuf.
fn lnd_id(ops: &[(&str, &[&str])]) -> Vec<u8> {
    let mut id = vec![3u8];
    pb_bytes(1, NONCE, &mut id);
    pb_bytes(2, STORAGE_ID, &mut id);
    for (entity, actions) in ops {
        pb_bytes(3, &pb_op(entity, actions), &mut id);
    }
    id
}

/// Macaroon v2 binary: version, [location] identifier EOS, caveats (each
/// ended by EOS), EOS, signature.
fn macaroon_bytes(id: &[u8], first_party: &[&[u8]], third_party: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut m = vec![2u8];
    m.push(1);
    varint(3, &mut m);
    m.extend_from_slice(b"lnd");
    m.push(2);
    varint(id.len() as u64, &mut m);
    m.extend_from_slice(id);
    m.push(0);
    for caveat in first_party {
        m.push(2);
        varint(caveat.len() as u64, &mut m);
        m.extend_from_slice(caveat);
        m.push(0);
    }
    for (cid, vid) in third_party {
        m.push(2);
        varint(cid.len() as u64, &mut m);
        m.extend_from_slice(cid);
        m.push(4);
        varint(vid.len() as u64, &mut m);
        m.extend_from_slice(vid);
        m.push(0);
    }
    m.push(0);
    m.push(6);
    varint(32, &mut m);
    m.extend_from_slice(&[0xA5; 32]);
    m
}

fn mac(ops: &[(&str, &[&str])]) -> Vec<u8> {
    macaroon_bytes(&lnd_id(ops), &[], &[])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const ENTITIES: [&str; 9] = [
    "onchain", "offchain", "address", "message", "peers", "info", "invoices", "signer", "macaroon",
];

fn admin_ops() -> Vec<(&'static str, &'static [&'static str])> {
    let mut ops: Vec<(&str, &[&str])> = ENTITIES.iter().map(|e| (*e, &["read", "write"][..])).collect();
    ops.push(("macaroon", &["generate"]));
    ops
}

fn readonly_ops() -> Vec<(&'static str, &'static [&'static str])> {
    ENTITIES.iter().map(|e| (*e, &["read"][..])).collect()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64url(data: &[u8], pad: bool) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, b)| acc | (*b as u32) << (16 - 8 * i));
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
        if pad {
            for _ in chars..4 {
                out.push('=');
            }
        }
    }
    out
}

const RUNE_STATE: [u8; 32] = *b"CANARYSTATE-0123456789abcdefghij";

fn rune_text(restrictions: &str, pad: bool) -> String {
    let mut raw = RUNE_STATE.to_vec();
    raw.extend_from_slice(restrictions.as_bytes());
    b64url(&raw, pad)
}

fn rune_ok(restrictions: &str) -> bool {
    rune::check(rune_text(restrictions, false).as_bytes()).is_ok()
        && rune::check(rune_text(restrictions, true).as_bytes()).is_ok()
}

fn rune_err(restrictions: &str) -> RuneRefusal {
    rune::check(rune_text(restrictions, false).as_bytes()).expect_err(restrictions)
}

// ---------------------------------------------------------------- macaroons

#[test]
fn info_read_alone_is_accepted_in_binary_and_hex() {
    let m = mac(&[("info", &["read"])]);
    let ok = macaroon::check(&m).expect("binary");
    assert_eq!(ok.first_party_caveats(), 0);
    assert_eq!(macaroon::check(hex(&m).as_bytes()), Ok(ok.clone()));
    assert_eq!(macaroon::check(hex(&m).to_uppercase().as_bytes()), Ok(ok));
}

#[test]
fn caveats_only_narrow_so_they_are_allowed_and_counted() {
    let id = lnd_id(&[("info", &["read"])]);
    let m = macaroon_bytes(&id, &[b"time-before 2030-01-01", b"ipaddr 10.0.0.1"], &[(b"3rd", b"vid")]);
    let ok = macaroon::check(&m).expect("accepted");
    assert_eq!(ok.first_party_caveats(), 2);
    assert_eq!(ok.third_party_caveats(), 1);
}

#[test]
fn admin_is_refused_as_admin() {
    assert_eq!(macaroon::check(&mac(&admin_ops())), Err(MacaroonRefusal::Admin));
    assert_eq!(macaroon::check(hex(&mac(&admin_ops())).as_bytes()), Err(MacaroonRefusal::Admin));
}

#[test]
fn any_write_permission_is_admin_even_on_info() {
    assert_eq!(macaroon::check(&mac(&[("info", &["write"])])), Err(MacaroonRefusal::Admin));
    assert_eq!(macaroon::check(&mac(&[("info", &["read", "write"])])), Err(MacaroonRefusal::Admin));
    assert_eq!(macaroon::check(&mac(&[("foo", &["write"])])), Err(MacaroonRefusal::Admin));
}

#[test]
fn the_stock_readonly_macaroon_is_refused_and_the_extras_are_named() {
    let err = macaroon::check(&mac(&readonly_ops())).expect_err("readonly");
    let text = err.to_string();
    match &err {
        MacaroonRefusal::TooWide { extra, unknown } => {
            assert!(!unknown);
            assert!(extra.contains(&"offchain:read"));
            assert!(extra.contains(&"onchain:read"));
            assert!(extra.contains(&"invoices:read"));
            assert!(!extra.contains(&"info:read"));
        }
        other => panic!("wrong refusal: {other:?}"),
    }
    assert!(text.contains("offchain:read") && text.contains("invoices:read"), "{text}");
    assert!(text.contains("lncli bakemacaroon info:read"), "{text}");
}

#[test]
fn info_read_plus_one_more_is_refused_by_name() {
    let err = macaroon::check(&mac(&[("info", &["read"]), ("offchain", &["read"])])).expect_err("extra");
    assert_eq!(err, MacaroonRefusal::TooWide { extra: vec!["offchain:read"], unknown: false });
    // Without info:read at all it is still not the narrow login.
    assert!(matches!(
        macaroon::check(&mac(&[("offchain", &["read"])])),
        Err(MacaroonRefusal::TooWide { .. })
    ));
}

#[test]
fn an_unknown_permission_is_never_echoed() {
    let err = macaroon::check(&mac(&[("info", &["read"]), ("zzqq-secret-entity", &["read"])])).expect_err("unknown");
    assert_eq!(err, MacaroonRefusal::TooWide { extra: vec![], unknown: true });
    let text = err.to_string();
    assert!(text.contains("an unknown permission"), "{text}");
    assert!(!text.contains("zzqq"), "{text}");
    assert!(!format!("{err:?}").contains("zzqq"));
}

#[test]
fn no_ops_at_all_is_refused() {
    assert_eq!(macaroon::check(&mac(&[])), Err(MacaroonRefusal::EmptyOps));
    assert_eq!(macaroon::check(&mac(&[("info", &[])])), Err(MacaroonRefusal::EmptyOps));
}

#[test]
fn the_wrong_version_is_refused() {
    let mut m = mac(&[("info", &["read"])]);
    m[0] = 1;
    assert_eq!(macaroon::check(&m), Err(MacaroonRefusal::WrongVersion));
    let mut id = lnd_id(&[("info", &["read"])]);
    id[0] = 4;
    assert_eq!(macaroon::check(&macaroon_bytes(&id, &[], &[])), Err(MacaroonRefusal::WrongVersion));
}

#[test]
fn oversize_input_is_refused_before_reading_it() {
    assert_eq!(macaroon::check(&vec![2u8; 4097]), Err(MacaroonRefusal::Oversize));
    assert_eq!(macaroon::check(&vec![b'a'; 4097]), Err(MacaroonRefusal::Oversize));
    assert!(matches!(macaroon::check(&vec![2u8; 4096]), Err(MacaroonRefusal::Malformed { .. })));
}

#[test]
fn junk_is_malformed() {
    for junk in [&b""[..], b"\x02", b"hello", b"zz", b"abc", b"\x02\x01\x03lnd", &[0xff; 40]] {
        assert!(matches!(macaroon::check(junk), Err(MacaroonRefusal::Malformed { .. }) | Err(MacaroonRefusal::WrongVersion)), "{junk:?}");
    }
    let mut trailing = mac(&[("info", &["read"])]);
    trailing.push(0);
    assert!(matches!(macaroon::check(&trailing), Err(MacaroonRefusal::Malformed { .. })));
    // A protobuf wire type we do not read (fixed32) is refused.
    let mut id = vec![3u8];
    id.extend_from_slice(&[0x0d, 1, 2, 3, 4]);
    assert!(matches!(macaroon::check(&macaroon_bytes(&id, &[], &[])), Err(MacaroonRefusal::Malformed { .. })));
}

#[test]
fn too_many_ops_or_long_strings_are_malformed() {
    let many: Vec<(&str, &[&str])> = (0..65).map(|_| ("info", &["read"][..])).collect();
    assert!(matches!(macaroon::check(&mac(&many)), Err(MacaroonRefusal::Malformed { .. })));
    let long = "a".repeat(65);
    assert!(matches!(macaroon::check(&mac(&[(long.as_str(), &["read"])])), Err(MacaroonRefusal::Malformed { .. })));
    let actions: Vec<&str> = vec!["read"; 65];
    assert!(matches!(macaroon::check(&mac(&[("info", &actions)])), Err(MacaroonRefusal::Malformed { .. })));
    assert!(matches!(macaroon::check(&mac(&[("inf\u{e9}", &["read"])])), Err(MacaroonRefusal::Malformed { .. })));
}

#[test]
fn every_truncation_is_refused_and_never_panics() {
    let m = mac(&[("info", &["read"])]);
    for cut in 0..m.len() {
        assert!(macaroon::check(&m[..cut]).is_err(), "binary cut at {cut}");
    }
    let h = hex(&m);
    for cut in 0..h.len() {
        assert!(macaroon::check(&h.as_bytes()[..cut]).is_err(), "hex cut at {cut}");
    }
    let wide = mac(&admin_ops());
    for cut in 0..wide.len() {
        assert!(macaroon::check(&wide[..cut]).is_err(), "admin cut at {cut}");
    }
}

// ---------------------------------------------------------------- runes

#[test]
fn the_getinfo_rune_is_accepted_padded_or_not() {
    assert!(rune_ok("=0&method=getinfo&pnum=0"));
    assert!(rune_ok("=7-1&method=getinfo&pnum=0"));
    assert!(rune_ok("method=getinfo&=0&pnum=0"));
    // Reversed order of the two restrictions.
    assert!(rune_ok("=0&pnum=0&method=getinfo"));
    // The padded form really has padding for some lengths.
    assert!((0..4).any(|n| rune_text(&"=0&method=getinfo&pnum=0".repeat(1).replace("=0", &format!("={}", "1".repeat(n + 1))), true).ends_with('=')));
}

#[test]
fn an_unrestricted_rune_is_refused() {
    assert_eq!(rune_err(""), RuneRefusal::Unrestricted);
    assert_eq!(rune_err("=0"), RuneRefusal::Unrestricted);
    assert!(RuneRefusal::Unrestricted.to_string().contains("can do anything on your node"));
}

#[test]
fn a_missing_restriction_is_refused_with_its_own_message() {
    assert_eq!(rune_err("=0&method=getinfo"), RuneRefusal::NotLimitedToNoParameters);
    assert!(RuneRefusal::NotLimitedToNoParameters.to_string().contains("can call getinfo with parameters"));
    assert_eq!(rune_err("=0&pnum=0"), RuneRefusal::NotLimitedToGetinfo);
    assert!(RuneRefusal::NotLimitedToGetinfo.to_string().contains("not limited to getinfo"));
}

#[test]
fn any_alternative_is_refused() {
    assert_eq!(rune_err("=0&method=getinfo|method=listfunds&pnum=0"), RuneRefusal::Alternatives);
    assert_eq!(rune_err("=0&method=getinfo&pnum=0|pnum=1"), RuneRefusal::Alternatives);
}

#[test]
fn restrictions_we_cannot_check_are_refused_without_echoing_them() {
    for text in [
        "=0&method^get",
        "=0&method=getinfo&pnum=0&time<123",
        "=0&method=listfunds&pnum=0",
        "=0&method=getinfo&pnum=0&method=getinfo",
        "method=getinfo&pnum=0",
        "=0&=1&method=getinfo&pnum=0",
        "=abc&method=getinfo&pnum=0",
        "=0&method=getinfo&pnum=1",
    ] {
        let err = rune_err(text);
        assert_eq!(err, RuneRefusal::UncheckableRestrictions, "{text}");
        let shown = format!("{err} {err:?}");
        assert!(shown.contains("has restrictions Guard Dog can't check"), "{shown}");
        assert!(!shown.contains("listfunds") && !shown.contains("time"), "{shown}");
    }
}

#[test]
fn escapes_are_read_not_trusted() {
    // An escaped separator is a character, so this is one odd restriction.
    assert_eq!(rune_err("=0&method=getinfo\\&pnum=0"), RuneRefusal::UncheckableRestrictions);
    assert!(matches!(rune_err("=0&method=getinfo&pnum=0\\"), RuneRefusal::Malformed { .. }));
}

#[test]
fn bad_base64_and_sizes_are_refused() {
    let good = rune_text("=0&method=getinfo&pnum=0", false);
    for bad in [good.replace('A', "*"), format!("{good} "), format!("{good}\n"), good.replace('-', "+"), format!("{good}=")] {
        // Only inputs that actually changed are bad.
        if bad != good {
            assert!(matches!(rune::check(bad.as_bytes()), Err(RuneRefusal::Malformed { .. })), "{bad}");
        }
    }
    assert!(matches!(rune::check(b"abcd!"), Err(RuneRefusal::Malformed { .. })));
    assert!(matches!(rune::check(b"a"), Err(RuneRefusal::Malformed { .. })));
    assert!(matches!(rune::check(b""), Err(RuneRefusal::Malformed { .. })));
    // Fewer than 32 bytes decoded.
    assert!(matches!(rune::check(b"AAAA"), Err(RuneRefusal::Malformed { .. })));
    assert_eq!(rune::check(&vec![b'A'; 1025]), Err(RuneRefusal::Oversize));
    assert!(matches!(rune::check(&vec![b'A'; 1024]), Err(RuneRefusal::Malformed { .. })));
    assert!(matches!(rune::check(&[0xff, 0xfe]), Err(RuneRefusal::Malformed { .. })));
}

#[test]
fn every_rune_truncation_is_refused_and_never_panics() {
    for restrictions in ["=0&method=getinfo&pnum=0", "=0&pnum=0&method=getinfo"] {
        for pad in [false, true] {
            let text = rune_text(restrictions, pad);
            for cut in 0..text.len() {
                // A cut that lands on a character boundary of the restriction
                // text leaves a *different* rune, which must be refused too.
                assert!(rune::check(&text.as_bytes()[..cut]).is_err(), "cut at {cut} of {text}");
            }
        }
    }
}

// ---------------------------------------------------------------- bitcoind

struct Stub {
    reply: CanaryReply,
    calls: Vec<String>,
}

impl CanaryRpc for Stub {
    fn call(&mut self, method: &str) -> CanaryReply {
        self.calls.push(method.to_string());
        self.reply
    }
}

fn run_bitcoind(user: &str, reply: CanaryReply) -> (Result<bitcoind::NarrowLogin, BitcoindRefusal>, Vec<String>) {
    let mut stub = Stub { reply, calls: Vec::new() };
    let result = bitcoind::check(user, &mut stub);
    (result, stub.calls)
}

#[test]
fn a_403_on_the_canary_call_accepts() {
    let (result, calls) = run_bitcoind("guarddog", CanaryReply::Status(403));
    assert!(result.is_ok());
    assert_eq!(calls, vec!["getblockcount"]);
}

#[test]
fn a_200_refuses_and_names_the_fix() {
    let (result, _) = run_bitcoind("guarddog", CanaryReply::Status(200));
    let err = result.expect_err("200");
    assert_eq!(err, BitcoindRefusal::TooWide);
    let text = err.to_string();
    assert!(text.contains("rpcwhitelist=<user>:getnetworkinfo,getblockchaininfo"), "{text}");
    assert!(text.contains("rpcwhitelistdefault=0"), "{text}");
}

#[test]
fn a_401_means_the_password_is_wrong() {
    let (result, _) = run_bitcoind("guarddog", CanaryReply::Status(401));
    let err = result.expect_err("401");
    assert_eq!(err, BitcoindRefusal::WrongPassword);
    assert!(err.to_string().contains("password"));
}

#[test]
fn anything_else_cannot_be_proved() {
    for reply in [CanaryReply::Status(500), CanaryReply::Status(404), CanaryReply::Status(0), CanaryReply::Status(204), CanaryReply::NoReply] {
        let (result, calls) = run_bitcoind("guarddog", reply);
        assert_eq!(result, Err(BitcoindRefusal::CouldNotProve), "{reply:?}");
        assert_eq!(calls.len(), 1);
    }
}

#[test]
fn the_cookie_login_is_refused_before_any_call() {
    let (result, calls) = run_bitcoind("__cookie__", CanaryReply::Status(403));
    let err = result.expect_err("cookie");
    assert_eq!(err, BitcoindRefusal::CookieLogin);
    assert!(err.to_string().contains("full-access cookie login"));
    assert!(calls.is_empty(), "no call may be made: {calls:?}");
}

// ---------------------------------------------------------------- process

#[test]
fn root_is_refused_and_an_ordinary_user_is_fine() {
    let refusals = privilege::check(&ProcessFacts::new(0)).expect_err("root");
    assert_eq!(refusals, vec![Refusal::RunningAsRoot]);
    assert!(refusals[0].to_string().contains("never runs as root"));
    assert!(privilege::check(&ProcessFacts::new(1000)).is_ok());
    assert!(privilege::check(&ProcessFacts::new(65534)).is_ok());
}

// ---------------------------------------------------------------- no leaks

#[test]
fn no_refusal_or_acceptance_prints_the_credential() {
    // Macaroons.
    let sets: Vec<Vec<(&str, &[&str])>> = vec![
        admin_ops(),
        readonly_ops(),
        vec![("info", &["read"])],
        vec![("info", &["read"]), ("offchain", &["read"])],
        vec![("secretentity", &["read"])],
        vec![("info", &["write"])],
        vec![],
    ];
    let mut shown = Vec::new();
    let mut inputs: Vec<Vec<u8>> = sets.iter().map(|s| mac(s)).collect();
    inputs.push(vec![2u8; 5000]);
    inputs.push(b"CANARYHEXTEXT".to_vec());
    for input in &inputs {
        for form in [input.clone(), hex(input).into_bytes()] {
            match macaroon::check(&form) {
                Ok(ok) => shown.push(format!("{ok:?}")),
                Err(err) => {
                    shown.push(format!("{err:?}"));
                    shown.push(format!("{err}"));
                }
            }
        }
    }
    // Runes.
    let rune_inputs = [
        rune_text("", false),
        rune_text("=0&method=getinfo&pnum=0", true),
        rune_text("=0&method=getinfo", false),
        rune_text("=0&method=a|method=b", false),
        rune_text("=0&secretfield^secretvalue", false),
        "CANARYRUNE*".to_string(),
    ];
    for input in &rune_inputs {
        match rune::check(input.as_bytes()) {
            Ok(ok) => shown.push(format!("{ok:?}")),
            Err(err) => {
                shown.push(format!("{err:?}"));
                shown.push(format!("{err}"));
            }
        }
    }
    // bitcoind.
    for reply in [CanaryReply::Status(200), CanaryReply::Status(401), CanaryReply::Status(403), CanaryReply::Status(500), CanaryReply::NoReply] {
        let (result, _) = run_bitcoind("svc_canary_user", reply);
        match result {
            Ok(ok) => shown.push(format!("{ok:?}")),
            Err(err) => {
                shown.push(format!("{err:?}"));
                shown.push(format!("{err}"));
            }
        }
    }
    let (cookie, _) = run_bitcoind("__cookie__", CanaryReply::NoReply);
    let cookie = cookie.expect_err("cookie");
    shown.push(format!("{cookie:?} {cookie}"));
    let root = &privilege::check(&ProcessFacts::new(0)).expect_err("root")[0];
    shown.push(format!("{root:?} {root}"));

    let mut secrets: Vec<String> = vec![
        "CANARYNONCE".into(),
        hex(NONCE),
        "canary-storage-id".into(),
        hex(STORAGE_ID),
        "CANARYSTATE".into(),
        hex(&RUNE_STATE),
        b64url(&RUNE_STATE, false)[..16].to_string(),
        "svc_canary_user".into(),
        "secretentity".into(),
        "secretfield".into(),
        "secretvalue".into(),
        "CANARYHEXTEXT".into(),
        "CANARYRUNE".into(),
        hex(&[0xA5; 32]),
    ];
    for input in &inputs {
        secrets.push(hex(input)[..24.min(hex(input).len())].to_string());
    }
    for text in &shown {
        assert!(!text.is_empty());
        for secret in secrets.iter().filter(|s| s.len() >= 8) {
            assert!(!text.contains(secret.as_str()), "{text:?} contains {secret:?}");
        }
    }
}

// ---------------------------------------------------------------- property tests

fn config() -> ProptestConfig {
    ProptestConfig {
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(0x0000_0000_2026_1117),
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

const OP_POOL: [(&str, &str); 8] = [
    ("info", "read"),
    ("info", "write"),
    ("offchain", "read"),
    ("onchain", "read"),
    ("invoices", "read"),
    ("macaroon", "generate"),
    ("mystery", "read"),
    ("peers", "write"),
];

const RUNE_POOL: [&str; 8] = ["method=getinfo", "pnum=0", "method=listfunds", "time<123", "method=getinfo|pnum=0", "pnum=1", "=1", "method^get"];

proptest! {
    #![proptest_config(config())]

    #[test]
    fn arbitrary_bytes_never_panic_and_rarely_pass_the_macaroon_decoder(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        if macaroon::check(&bytes).is_ok() {
            let decoded_has_info_read = contains(&bytes, b"info") && contains(&bytes, b"read") && !contains(&bytes, b"write");
            prop_assert!(decoded_has_info_read);
        }
        let _ = macaroon::check(hex(&bytes).as_bytes());
    }

    #[test]
    fn arbitrary_bytes_never_panic_and_only_url_safe_text_passes_the_rune_decoder(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        if rune::check(&bytes).is_ok() {
            prop_assert!(bytes.iter().all(|b| B64.contains(b) || *b == b'='));
        }
    }

    #[test]
    fn a_macaroon_passes_exactly_when_its_ops_are_info_read(picks in proptest::collection::vec(0..OP_POOL.len(), 0..6), caveats in 0usize..4) {
        let ops: Vec<(&str, &[&str])> = picks.iter().map(|i| (OP_POOL[*i].0, std::slice::from_ref(&OP_POOL[*i].1))).collect();
        let caveat_bytes: Vec<&[u8]> = (0..caveats).map(|_| &b"time-before 2030"[..]).collect();
        let m = macaroon_bytes(&lnd_id(&ops), &caveat_bytes, &[]);
        let exact = !picks.is_empty() && picks.iter().all(|i| OP_POOL[*i] == ("info", "read"));
        let result = macaroon::check(&m);
        prop_assert_eq!(result.is_ok(), exact);
        if let Ok(ok) = result {
            prop_assert_eq!(ok.first_party_caveats(), caveats);
        }
        prop_assert_eq!(macaroon::check(hex(&m).as_bytes()).is_ok(), exact);
    }

    #[test]
    fn a_rune_passes_exactly_when_its_restrictions_are_the_two_allowed_ones(picks in proptest::collection::vec(0..RUNE_POOL.len(), 0..5), pad in any::<bool>()) {
        let text = picks.iter().map(|i| RUNE_POOL[*i]).collect::<Vec<_>>().join("&");
        let mut sorted: Vec<&str> = picks.iter().map(|i| RUNE_POOL[*i]).filter(|r| *r != "=1").collect();
        let ids = picks.iter().filter(|i| RUNE_POOL[**i] == "=1").count();
        sorted.sort_unstable();
        // The one unique id comes from this prefix when the pool did not add any.
        let full = if ids == 0 { format!("=0&{text}") } else { text.clone() };
        let exact = ids <= 1 && sorted == ["method=getinfo", "pnum=0"];
        let result = rune::check(rune_text(full.trim_end_matches('&'), pad).as_bytes());
        prop_assert_eq!(result.is_ok(), exact, "{}", full);
    }
}
