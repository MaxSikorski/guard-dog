//! Judge: `only_a_proved_narrow_credential_is_accepted` and
//! `privilege_check_refuses_each_unsafe_start` (the process part).
//!
//! Macaroons and runes are built here by small test-only encoders, so the
//! decoders under test are checked against a second, independent writer.

// Test helpers may index and unwrap: a test that panics is a test that fails.
#![allow(
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic
)]

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
    let mut ops: Vec<(&str, &[&str])> = ENTITIES
        .iter()
        .map(|e| (*e, &["read", "write"][..]))
        .collect();
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
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (*b as u32) << (16 - 8 * i));
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
    let m = macaroon_bytes(
        &id,
        &[b"time-before 2030-01-01", b"ipaddr 10.0.0.1"],
        &[(b"3rd", b"vid")],
    );
    let ok = macaroon::check(&m).expect("accepted");
    assert_eq!(ok.first_party_caveats(), 2);
    assert_eq!(ok.third_party_caveats(), 1);
}

#[test]
fn admin_is_refused_as_admin() {
    assert_eq!(
        macaroon::check(&mac(&admin_ops())),
        Err(MacaroonRefusal::Admin)
    );
    assert_eq!(
        macaroon::check(hex(&mac(&admin_ops())).as_bytes()),
        Err(MacaroonRefusal::Admin)
    );
}

#[test]
fn any_write_permission_is_admin_even_on_info() {
    assert_eq!(
        macaroon::check(&mac(&[("info", &["write"])])),
        Err(MacaroonRefusal::Admin)
    );
    assert_eq!(
        macaroon::check(&mac(&[("info", &["read", "write"])])),
        Err(MacaroonRefusal::Admin)
    );
    assert_eq!(
        macaroon::check(&mac(&[("foo", &["write"])])),
        Err(MacaroonRefusal::Admin)
    );
}

#[test]
fn the_stock_readonly_macaroon_is_refused_and_the_extras_are_named() {
    let err = macaroon::check(&mac(&readonly_ops())).expect_err("readonly");
    let text = err.to_string();
    match &err {
        MacaroonRefusal::TooWide {
            extra,
            unknown,
            has_info_read,
        } => {
            assert!(!unknown);
            assert!(has_info_read);
            assert!(extra.contains(&"offchain:read"));
            assert!(extra.contains(&"onchain:read"));
            assert!(extra.contains(&"invoices:read"));
            assert!(!extra.contains(&"info:read"));
        }
        other => panic!("wrong refusal: {other:?}"),
    }
    assert!(
        text.contains("offchain:read") && text.contains("invoices:read"),
        "{text}"
    );
    assert!(text.contains("lncli bakemacaroon info:read"), "{text}");
}

#[test]
fn info_read_plus_one_more_is_refused_by_name() {
    let err =
        macaroon::check(&mac(&[("info", &["read"]), ("offchain", &["read"])])).expect_err("extra");
    assert_eq!(
        err,
        MacaroonRefusal::TooWide {
            extra: vec!["offchain:read"],
            unknown: false,
            has_info_read: true
        }
    );
    // Without info:read at all it is still not the narrow login.
    assert!(matches!(
        macaroon::check(&mac(&[("offchain", &["read"])])),
        Err(MacaroonRefusal::TooWide { .. })
    ));
}

#[test]
fn an_unknown_permission_is_never_echoed() {
    let err = macaroon::check(&mac(&[
        ("info", &["read"]),
        ("zzqq-secret-entity", &["read"]),
    ]))
    .expect_err("unknown");
    assert_eq!(
        err,
        MacaroonRefusal::TooWide {
            extra: vec![],
            unknown: true,
            has_info_read: true
        }
    );
    let text = err.to_string();
    assert!(text.contains("an unknown permission"), "{text}");
    assert!(!text.contains("zzqq"), "{text}");
    assert!(!format!("{err:?}").contains("zzqq"));
}

#[test]
fn no_ops_at_all_is_refused() {
    assert_eq!(macaroon::check(&mac(&[])), Err(MacaroonRefusal::EmptyOps));
    assert_eq!(
        macaroon::check(&mac(&[("info", &[])])),
        Err(MacaroonRefusal::EmptyOps)
    );
}

#[test]
fn the_wrong_version_is_refused() {
    let mut m = mac(&[("info", &["read"])]);
    m[0] = 1;
    assert_eq!(macaroon::check(&m), Err(MacaroonRefusal::WrongVersion));
    let mut id = lnd_id(&[("info", &["read"])]);
    id[0] = 4;
    assert_eq!(
        macaroon::check(&macaroon_bytes(&id, &[], &[])),
        Err(MacaroonRefusal::WrongVersion)
    );
}

#[test]
fn oversize_input_is_refused_before_reading_it() {
    assert_eq!(
        macaroon::check(&vec![2u8; 4097]),
        Err(MacaroonRefusal::Oversize)
    );
    assert_eq!(
        macaroon::check(&vec![b'a'; 4097]),
        Err(MacaroonRefusal::Oversize)
    );
    assert!(matches!(
        macaroon::check(&vec![2u8; 4096]),
        Err(MacaroonRefusal::Malformed { .. })
    ));
}

#[test]
fn junk_is_malformed() {
    for junk in [
        &b""[..],
        b"\x02",
        b"hello",
        b"zz",
        b"abc",
        b"\x02\x01\x03lnd",
        &[0xff; 40],
    ] {
        assert!(
            matches!(
                macaroon::check(junk),
                Err(MacaroonRefusal::Malformed { .. }) | Err(MacaroonRefusal::WrongVersion)
            ),
            "{junk:?}"
        );
    }
    let mut trailing = mac(&[("info", &["read"])]);
    trailing.push(0);
    assert!(matches!(
        macaroon::check(&trailing),
        Err(MacaroonRefusal::Malformed { .. })
    ));
    // A protobuf wire type we do not read (fixed32) is refused.
    let mut id = vec![3u8];
    id.extend_from_slice(&[0x0d, 1, 2, 3, 4]);
    assert!(matches!(
        macaroon::check(&macaroon_bytes(&id, &[], &[])),
        Err(MacaroonRefusal::Malformed { .. })
    ));
}

#[test]
fn too_many_ops_or_long_strings_are_malformed() {
    let many: Vec<(&str, &[&str])> = (0..65).map(|_| ("info", &["read"][..])).collect();
    assert!(matches!(
        macaroon::check(&mac(&many)),
        Err(MacaroonRefusal::Malformed { .. })
    ));
    let long = "a".repeat(65);
    assert!(matches!(
        macaroon::check(&mac(&[(long.as_str(), &["read"])])),
        Err(MacaroonRefusal::Malformed { .. })
    ));
    let actions: Vec<&str> = vec!["read"; 65];
    assert!(matches!(
        macaroon::check(&mac(&[("info", &actions)])),
        Err(MacaroonRefusal::Malformed { .. })
    ));
    assert!(matches!(
        macaroon::check(&mac(&[("inf\u{e9}", &["read"])])),
        Err(MacaroonRefusal::Malformed { .. })
    ));
}

#[test]
fn every_truncation_is_refused_and_never_panics() {
    let m = mac(&[("info", &["read"])]);
    for cut in 0..m.len() {
        assert!(macaroon::check(&m[..cut]).is_err(), "binary cut at {cut}");
    }
    let h = hex(&m);
    for cut in 0..h.len() {
        assert!(
            macaroon::check(&h.as_bytes()[..cut]).is_err(),
            "hex cut at {cut}"
        );
    }
    let wide = mac(&admin_ops());
    for cut in 0..wide.len() {
        assert!(macaroon::check(&wide[..cut]).is_err(), "admin cut at {cut}");
    }
}

// ---- exact reasons for each malformed shape

const W_NUM: &str = "a number in it is cut short or malformed";

fn why(input: &[u8]) -> &'static str {
    match macaroon::check(input) {
        Err(MacaroonRefusal::Malformed { why }) => why,
        other => panic!("expected Malformed, got {other:?}"),
    }
}

fn field(kind: u8, data: &[u8]) -> Vec<u8> {
    let mut f = vec![kind];
    varint(data.len() as u64, &mut f);
    f.extend_from_slice(data);
    f
}

/// A macaroon around hand-made sections: version, the given header bytes
/// (which must end in EOS), the given caveat bytes, EOS, signature.
fn raw_macaroon(header: &[u8], caveats: &[u8]) -> Vec<u8> {
    let mut m = vec![2u8];
    m.extend_from_slice(header);
    m.extend_from_slice(caveats);
    m.extend_from_slice(&[0, 6, 32]);
    m.extend_from_slice(&[0xA5; 32]);
    m
}

fn header_of(fields: &[Vec<u8>]) -> Vec<u8> {
    let mut h = fields.concat();
    h.push(0);
    h
}

fn id_with_op(op: &[u8]) -> Vec<u8> {
    let mut id = vec![3u8];
    pb_bytes(3, op, &mut id);
    id
}

#[test]
fn each_malformed_shape_is_refused_for_its_own_reason() {
    let info = lnd_id(&[("info", &["read"])]);
    assert!(macaroon::check(&raw_macaroon(&header_of(&[field(2, &info)]), &[])).is_ok());

    // Two entity fields: protobuf would keep the last one, so refuse.
    let two_entities = [
        &[0x0a, 4][..],
        b"info",
        &[0x0a, 7],
        b"onchain",
        &[0x12, 4],
        b"read",
    ]
    .concat();
    assert_eq!(
        why(&macaroon_bytes(&id_with_op(&two_entities), &[], &[])),
        "a permission names two entities"
    );
    // Wrong wire type (a number) for an op's entity (1) and actions (2).
    for op in [[0x08u8, 1], [0x10, 1]] {
        assert_eq!(
            why(&macaroon_bytes(&id_with_op(&op), &[], &[])),
            "a permission has the wrong shape"
        );
    }
    // Wrong wire type for the identifier's ops (3).
    assert_eq!(
        why(&macaroon_bytes(&[3, 0x18, 1], &[], &[])),
        "its identifier has the wrong shape"
    );
    // Actions but no entity.
    let mut no_entity = Vec::new();
    pb_bytes(2, b"read", &mut no_entity);
    assert_eq!(
        why(&macaroon_bytes(&id_with_op(&no_entity), &[], &[])),
        "a permission has no entity"
    );
    // Header: the identifier twice, and a verification id.
    assert_eq!(
        why(&raw_macaroon(
            &header_of(&[field(2, &info), field(2, &info)]),
            &[]
        )),
        "a field appears twice"
    );
    assert_eq!(
        why(&raw_macaroon(
            &header_of(&[field(2, &info), field(4, b"v")]),
            &[]
        )),
        "its identifier section is wrong"
    );
    // A caveat with no identifier.
    assert_eq!(
        why(&raw_macaroon(
            &header_of(&[field(2, &info)]),
            &[field(1, b"lnd"), vec![0]].concat()
        )),
        "a caveat has no text"
    );
    // A ten-byte length that is a valid number but far longer than the file.
    let mut huge = vec![2u8, 2];
    huge.extend_from_slice(&[0xff; 9]);
    huge.push(1);
    assert_eq!(why(&huge), "a field is longer than the file");
    // A ten-byte number that overflows 64 bits.
    let mut overflow = vec![2u8, 2];
    overflow.extend_from_slice(&[0xff; 9]);
    overflow.push(2);
    assert_eq!(why(&overflow), W_NUM);
    // Overlong (non-canonical) field number and length.
    let mut field_no = vec![2u8, 0x82, 0x00, info.len() as u8];
    field_no.extend_from_slice(&info);
    field_no.push(0);
    assert_eq!(why(&raw_macaroon(&field_no[1..], &[])), W_NUM);
    let mut length = vec![2u8, 2, 0x80 | info.len() as u8, 0x00];
    length.extend_from_slice(&info);
    length.push(0);
    assert_eq!(why(&raw_macaroon(&length[1..], &[])), W_NUM);
}

#[test]
fn a_uri_permission_with_no_actions_is_still_refused() {
    assert_eq!(
        macaroon::check(&mac(&[("uri", &[])])),
        Err(MacaroonRefusal::UncheckablePermissions)
    );
    assert_eq!(
        macaroon::check(&mac(&[("info", &["read"]), ("uri", &[])])),
        Err(MacaroonRefusal::UncheckablePermissions)
    );
}

fn wrapped(text: &str, width: usize, newline: &str) -> String {
    text.as_bytes()
        .chunks(width)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(newline)
}

#[test]
fn whitespace_around_and_inside_hex_is_accepted() {
    let m = mac(&[("info", &["read"])]);
    let h = hex(&m);
    for text in [
        format!("{h}\n"),
        format!("{h}\r\n"),
        format!("{h} \n\n"),
        wrapped(&h, 60, "\n"),
        format!("{}\n", wrapped(&h, 60, "\n")),
        format!("{}\r\n", wrapped(&h, 60, "\r\n")),
    ] {
        assert!(macaroon::check(text.as_bytes()).is_ok(), "{text:?}");
    }
    // Only whitespace is not a macaroon.
    assert!(matches!(
        macaroon::check(b"\n\n"),
        Err(MacaroonRefusal::Malformed { .. })
    ));
    // A binary macaroon is never trimmed: a signature may end in a newline byte.
    let mut binary = m.clone();
    *binary.last_mut().unwrap() = b'\n';
    assert!(macaroon::check(&binary).is_ok());
    // And stray bytes after it are still refused.
    binary.push(b'\n');
    assert!(matches!(
        macaroon::check(&binary),
        Err(MacaroonRefusal::Malformed { .. })
    ));
}

#[test]
fn messages_say_what_info_read_is_and_say_also_only_when_it_is_true() {
    let phrase = "reads your node's status and the public network graph; nothing that touches funds or channels";
    for ops in [
        admin_ops(),
        readonly_ops(),
        vec![("info", &["write"][..])],
        vec![("offchain", &["read"][..])],
        vec![("info", &["read"][..]), ("offchain", &["read"][..])],
        vec![],
    ] {
        let text = macaroon::check(&mac(&ops))
            .expect_err("refused")
            .to_string();
        assert!(text.contains(phrase), "{text}");
        assert!(!text.contains("version"), "{text}");
    }
    let without = macaroon::check(&mac(&[("offchain", &["read"])]))
        .expect_err("refused")
        .to_string();
    assert!(!without.contains("also"), "{without}");
    assert!(without.contains("offchain:read"), "{without}");
    let with = macaroon::check(&mac(&[("info", &["read"]), ("offchain", &["read"])]))
        .expect_err("refused")
        .to_string();
    assert!(with.contains("also"), "{with}");
}

#[test]
fn the_oversize_message_counts_hex_text() {
    let text = MacaroonRefusal::Oversize.to_string();
    assert!(
        text.contains("over 4 KiB of text (about 2 KiB of macaroon in hex)"),
        "{text}"
    );
}

#[test]
fn an_accepted_macaroon_says_its_signature_is_not_checked() {
    let ok = macaroon::check(&mac(&[("info", &["read"])])).expect("accepted");
    assert!(
        ok.note().contains(
            "Guard Dog can't verify the signature; it reads the permissions the macaroon claims, and LND checks the signature when it's used"
        ),
        "{}",
        ok.note()
    );
}

// ---------------------------------------------------------------- runes

#[test]
fn the_getinfo_rune_is_accepted_padded_or_not() {
    assert!(rune_ok("=0&method=getinfo&pnum=0"));
    assert!(rune_ok("=7-1&method=getinfo&pnum=0"));
    assert!(rune_ok("=0&pnum=0&method=getinfo"));
}

#[test]
fn trailing_whitespace_on_a_rune_is_trimmed() {
    let text = rune_text("=0&method=getinfo&pnum=0", false);
    for tail in ["\n", "\r\n", " \n", "\n\n"] {
        assert!(
            rune::check(format!("{text}{tail}").as_bytes()).is_ok(),
            "{tail:?}"
        );
    }
    // Whitespace inside is still refused.
    let (a, b) = text.split_at(10);
    assert!(matches!(
        rune::check(format!("{a}\n{b}").as_bytes()),
        Err(RuneRefusal::Malformed { .. })
    ));
}

#[test]
fn an_unrestricted_rune_is_refused() {
    assert_eq!(rune_err(""), RuneRefusal::Unrestricted);
    assert_eq!(rune_err("=0"), RuneRefusal::Unrestricted);
    assert!(
        RuneRefusal::Unrestricted
            .to_string()
            .contains("can do anything on your node")
    );
}

#[test]
fn a_rune_with_only_ids_is_refused_with_its_own_message() {
    for text in ["=0&=1", "=0&=1-2&=3"] {
        let err = rune_err(text);
        assert_eq!(err, RuneRefusal::OnlyIds, "{text}");
        assert!(
            err.to_string()
                .contains("its only restrictions are ids, so Guard Dog can't tell what it allows"),
            "{err}"
        );
    }
}

#[test]
fn a_missing_restriction_is_refused_with_its_own_message() {
    assert_eq!(
        rune_err("=0&method=getinfo"),
        RuneRefusal::NotLimitedToNoParameters
    );
    assert!(
        RuneRefusal::NotLimitedToNoParameters
            .to_string()
            .contains("can call getinfo with parameters")
    );
    assert_eq!(rune_err("=0&pnum=0"), RuneRefusal::NotLimitedToGetinfo);
    assert!(
        RuneRefusal::NotLimitedToGetinfo
            .to_string()
            .contains("not limited to getinfo")
    );
}

#[test]
fn any_alternative_is_refused() {
    assert_eq!(
        rune_err("=0&method=getinfo|method=listfunds&pnum=0"),
        RuneRefusal::Alternatives
    );
    assert_eq!(
        rune_err("=0&method=getinfo&pnum=0|pnum=1"),
        RuneRefusal::Alternatives
    );
    assert_eq!(
        rune_err("=0|=1&method=getinfo&pnum=0"),
        RuneRefusal::Alternatives
    );
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
        // An id anywhere but first.
        "method=getinfo&=0&pnum=0",
        "method=getinfo&pnum=0&=0",
        "=0&method=getinfo&pnum=0&=1",
        // Near misses of the id and the two restrictions.
        "=&method=getinfo&pnum=0",
        "=0-&method=getinfo&pnum=0",
        "=-1&method=getinfo&pnum=0",
        "=0-1-2&method=getinfo&pnum=0",
        "=0&Method=getinfo&pnum=0",
        "=0&method=getinfo &pnum=0",
        "=0&method=getinfo&pnum=00",
    ] {
        let err = rune_err(text);
        assert_eq!(err, RuneRefusal::UncheckableRestrictions, "{text}");
        let shown = format!("{err} {err:?}");
        assert!(
            shown.contains("has restrictions Guard Dog can't check"),
            "{shown}"
        );
        assert!(
            !shown.contains("listfunds") && !shown.contains("time"),
            "{shown}"
        );
    }
}

#[test]
fn any_backslash_is_refused_because_the_rune_is_decided_on_raw_bytes() {
    for text in [
        "=\\0&method=getinfo&pnum=0",
        "=0&meth\\od=getinfo&pnum=0",
        "=0&method=\\getinfo&pnum=0",
        "=0&method=getinfo\\|pnum=0",
        "=0&method=getinfo\\&pnum=0",
        "=0&method=getinfo&pnum=0\\",
        "\\",
    ] {
        let err = rune_err(text);
        assert_eq!(err, RuneRefusal::Backslash, "{text}");
        assert!(
            err.to_string()
                .contains("can't check restrictions containing a backslash"),
            "{err}"
        );
    }
}

#[test]
fn bad_base64_and_sizes_are_refused() {
    let good = rune_text("=0&method=getinfo&pnum=0", false);
    let (a, b) = good.split_at(20);
    for bad in [
        good.replacen('A', "*", 1),
        format!("{a} {b}"),
        format!("{a}\n{b}"),
        good.replace('-', "+"),
        format!("{good}=="),
    ] {
        if bad != good {
            assert!(
                matches!(
                    rune::check(bad.as_bytes()),
                    Err(RuneRefusal::Malformed { .. })
                ),
                "{bad}"
            );
        }
    }
    assert!(matches!(
        rune::check(b"abcd!"),
        Err(RuneRefusal::Malformed { .. })
    ));
    assert!(matches!(
        rune::check(b"a"),
        Err(RuneRefusal::Malformed { .. })
    ));
    assert!(matches!(
        rune::check(b""),
        Err(RuneRefusal::Malformed { .. })
    ));
    // Fewer than 32 bytes decoded.
    assert!(matches!(
        rune::check(b"AAAA"),
        Err(RuneRefusal::Malformed { .. })
    ));
    assert_eq!(rune::check(&vec![b'A'; 1025]), Err(RuneRefusal::Oversize));
    assert!(matches!(
        rune::check(&vec![b'A'; 1024]),
        Err(RuneRefusal::Malformed { .. })
    ));
    assert!(matches!(
        rune::check(&[0xff, 0xfe]),
        Err(RuneRefusal::Malformed { .. })
    ));
}

#[test]
fn every_rune_truncation_is_refused_and_never_panics() {
    for restrictions in ["=0&method=getinfo&pnum=0", "=0&pnum=0&method=getinfo"] {
        for pad in [false, true] {
            let text = rune_text(restrictions, pad);
            for cut in 0..text.trim_end_matches('=').len() {
                assert!(
                    rune::check(&text.as_bytes()[..cut]).is_err(),
                    "cut at {cut} of {text}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------- bitcoind

struct Stub {
    replies: Vec<CanaryReply>,
    calls: Vec<String>,
}

impl CanaryRpc for Stub {
    fn call(&mut self, method: &str) -> CanaryReply {
        self.calls.push(method.to_string());
        let i = (self.calls.len() - 1).min(self.replies.len() - 1);
        self.replies[i]
    }
}

type Run = (Result<bitcoind::NarrowLogin, BitcoindRefusal>, Vec<String>);

/// The same reply to every call.
fn run_bitcoind(user: &str, reply: CanaryReply) -> Run {
    run_sequence(user, &[reply])
}

/// Replies are given one per call; the last one repeats.
fn run_sequence(user: &str, replies: &[CanaryReply]) -> Run {
    let mut stub = Stub {
        replies: replies.to_vec(),
        calls: Vec::new(),
    };
    let result = bitcoind::check(user, &mut stub);
    (result, stub.calls)
}

const CALL_ORDER: [&str; 5] = [
    "getnetworkinfo",
    "getblockchaininfo",
    "getblockcount",
    "getbestblockhash",
    "uptime",
];

const OK: CanaryReply = CanaryReply::Status(200);
const NO: CanaryReply = CanaryReply::Status(403);
const BAD_PASSWORD: CanaryReply = CanaryReply::Status(401);

/// A properly whitelisted login: the two needed calls work, the canaries get 403.
fn whitelisted() -> [CanaryReply; 5] {
    [OK, OK, NO, NO, NO]
}

#[test]
fn a_whitelisted_login_is_accepted_after_the_exact_calls_in_order() {
    let (result, calls) = run_sequence("guarddog", &whitelisted());
    assert_eq!(calls, CALL_ORDER);
    let note = result.expect("accepted").note();
    assert!(note.contains("can't read your rpcwhitelist line"), "{note}");
    assert!(note.contains("getnetworkinfo,getblockchaininfo"), "{note}");
    assert!(note.contains("extra methods would still pass"), "{note}");
}

#[test]
fn a_blanket_403_is_refused_because_the_needed_calls_fail_too() {
    // Everything 403: an rpcallowip or proxy refusal, or a whitelist of spending methods only.
    let (result, calls) = run_bitcoind("guarddog", NO);
    let err = result.expect_err("blanket 403");
    assert_eq!(err, BitcoindRefusal::CannotReadWhatItNeeds);
    assert_eq!(calls, ["getnetworkinfo"]);
    assert!(
        err.to_string()
            .contains("this login can't read what Guard Dog needs"),
        "{err}"
    );
    // One of the two needed calls refused.
    let (result, calls) = run_sequence("guarddog", &[OK, NO, NO, NO, NO]);
    assert_eq!(result, Err(BitcoindRefusal::CannotReadWhatItNeeds));
    assert_eq!(calls, ["getnetworkinfo", "getblockchaininfo"]);
}

#[test]
fn a_failed_needed_call_stops_everything_after_it() {
    for (replies, expect, count) in [
        (vec![BAD_PASSWORD], BitcoindRefusal::WrongPassword, 1),
        (vec![OK, BAD_PASSWORD], BitcoindRefusal::WrongPassword, 2),
        (
            vec![CanaryReply::Status(500)],
            BitcoindRefusal::CouldNotProve,
            1,
        ),
        (
            vec![CanaryReply::NoReply],
            BitcoindRefusal::CouldNotProve,
            1,
        ),
        (
            vec![OK, CanaryReply::NoReply],
            BitcoindRefusal::CouldNotProve,
            2,
        ),
        (
            vec![OK, CanaryReply::Status(404)],
            BitcoindRefusal::CouldNotProve,
            2,
        ),
    ] {
        let (result, calls) = run_sequence("guarddog", &replies);
        assert_eq!(result, Err(expect), "{replies:?}");
        assert_eq!(calls.len(), count, "{replies:?}");
    }
}

#[test]
fn the_first_canary_that_is_not_403_stops_the_calls() {
    let cases = [
        (vec![OK, OK, OK], BitcoindRefusal::TooWide, 3),
        (vec![OK, OK, NO, OK, NO], BitcoindRefusal::TooWide, 4),
        (vec![OK, OK, NO, NO, OK], BitcoindRefusal::TooWide, 5),
        (
            vec![OK, OK, NO, BAD_PASSWORD],
            BitcoindRefusal::WrongPassword,
            4,
        ),
        (
            vec![OK, OK, NO, NO, CanaryReply::NoReply],
            BitcoindRefusal::CouldNotProve,
            5,
        ),
        (
            vec![OK, OK, CanaryReply::Status(500)],
            BitcoindRefusal::CouldNotProve,
            3,
        ),
        (
            vec![OK, OK, CanaryReply::Status(204)],
            BitcoindRefusal::CouldNotProve,
            3,
        ),
    ];
    for (replies, expect, count) in cases {
        let (result, calls) = run_sequence("guarddog", &replies);
        assert_eq!(result, Err(expect), "{replies:?}");
        assert_eq!(calls, CALL_ORDER[..count], "{replies:?}");
    }
}

#[test]
fn a_200_refuses_and_names_the_fix() {
    let (result, _) = run_sequence("guarddog", &[OK]);
    let err = result.expect_err("200");
    assert_eq!(err, BitcoindRefusal::TooWide);
    let text = err.to_string();
    assert!(
        text.contains("rpcwhitelist=<user>:getnetworkinfo,getblockchaininfo"),
        "{text}"
    );
    assert!(text.contains("rpcwhitelistdefault=0"), "{text}");
}

#[test]
fn a_401_means_the_password_is_wrong() {
    let (result, _) = run_bitcoind("guarddog", BAD_PASSWORD);
    let err = result.expect_err("401");
    assert_eq!(err, BitcoindRefusal::WrongPassword);
    assert!(err.to_string().contains("password"));
}

#[test]
fn only_harmless_read_only_methods_are_ever_called() {
    let mut all = Vec::new();
    for replies in [
        vec![OK],
        vec![NO],
        vec![BAD_PASSWORD],
        vec![CanaryReply::NoReply],
        whitelisted().to_vec(),
        vec![OK, OK, NO, OK],
    ] {
        all.extend(run_sequence("guarddog", &replies).1);
    }
    for call in all {
        assert!(CALL_ORDER.contains(&call.as_str()), "{call}");
    }
}

#[test]
fn the_cookie_login_is_refused_before_any_call() {
    let (result, calls) = run_sequence("__cookie__", &whitelisted());
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
    for reply in [
        CanaryReply::Status(200),
        CanaryReply::Status(401),
        CanaryReply::Status(403),
        CanaryReply::Status(500),
        CanaryReply::NoReply,
    ] {
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
        for (index, secret) in secrets.iter().enumerate().filter(|(_, s)| s.len() >= 8) {
            // Failure messages name the canary by index only, so a failing
            // test never prints a credential-shaped value (CodeQL
            // rust/cleartext-logging).
            assert!(
                !text.contains(secret.as_str()),
                "a shown message contains canary #{index}"
            );
        }
    }

    // Needles from every offset: each 8-byte window of every credential, raw,
    // as hex and as base64.
    let mut credentials: Vec<Vec<u8>> = vec![
        RUNE_STATE.to_vec(),
        hex(&RUNE_STATE).into_bytes(),
        b64url(&RUNE_STATE, false).into_bytes(),
        NONCE.to_vec(),
        STORAGE_ID.to_vec(),
        hex(NONCE).into_bytes(),
        hex(STORAGE_ID).into_bytes(),
        b64url(NONCE, false).into_bytes(),
        b64url(STORAGE_ID, false).into_bytes(),
        b"svc_canary_user".to_vec(),
    ];
    for input in &inputs {
        credentials.push(input.clone());
        credentials.push(hex(input).into_bytes());
        credentials.push(b64url(input, false).into_bytes());
    }
    for input in &rune_inputs {
        credentials.push(input.clone().into_bytes());
    }
    // The fixed permission names are ordinary words that messages may use.
    let vocabulary = format!(
        "{} read write generate info:read macaroon:generate",
        ENTITIES.join(" ")
    );
    let needles: std::collections::BTreeSet<Vec<u8>> = credentials
        .iter()
        .flat_map(|c| c.windows(8).map(<[u8]>::to_vec))
        .filter(|w| !contains(vocabulary.as_bytes(), w))
        .collect();
    assert!(needles.len() > 500);
    for (shown_index, text) in shown.iter().enumerate() {
        for (needle_index, needle) in needles.iter().enumerate() {
            assert!(
                !contains(text.as_bytes(), needle),
                "shown message #{shown_index} contains credential window #{needle_index}"
            );
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
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// What a macaroon that decodes to exactly `info:read` must contain, and what
/// it must not: a check written separately from the decoder.
fn looks_like_info_read(bytes: &[u8]) -> bool {
    contains(bytes, b"\x0a\x04info\x12\x04read")
        && !contains(bytes, b"write")
        && !contains(bytes, b"uri")
}

/// The same for runes, on the restriction text.
fn is_the_allowed_rune_text(text: &str) -> bool {
    let parts: Vec<&str> = text.split('&').collect();
    let id = |s: &str| {
        let Some(rest) = s.strip_prefix('=') else {
            return false;
        };
        let digits = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
        match rest.split_once('-') {
            Some((a, b)) => digits(a) && digits(b),
            None => digits(rest),
        }
    };
    let mut rest: Vec<&str> = parts.iter().skip(1).copied().collect();
    rest.sort_unstable();
    parts.len() == 3 && id(parts[0]) && rest == ["method=getinfo", "pnum=0"]
}

const OP_POOL: [(&str, &str); 9] = [
    ("info", "read"),
    ("info", "write"),
    ("offchain", "read"),
    ("onchain", "read"),
    ("invoices", "read"),
    ("macaroon", "generate"),
    ("mystery", "read"),
    ("peers", "write"),
    ("uri", "/lnrpc.Lightning/GetInfo"),
];

const RUNE_POOL: [&str; 9] = [
    "method=getinfo",
    "pnum=0",
    "method=listfunds",
    "time<123",
    "method=getinfo|pnum=0",
    "pnum=1",
    "=1",
    "=0",
    "method^get",
];

const RUNE_ALPHABET: &str = "methodgetinfopnum0123456789&|=\\!/^$~<>{}#-";

/// One random edit of a byte string: flip, insert, delete or truncate.
fn mutate(bytes: &mut Vec<u8>, kind: u8, at: usize, value: u8) {
    match kind % 4 {
        0 => {
            if let Some(len) = bytes.len().checked_sub(1) {
                bytes[at % (len + 1)] ^= value | 1;
            }
        }
        1 => bytes.insert(at % (bytes.len() + 1), value),
        2 => {
            if !bytes.is_empty() {
                bytes.remove(at % bytes.len());
            }
        }
        _ => bytes.truncate(at % (bytes.len() + 1)),
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn arbitrary_bytes_never_panic_and_rarely_pass_the_macaroon_decoder(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        if macaroon::check(&bytes).is_ok() {
            prop_assert!(looks_like_info_read(&bytes));
        }
        let _ = macaroon::check(hex(&bytes).as_bytes());
    }

    #[test]
    fn mutated_valid_macaroons_never_panic_and_pass_only_as_info_read(
        edits in proptest::collection::vec((any::<u8>(), any::<usize>(), any::<u8>()), 1..6),
        caveats in 0usize..3,
    ) {
        let caveat_bytes: Vec<&[u8]> = (0..caveats).map(|_| &b"time-before 2030"[..]).collect();
        let mut m = macaroon_bytes(&lnd_id(&[("info", &["read"])]), &caveat_bytes, &[]);
        for (kind, at, value) in edits {
            mutate(&mut m, kind, at, value);
        }
        if macaroon::check(&m).is_ok() {
            prop_assert!(looks_like_info_read(&m));
        }
        // The same bytes as hex text, wrapped, are judged the same.
        let plain = macaroon::check(&m).is_ok();
        let text = wrapped(&hex(&m), 60, "\n");
        if !m.is_empty() && m.first() == Some(&2) {
            prop_assert_eq!(macaroon::check(text.as_bytes()).is_ok(), plain);
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic_and_only_url_safe_text_passes_the_rune_decoder(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        if rune::check(&bytes).is_ok() {
            prop_assert!(bytes.iter().all(|b| B64.contains(b) || *b == b'=' || matches!(*b, b' ' | b'\t' | b'\r' | b'\n')));
        }
    }

    #[test]
    fn random_restriction_text_passes_exactly_when_it_is_the_allowed_one(
        chars in proptest::collection::vec(proptest::sample::select(RUNE_ALPHABET.chars().collect::<Vec<_>>()), 0..60),
        pad in any::<bool>(),
    ) {
        let text: String = chars.into_iter().collect();
        let result = rune::check(rune_text(&text, pad).as_bytes());
        prop_assert_eq!(result.is_ok(), is_the_allowed_rune_text(&text), "{}", text);
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
    fn a_rune_passes_exactly_when_its_restrictions_are_the_id_then_the_two_allowed_ones(picks in proptest::collection::vec(0..RUNE_POOL.len(), 0..5), pad in any::<bool>()) {
        let text = picks.iter().map(|i| RUNE_POOL[*i]).collect::<Vec<_>>().join("&");
        let result = rune::check(rune_text(&text, pad).as_bytes());
        prop_assert_eq!(result.is_ok(), is_the_allowed_rune_text(&text), "{}", text);
    }
}

// ---------------------------------------------------------------- uri and live checks

#[test]
fn a_uri_permission_is_never_accepted() {
    for ops in [
        vec![("uri", &["/lnrpc.Lightning/GetInfo"][..])],
        vec![
            ("info", &["read"][..]),
            ("uri", &["/lnrpc.Lightning/GetInfo"][..]),
        ],
        vec![("info", &["read"][..]), ("uri", &["write"][..])],
    ] {
        let err = macaroon::check(&mac(&ops)).expect_err("uri");
        assert_eq!(err, MacaroonRefusal::UncheckablePermissions, "{ops:?}");
        assert!(err.to_string().contains("can't check"), "{err}");
        assert!(!err.to_string().contains("GetInfo"));
    }
}

/// Live checks run only when `GD_LAB=1` (the nightly lab run sets it). They
/// read the lab's own login files, written by `lab/up.sh`; nothing is committed.
/// With `GD_LAB=1` a missing file fails the test.
fn lab_file(name: &str) -> Option<Vec<u8>> {
    if std::env::var("GD_LAB").as_deref() != Ok("1") {
        eprintln!("GD_LAB is not 1; skipping the live check of {name}");
        return None;
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../lab/.data/creds")
        .join(name);
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(err) => panic!("GD_LAB=1 but lab/.data/creds/{name} could not be read: {err}"),
    }
}

#[test]
fn real_lab_macaroon_decodes() {
    let Some(bytes) = lab_file("lnd-info-read.macaroon.hex") else {
        return;
    };
    let ok = macaroon::check(&bytes);
    assert!(
        ok.is_ok(),
        "the lab's info:read macaroon was refused: {ok:?}"
    );
}

#[test]
fn real_lab_rune_decodes() {
    let Some(bytes) = lab_file("cln-getinfo.rune") else {
        return;
    };
    let ok = rune::check(&bytes);
    assert!(ok.is_ok(), "the lab's getinfo rune was refused: {ok:?}");
}
