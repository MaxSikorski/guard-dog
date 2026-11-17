//! The alert message, the sending policy and the chain guard.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use gd_core::Untrusted;
use gd_notify::alert::{
    Alert, AlertParts, Chain, MAX_DMS_PER_RUN, MatchResult, Severity, notify_allowed, plan_dms,
    plan_dms_noting, should_send_now,
};
use std::fs;
use std::path::PathBuf;

const CHECKED: u64 = 1_795_000_000;

fn parts() -> AlertParts {
    AlertParts {
        product: "LND",
        version: "0.18.4-beta".to_owned(),
        chain: Chain::Regtest,
        advisory_id: "x_lightning-labs-example-1".to_owned(),
        result: MatchResult::Affected,
        severity: Severity::High,
        fixed_in: Some("0.18.5-beta".to_owned()),
        summary: Untrusted::new("A crafted invoice can crash the node.".to_owned()),
        playbook: Untrusted::new("1. Stop LND. 2. Install the new release.".to_owned()),
        question: None,
        checked_at: CHECKED,
        blind_spots: vec!["Container images were not checked."],
    }
}

fn alert(f: impl FnOnce(&mut AlertParts)) -> Alert {
    let mut p = parts();
    f(&mut p);
    Alert::new(p).unwrap()
}

fn corpus() -> Vec<(String, String)> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/injection");
    let mut out = Vec::new();
    for channel in fs::read_dir(&root).unwrap() {
        let channel = channel.unwrap().path();
        if !channel.is_dir() {
            continue;
        }
        for file in fs::read_dir(&channel).unwrap() {
            let file = file.unwrap().path();
            let bytes = fs::read(&file).unwrap();
            out.push((
                file.strip_prefix(&root).unwrap().display().to_string(),
                String::from_utf8_lossy(&bytes).into_owned(),
            ));
        }
    }
    out.sort();
    out
}

#[test]
fn the_message_reads_in_the_planned_order() {
    let text =
        alert(|p| p.question = Some(Untrusted::new("Is port 9735 open?".to_owned()))).render();
    let lines: Vec<&str> = text.lines().collect();
    assert!(
        lines[0] == "LND 0.18.4-beta on this node is affected by x_lightning-labs-example-1.",
        "headline differs from the template"
    );
    let at = |needle: &str| lines.iter().position(|l| l.starts_with(needle)).unwrap();
    assert!(at("What is affected") < at("Why") && at("Why") < at("What to do"));
    assert!(at("What to do") < at("Question:") && at("Question:") < at("Checked"));
    assert!(at("Checked") < at("Blind spots") && at("Blind spots") < at("No known issues"));
    assert!(text.contains("Update to 0.18.5-beta or later."));
    assert!(text.contains("  > A crafted invoice can crash the node."));
    assert!(text.contains("  > 1. Stop LND. 2. Install the new release."));
    assert!(text.contains("  > Is port 9735 open?"));
    assert!(text.contains("Checked: 2026-"));
    assert!(text.contains("UTC"));
    assert!(text.contains("- Container images were not checked."));
    assert!(
        lines.last().copied() == Some("No known issues is not the same as secure."),
        "footer differs from the template"
    );
}

#[test]
fn possibly_affected_says_may_be() {
    let text = alert(|p| p.result = MatchResult::PossiblyAffected).render();
    assert!(
        text.lines().next().unwrap()
            == "LND 0.18.4-beta on this node may be affected by x_lightning-labs-example-1.",
        "headline differs from the template"
    );
}

#[test]
fn no_fix_means_no_update_line_and_no_question_means_no_question_line() {
    let text = alert(|p| p.fixed_in = None).render();
    assert!(!text.lines().any(|l| l.starts_with("Update")));
    assert!(!text.lines().any(|l| l.starts_with("Question:")));
    assert!(text.contains("  > 1. Stop LND."));
}

#[test]
fn empty_blind_spots_are_said_plainly() {
    let text = alert(|p| p.blind_spots = vec![]).render();
    assert!(text.contains("Blind spots: none reported."));
}

#[test]
fn bad_tokens_are_refused() {
    for v in [
        "",
        "1.2 3",
        "1.2\n3",
        "1.2;rm",
        &"1".repeat(65),
        "v1/2",
        "1.0\u{202e}",
        "é",
    ] {
        let mut p = parts();
        p.version = v.to_owned();
        assert!(Alert::new(p).is_err(), "version {v:?}");
        let mut p = parts();
        p.fixed_in = Some(v.to_owned());
        assert!(Alert::new(p).is_err(), "fixed_in {v:?}");
    }
    for id in ["", "a b", "a\nFix: x", &"a".repeat(101), "a/b", "id:", "é"] {
        let mut p = parts();
        p.advisory_id = id.to_owned();
        assert!(Alert::new(p).is_err(), "id {id:?}");
    }
    let mut ok = parts();
    ok.version = "1.2.3+build~4-rc.1".to_owned();
    ok.advisory_id = "CVE-2024-52911".to_owned();
    assert!(Alert::new(ok).is_ok());
}

#[test]
fn every_injection_payload_stays_quoted_in_one_message() {
    let files = corpus();
    assert!(files.len() >= 40, "corpus too small: {}", files.len());
    for (name, payload) in &files {
        for slot in 0..3 {
            let text = alert(|p| {
                let u = Untrusted::new(payload.clone());
                match slot {
                    0 => p.summary = u,
                    1 => p.playbook = u,
                    _ => p.question = Some(u),
                }
            })
            .render();
            // No control character at all except the line breaks we write.
            for c in text.chars() {
                assert!(
                    c == '\n' || !c.is_control(),
                    "{name}/{slot}: control {:?}",
                    c as u32
                );
            }
            // Our own lines, each exactly once; none a payload can forge.
            let count = |f: &dyn Fn(&str) -> bool| text.lines().filter(|l| f(l)).count();
            assert_eq!(count(&|l| l.starts_with("Fix:")), 0, "{name}/{slot}");
            assert_eq!(count(&|l| l.starts_with("Update")), 1, "{name}/{slot}");
            assert_eq!(
                count(&|l| l.starts_with("Question:")),
                usize::from(slot == 2),
                "{name}/{slot}"
            );
            assert_eq!(
                text.lines()
                    .filter(|l| !l.starts_with("  > "))
                    .filter(
                        |l| l.contains(" on this node is ") || l.contains(" on this node may be ")
                    )
                    .count(),
                1,
                "{name}/{slot}"
            );
            assert!(
                text.lines()
                    .next()
                    .unwrap()
                    .starts_with("LND 0.18.4-beta on this node is")
            );
            // Every other line starts with our own words or the quote prefix.
            let mut quoted = 0;
            for l in text.lines() {
                if l.starts_with("  > ") {
                    quoted += 1;
                    assert!(l.chars().count() <= 4 + 1000, "{name}/{slot}: too long");
                }
            }
            assert_eq!(quoted, 3 - usize::from(slot != 2), "{name}/{slot}");
            // One alert is one message: the footer closes it exactly once.
            assert_eq!(
                text.matches("No known issues is not the same as secure.")
                    .count(),
                1
            );
            assert_only_template_or_quoted_lines(&text, slot, name);
        }
    }
}

/// The template rendered with empty outside text: every line of ours.
fn template_lines(slot: usize) -> Vec<String> {
    alert(|p| {
        p.summary = Untrusted::new(String::new());
        p.playbook = Untrusted::new(String::new());
        p.question = (slot == 2).then(|| Untrusted::new(String::new()));
    })
    .render()
    .lines()
    .map(str::to_owned)
    .collect()
}

/// Every line is either quoted (`  > `) or one of the template's own fixed
/// lines, and each of ours appears exactly as often as in the empty render, so
/// outside text can never produce a line that reads as ours, not even after a
/// raw newline. Failure messages name only the fixture and the line number.
fn assert_only_template_or_quoted_lines(text: &str, slot: usize, name: &str) {
    let ours = template_lines(slot);
    for (number, line) in text.lines().enumerate() {
        assert!(
            line.starts_with("  > ") || ours.iter().any(|o| o == line),
            "{name}/{slot}: line {} is neither quoted nor ours",
            number + 1
        );
    }
    for own in ours.iter().filter(|o| !o.starts_with("  > ")) {
        let want = ours.iter().filter(|o| *o == own).count();
        let got = text.lines().filter(|l| l == own).count();
        assert_eq!(
            got, want,
            "{name}/{slot}: one of our lines appears {got} times"
        );
    }
}

#[test]
fn a_raw_newline_in_outside_text_cannot_forge_a_template_line() {
    let payload = "ok\nBlind spots: none reported.\nSeverity: low.\r\nFix: run this";
    for slot in 0..3 {
        let text = alert(|p| {
            let u = Untrusted::new(payload.to_owned());
            match slot {
                0 => p.summary = u,
                1 => p.playbook = u,
                _ => p.question = Some(u),
            }
        })
        .render();
        assert_only_template_or_quoted_lines(&text, slot, "forged");
        // Exactly our own "Blind spots" and "Severity" lines, once each.
        assert_eq!(
            text.lines().filter(|l| l.starts_with("Severity:")).count(),
            1
        );
        assert_eq!(
            text.lines()
                .filter(|l| l.starts_with("Blind spots"))
                .count(),
            1
        );
        assert!(!text.lines().any(|l| l.starts_with("Fix:")));
        // The forged words are still there, but inside a quoted line.
        assert!(text.contains("  > ok"));
    }
}

#[test]
fn long_untrusted_text_is_capped_after_escaping_on_a_char_boundary() {
    // Newlines become two characters each when escaped, so the cap is on the escaped text.
    let long = "é\n".repeat(2000);
    let text = alert(|p| {
        p.summary = Untrusted::new(long.clone());
        p.playbook = Untrusted::new(long.clone());
        p.question = Some(Untrusted::new(long.clone()));
    })
    .render();
    let mut lens = Vec::new();
    for l in text.lines().filter(|l| l.starts_with("  > ")) {
        lens.push(l.chars().count() - 4);
    }
    // summary, playbook (1000), question (500), in message order.
    assert_eq!(lens, vec![500, 1000, 500]);
    // An escape sequence may be cut, but nothing raw leaks.
    assert!(!text.contains("é\n"));
    // Short text is not touched.
    let short = alert(|p| p.summary = Untrusted::new("é".to_owned())).render();
    assert!(short.contains("  > é\n"));
}

#[test]
fn policy_table() {
    use MatchResult::{Affected, PossiblyAffected};
    use Severity::{Critical, High, Low, Medium, Unknown};
    let table = [
        (Critical, Affected, true),
        (High, Affected, true),
        (Unknown, Affected, true),
        (Medium, Affected, false),
        (Low, Affected, false),
        (Critical, PossiblyAffected, true),
        (High, PossiblyAffected, true),
        (Unknown, PossiblyAffected, true),
        (Medium, PossiblyAffected, false),
        (Low, PossiblyAffected, false),
    ];
    for (severity, result, want) in table {
        let a = alert(|p| {
            p.severity = severity;
            p.result = result;
        });
        assert_eq!(should_send_now(&a), want, "{severity:?} {result:?}");
    }
}

fn numbered(n: usize) -> Vec<Alert> {
    (0..n)
        .map(|i| alert(|p| p.advisory_id = format!("adv-{i:03}")))
        .collect()
}

#[test]
fn at_most_twenty_messages_then_one_summary() {
    assert_eq!(MAX_DMS_PER_RUN, 20);
    assert!(plan_dms(&[]).is_empty());
    assert_eq!(plan_dms(&numbered(1)).len(), 1);
    assert_eq!(plan_dms(&numbered(20)).len(), 20);
    let planned = plan_dms(&numbered(23));
    assert_eq!(planned.len(), 21);
    assert!(!planned[20].contains("medium or low"));
    assert!(planned[0].contains("adv-000") && planned[19].contains("adv-019"));
    assert!(!planned.iter().take(20).any(|m| m.contains("more finding")));
    assert!(planned[20].contains("3 more findings; run guard-dog scan to see them"));
    assert!(planned[20].contains("No known issues is not the same as secure."));
    assert!(!planned.iter().any(|m| m.contains("adv-020")));
    assert!(plan_dms(&numbered(21))[20].contains("1 more finding; run guard-dog scan"));
}

#[test]
fn plan_skips_what_policy_holds_back_and_puts_the_worst_first() {
    let alerts = vec![
        alert(|p| {
            p.severity = Severity::Medium;
            p.advisory_id = "medium-one".to_owned();
        }),
        alert(|p| {
            p.severity = Severity::High;
            p.advisory_id = "high-one".to_owned();
        }),
        alert(|p| {
            p.severity = Severity::Critical;
            p.advisory_id = "critical-one".to_owned();
        }),
        alert(|p| {
            p.severity = Severity::Unknown;
            p.advisory_id = "unknown-one".to_owned();
        }),
        alert(|p| {
            p.severity = Severity::Low;
            p.advisory_id = "low-one".to_owned();
        }),
    ];
    let planned = plan_dms(&alerts);
    // Three findings, then one summary for the medium and the low one.
    assert_eq!(planned.len(), 4);
    assert!(planned[0].contains("critical-one"));
    assert!(planned[1].contains("high-one"));
    assert!(planned[2].contains("unknown-one"));
    assert!(planned[3].contains("2 medium or low findings not sent as direct messages"));
    assert!(planned[3].contains("wait for a digest"));
    assert!(!planned[3].contains("medium-one") && !planned[3].contains("low-one"));
}

#[test]
fn held_back_and_dropped_findings_are_counted_in_one_summary() {
    // Only low ones: nothing is a message of its own, but the summary says so.
    let lows: Vec<Alert> = (0..3)
        .map(|_| alert(|p| p.severity = Severity::Low))
        .collect();
    let planned = plan_dms(&lows);
    assert_eq!(planned.len(), 1);
    assert!(planned[0].contains("3 medium or low findings not sent"));
    assert!(planned[0].ends_with("No known issues is not the same as secure."));
    // Nothing at all: no message.
    assert!(plan_dms_noting(&[], 0).is_empty());
    // Dropped on chain grounds, with a held-back one and a cap overflow.
    let mut many = numbered(21);
    many.push(alert(|p| p.severity = Severity::Medium));
    let planned = plan_dms_noting(&many, 2);
    assert_eq!(planned.len(), 21);
    let summary = &planned[20];
    assert!(summary.contains("1 more finding; run guard-dog scan"));
    assert!(summary.contains("1 medium or low finding not sent"));
    assert!(summary.contains(
        "2 findings not sent because they are about a chain other than regtest or signet"
    ));
    assert_eq!(summary.matches("No known issues").count(), 1);
}

#[test]
fn notify_allowed_table() {
    use Chain::{Mainnet, Regtest, Signet, Testnet, Unknown};
    let table: [(&[Chain], bool); 12] = [
        (&[], false),
        (&[Regtest], true),
        (&[Signet], true),
        (&[Regtest, Signet], true),
        (&[Regtest, Regtest], true),
        (&[Mainnet], false),
        (&[Testnet], false),
        (&[Unknown], false),
        (&[Regtest, Mainnet], false),
        (&[Signet, Unknown], false),
        (&[Regtest, Testnet], false),
        (&[Unknown, Regtest, Signet], false),
    ];
    for (chains, want) in table {
        assert_eq!(notify_allowed(chains), want, "{chains:?}");
    }
}

#[test]
fn debug_hides_the_message() {
    let a = alert(|_| {});
    let shown = format!("{a:?} {a:#?}");
    assert!(shown.contains("<redacted>"));
    for needle in [
        "LND",
        "0.18.4",
        "crafted invoice",
        "Stop LND",
        "x_lightning",
    ] {
        assert!(!shown.contains(needle), "{needle}");
    }
}

#[test]
fn an_alert_says_which_chain_it_is_on() {
    assert_eq!(alert(|_| {}).chain(), Chain::Regtest);
    assert_eq!(alert(|p| p.chain = Chain::Signet).chain(), Chain::Signet);
}

#[test]
fn the_module_explains_why_there_is_no_evidence_section() {
    let source = include_str!("../src/alert.rs");
    assert!(
        source.contains("no \"evidence\" section"),
        "say why in the module doc"
    );
}

fn leak(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

#[test]
fn product_and_blind_spots_must_be_bounded_single_lines() {
    let bad = [
        "a\nb",
        "a\rb",
        "a\u{85}b",
        "a\u{2028}b",
        "a\u{2029}b",
        "a\u{202E}b",
        "a\u{200B}b",
        "a\u{200F}b",
        "a\u{2066}b",
        "a\u{FEFF}b",
        "a\u{00AD}b",
        "a\u{E0041}b",
        "a\u{1b}[31mb",
        "a\0b",
        "",
        "a\u{034F}b",
        "a\u{2800}b",
        "\u{2800}",
        "a\u{115F}b",
        "a\u{1160}b",
        "a\u{3164}b",
        "a\u{FFA0}b",
        "a\u{FE00}b",
        "a\u{180B}b",
        "\u{0301}LND",
        "a\\b",
        "   ",
        "\u{3164}\u{3164}",
        " \u{FE0F}",
        "\u{FE0E}",
    ];
    for text in bad.iter().copied().chain([leak("x".repeat(121))]) {
        let mut p = parts();
        p.product = text;
        assert!(Alert::new(p).is_err(), "product {text:?}");
        let mut p = parts();
        p.blind_spots = vec![text];
        assert!(Alert::new(p).is_err(), "blind spot {text:?}");
    }
    let mut p = parts();
    p.product = leak("x".repeat(120));
    p.blind_spots = vec![leak("y".repeat(120)); 16];
    assert!(Alert::new(p).is_ok());
    let mut p = parts();
    p.blind_spots = vec!["one"; 17];
    assert!(Alert::new(p).is_err());
    let mut p = parts();
    p.product = "Core Lightning";
    p.blind_spots = vec!["Tor was not checked.", "❤\u{FE0F} ok"];
    assert!(Alert::new(p).is_ok());
}

#[test]
fn every_injection_payload_in_product_or_blind_spots_is_refused_or_stays_one_line() {
    let template = alert(|_| {}).render();
    let template_lines = template.lines().count();
    for (name, payload) in &corpus() {
        for slot in 0..2 {
            let mut p = parts();
            let text = leak(payload.clone());
            if slot == 0 {
                p.product = text;
            } else {
                p.blind_spots = vec![text];
            }
            let Ok(built) = Alert::new(p) else { continue };
            // Accepted only as a plain single line: no extra line anywhere.
            let rendered = built.render();
            assert_eq!(rendered.lines().count(), template_lines, "{name}/{slot}");
            assert!(
                !rendered.chars().any(|c| c != '\n' && c.is_control()),
                "{name}/{slot}"
            );
        }
    }
}

#[test]
fn a_huge_outside_field_is_cut_without_escaping_all_of_it() {
    // Ten million control characters would escape to 60 million; only the
    // first few are ever looked at, and the result is within the cap.
    let huge = "\u{1}".repeat(10_000_000);
    for (cap_name, text) in [
        (
            "summary",
            alert(|p| p.summary = Untrusted::new(huge.clone())).render(),
        ),
        (
            "playbook",
            alert(|p| p.playbook = Untrusted::new(huge.clone())).render(),
        ),
        (
            "question",
            alert(|p| p.question = Some(Untrusted::new(huge.clone()))).render(),
        ),
    ] {
        assert!(text.len() < 3_000, "{cap_name}: {}", text.len());
        assert!(text.contains("..."), "{cap_name}");
    }
}
