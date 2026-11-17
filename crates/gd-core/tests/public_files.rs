//! Public files must hold no details of the machine they were written on.
//!
//! Every git-tracked text file is scanned line by line for home paths, temp
//! paths, a pasted `id -G` group list, this machine's host and user name, and
//! email addresses. Each refusal names `file:line`. The checker is a plain
//! function so a second test can feed it planted strings.
//!
//! The planted strings in this file are built from pieces, so this file does
//! not trip its own checker.

// Helpers in a test file are not covered by clippy.toml's test exemption; a panic here is a failed test.
#![allow(clippy::indexing_slicing, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// Tracked files that are skipped on purpose. Empty: no fixture has needed it.
/// Add `(path, reason)` only for a deliberately synthetic file that would
/// false-positive, and say why.
const SKIP_FILES: &[(&str, &str)] = &[];

/// Names allowed after `/home/`: placeholders and the service users the lab
/// and the test fixtures already use (`lab/compose.yml`, `gd-egress` tests).
const ALLOWED_HOME_NAMES: &[&str] = &["user", "bitcoin", "admin", "umbrel"];

/// Names allowed after `/Users/`: none. Any real-looking name is refused.
const ALLOWED_USERS_NAMES: &[&str] = &[];

/// Email addresses that are allowed, each public by design.
/// `you@yourwallet.com` is the placeholder in the website's example;
/// `jack@greensock.com` is the author contact inside the vendored GSAP
/// licence header; `git@github.com` is the standard ssh clone address.
const ALLOWED_EMAILS: &[&str] = &[
    "you@yourwallet.com",
    "jack@greensock.com",
    "git@github.com",
    "noreply@anthropic.com",
    "noreply@github.com",
];

/// Email domains that are allowed whatever the name: GitHub's noreply
/// addresses and the reserved example domains.
const ALLOWED_EMAIL_DOMAINS: &[&str] = &[
    "users.noreply.github.com",
    "example.com",
    "example.org",
    "example.net",
];

/// Host or user names that are too common to count as a leak.
const COMMON_NAMES: &[&str] = &[
    "root",
    "runner",
    "user",
    "admin",
    "ubuntu",
    "debian",
    "docker",
    "build",
    "builder",
    "github",
    "localhost",
    "bitcoin",
    "umbrel",
    "nobody",
    "test",
    "guest",
    "ci",
    "linuxkit",
];

/// What this machine calls itself, read once from the environment.
struct Identity {
    names: Vec<String>,
}

impl Identity {
    fn from_environment() -> Self {
        let mut raw = Vec::new();
        for key in ["HOSTNAME", "USER", "LOGNAME"] {
            if let Ok(value) = std::env::var(key) {
                raw.push(value);
            }
        }
        // macOS does not export HOSTNAME; ask the system for it.
        if std::env::var("HOSTNAME").is_err()
            && let Ok(out) = Command::new("hostname").output()
        {
            raw.push(String::from_utf8_lossy(&out.stdout).trim().to_string());
        }
        Self::from_names(raw)
    }

    /// Keep names of 4+ characters that are not common words. A host name
    /// like `box.local` also yields its first label, `box`, when long enough.
    fn from_names(raw: Vec<String>) -> Self {
        let mut names = Vec::new();
        for value in raw {
            let lower = value.trim().to_lowercase();
            let first = lower.split('.').next().unwrap_or("").to_string();
            for candidate in [lower, first] {
                if candidate.chars().count() >= 4
                    && !COMMON_NAMES.contains(&candidate.as_str())
                    && !names.contains(&candidate)
                {
                    names.push(candidate);
                }
            }
        }
        Self { names }
    }
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')
}

/// Every refusal found in one line, as plain-English reasons.
fn check_line(line: &str, who: &Identity) -> Vec<String> {
    let mut found = Vec::new();
    home_paths(line, &mut found);
    temp_paths(line, &mut found);
    group_list(line, &mut found);
    machine_names(line, who, &mut found);
    emails(line, &mut found);
    found
}

fn home_paths(line: &str, found: &mut Vec<String>) {
    for (marker, allowed) in [
        (concat!("/Us", "ers/"), ALLOWED_USERS_NAMES),
        (concat!("/ho", "me/"), ALLOWED_HOME_NAMES),
    ] {
        for (at, _) in line.match_indices(marker) {
            // `docs/home/x` is a relative path, not a home directory.
            if line[..at].chars().next_back().is_some_and(is_name_char) {
                continue;
            }
            let name: String = line[at + marker.len()..]
                .chars()
                .take_while(|c| is_name_char(*c))
                .collect();
            if name.is_empty() || allowed.contains(&name.as_str()) {
                continue;
            }
            found.push(format!("home path {marker}{name}"));
        }
    }
}

fn temp_paths(line: &str, found: &mut Vec<String>) {
    for marker in [
        concat!("/private/", "var/folders/"),
        concat!("/var/", "folders/"),
        concat!("/private/", "tmp/claude-"),
    ] {
        if line.contains(marker) {
            found.push(format!("local temp path {marker}"));
        }
    }
}

/// Eight or more small whole numbers in a row, single-space separated, look
/// like the output of `id -G`. Dotted versions such as `0.17.0` do not count.
fn group_list(line: &str, found: &mut Vec<String>) {
    let mut run = 0;
    let mut longest = 0;
    for token in line.split(' ') {
        let small =
            !token.is_empty() && token.len() <= 3 && token.bytes().all(|b| b.is_ascii_digit());
        run = if small { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    if longest >= 8 {
        found.push(format!(
            "run of {longest} small numbers, like an `id -G` group list"
        ));
    }
}

fn machine_names(line: &str, who: &Identity, found: &mut Vec<String>) {
    let lower = line.to_lowercase();
    for name in &who.names {
        for (at, _) in lower.match_indices(name.as_str()) {
            let before = lower[..at].chars().next_back();
            let after = lower[at + name.len()..].chars().next();
            // Whole words only, so a short name inside a longer word is fine.
            if before.is_some_and(|c| c.is_alphanumeric())
                || after.is_some_and(|c| c.is_alphanumeric())
            {
                continue;
            }
            found.push("this machine's host or user name".to_string());
            break;
        }
    }
}

fn emails(line: &str, found: &mut Vec<String>) {
    let bytes = line.as_bytes();
    for (at, _) in line.match_indices('@') {
        let mut start = at;
        while start > 0
            && (bytes[start - 1].is_ascii_alphanumeric() || b"._%+-".contains(&bytes[start - 1]))
        {
            start -= 1;
        }
        let mut end = at + 1;
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric() || b".-".contains(&bytes[end]))
        {
            end += 1;
        }
        let domain = line[at + 1..end].trim_end_matches(['.', '-']);
        let tld_is_letters = domain
            .rsplit_once('.')
            .is_some_and(|(_, tld)| tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic()));
        if start == at || !tld_is_letters {
            continue; // `@types/node`, `pkg@1.2.3`, a bare `@`
        }
        let address = format!("{}@{}", &line[start..at], domain).to_lowercase();
        if ALLOWED_EMAILS.contains(&address.as_str())
            || ALLOWED_EMAIL_DOMAINS.contains(&domain.to_lowercase().as_str())
        {
            continue;
        }
        found.push(format!("email address {address}"));
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn tracked_files(root: &Path) -> Vec<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .output()
        .expect("git must be installed to list the tracked files");
    assert!(
        out.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
        .split(|b| *b == 0)
        .filter(|name| !name.is_empty())
        .map(|name| String::from_utf8_lossy(name).into_owned())
        .collect()
}

#[test]
fn public_files_hold_no_local_details() {
    let root = repo_root();
    let who = Identity::from_environment();
    let mut refusals = Vec::new();
    let mut scanned = 0;
    for path in tracked_files(&root) {
        if SKIP_FILES.iter().any(|(skip, _)| *skip == path) {
            continue;
        }
        let Ok(bytes) = std::fs::read(root.join(&path)) else {
            continue; // a tracked file deleted in the working tree
        };
        if bytes.contains(&0) {
            continue; // binary
        }
        let Ok(text) = String::from_utf8(bytes) else {
            continue; // not text
        };
        scanned += 1;
        for (index, line) in text.lines().enumerate() {
            for reason in check_line(line, &who) {
                refusals.push(format!("{path}:{}: {reason}", index + 1));
            }
        }
    }
    assert!(
        scanned > 50,
        "only {scanned} text files scanned; is the file list wrong?"
    );
    assert!(
        refusals.is_empty(),
        "local details in public files:\n{}",
        refusals.join("\n")
    );
}

#[test]
fn the_checker_catches_planted_details_and_leaves_ordinary_text_alone() {
    let who = Identity::from_names(vec![
        "Zorbax-Mac.local".to_string(),
        "zorbaxuser".to_string(),
        "root".to_string(),
    ]);
    assert_eq!(who.names, ["zorbax-mac.local", "zorbax-mac", "zorbaxuser"]);

    let caught = [
        format!("see {}alice/Projects/x", concat!("/Us", "ers/")),
        format!("cd {}bob/node", concat!("/ho", "me/")),
        format!(
            "export DIR={}T/tmp.abc",
            concat!("/private/", "var/folders/zz/0123")
        ),
        format!(
            "{}-501/-Users-x/scratch",
            concat!("/private/", "tmp/claude")
        ),
        format!("{}7/x", concat!("/var/", "folders/")),
        "groups: 20 12 61 79 80 81 98 33 100".to_string(),
        "uid 501 20 12 61 79 80 81 98 33 100 204 250".to_string(),
        "written on Zorbax-Mac".to_string(),
        "host zorbax-mac.local up".to_string(),
        "user=zorbaxuser".to_string(),
        "contact max@private-mail.org please".to_string(),
        "mail: Someone.Else+tag@gmail.com.".to_string(),
    ];
    for line in &caught {
        assert!(
            !check_line(line, &who).is_empty(),
            "planted detail not caught: {line}"
        );
    }

    let fine = [
        "TLS 1.3 only",
        "tested on Bitcoin Core 0.17.0 0.18.4 0.19.2 0.20.1 0.21.2 22.0 23.0 24.0",
        "versions 1 2 3 4 5 6 7",
        "run 20 12 61 79 80 81 98 only seven then text",
        "docs/home/index.html and crates/ho/me",
        concat!(
            "volume /ho",
            "me/bitcoin/.bitcoin and ",
            "/ho",
            "me/user and ",
            "/ho",
            "me/admin"
        ),
        concat!("placeholder /Us", "ers/<name>/ and ", "/ho", "me/<you>"),
        "email you@yourwallet.com or jack@greensock.com",
        "git@github.com:MaxSikorski/guard-dog.git",
        "12345+max@users.noreply.github.com and a@example.com",
        "import @types/node and serde@1.0.200",
        "the Zorbaxes are not Zorbax-Macs, nor ZORBAXUSERS",
        "root runs this as root",
    ];
    for line in fine {
        assert!(
            check_line(line, &who).is_empty(),
            "ordinary text refused: {line}: {:?}",
            check_line(line, &who)
        );
    }
}
