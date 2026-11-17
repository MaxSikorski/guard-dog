//! Public files must hold no details of the machine they were written on.
//!
//! Every git-tracked file is scanned line by line (a symlink by its target
//! text). Two kinds of check run, kept apart:
//!
//! - `check_line` is deterministic and reads no environment: home paths, temp
//!   paths, a pasted `id -G` group list, email addresses.
//! - `check_identity` looks for this machine's own host and user name. The
//!   identity is passed in, so the self-test uses made-up ones.
//!
//! Each refusal names `file:line`. The planted strings in this file are built
//! from pieces, so the file does not trip its own checker; the real file walk
//! covers this file too.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Tracked files skipped on purpose. Empty: nothing has needed it. Add
/// `(path, reason)` only for a deliberately synthetic file that would
/// false-positive.
const SKIP_FILES: &[(&str, &str)] = &[];

/// Names allowed after the Linux home folder prefix: placeholders and the
/// service users the lab and the test fixtures already use
/// (`lab/compose.yml`, the `gd-egress` tests).
const ALLOWED_HOME_NAMES: &[&str] = &["user", "bitcoin", "admin", "umbrel"];

/// Names allowed after the macOS or Windows users folder prefix: none.
const ALLOWED_USERS_NAMES: &[&str] = &[];

/// Names allowed after the root home prefix: the lightning data folders inside
/// the lab's containers (`lab/compose.yml`), which are not this machine's.
const ALLOWED_ROOT_NAMES: &[&str] = &[".lnd", ".lightning"];

/// Names allowed after the tilde home prefix: none.
const ALLOWED_TILDE_NAMES: &[&str] = &[];

/// Email addresses allowed, each public by design: the website's placeholder,
/// the author contact in the vendored GSAP licence header, the ssh clone
/// address, and noreply addresses.
const ALLOWED_EMAILS: &[&str] = &[
    "you@yourwallet.com",
    "jack@greensock.com",
    "git@github.com",
    "noreply@anthropic.com",
    "noreply@github.com",
];

/// Email domains allowed whatever the name.
const ALLOWED_EMAIL_DOMAINS: &[&str] = &[
    "users.noreply.github.com",
    "example.com",
    "example.org",
    "example.net",
];

/// Host or user names too common to count as a leak.
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

/// What this machine calls itself. Passed in, never read by the checks.
struct Identity {
    names: Vec<String>,
}

impl Identity {
    /// Keep names of 4+ characters that are not common words. A host name like
    /// `box.local` also yields its first label.
    fn from_names(raw: &[String]) -> Self {
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
        Self::from_names(&raw)
    }
}

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')
}

/// The deterministic checks. Reads no environment.
fn check_line(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    home_paths(line, &mut found);
    temp_paths(line, &mut found);
    group_list(line, &mut found);
    emails(line, &mut found);
    found
}

/// Name characters right after `at`.
fn name_at(text: &str, at: usize) -> String {
    text.get(at..)
        .unwrap_or("")
        .chars()
        .take_while(|c| is_name_char(*c))
        .collect()
}

/// Report a path marker followed by a real-looking name, matched without
/// regard to case. A marker glued to a longer word (`docs/home/x`) is a
/// relative path, not a home folder; `file://localhost/...` is a home folder.
fn report_after(line: &str, marker: &str, allowed: &[&str], found: &mut Vec<String>) {
    // ASCII lowercasing keeps every byte offset, so odd Unicode cannot hide a line.
    let lower = line.to_ascii_lowercase();
    for (at, _) in lower.match_indices(marker.to_ascii_lowercase().as_str()) {
        let before = lower.get(..at).unwrap_or("");
        if before.chars().next_back().is_some_and(is_name_char) && !before.ends_with("localhost") {
            continue;
        }
        let name = name_at(line, at + marker.len());
        if name.is_empty() || allowed.contains(&name.to_lowercase().as_str()) {
            continue;
        }
        found.push(format!("home path {marker}{name}"));
    }
}

fn home_paths(line: &str, found: &mut Vec<String>) {
    report_after(line, concat!("/Us", "ers/"), ALLOWED_USERS_NAMES, found);
    report_after(line, concat!("/ho", "me/"), ALLOWED_HOME_NAMES, found);
    report_after(line, concat!("/ro", "ot/"), ALLOWED_ROOT_NAMES, found);
    // Windows, single backslashes and the doubled ones of JSON.
    report_after(line, concat!("\\Us", "ers\\"), ALLOWED_USERS_NAMES, found);
    report_after(line, concat!("\\Us", "ers\\\\"), ALLOWED_USERS_NAMES, found);
    // URL-encoded.
    report_after(line, concat!("%2FUs", "ers%2F"), ALLOWED_USERS_NAMES, found);
    report_after(line, concat!("%2Fho", "me%2F"), ALLOWED_HOME_NAMES, found);
    // Tilde form, after a space, quote or the start of the line.
    for (at, _) in line.match_indices("~/") {
        if line
            .get(..at)
            .and_then(|s| s.chars().next_back())
            .is_some_and(is_name_char)
        {
            continue;
        }
        let name = name_at(line, at + 2);
        if !name.is_empty() && !ALLOWED_TILDE_NAMES.contains(&name.as_str()) {
            found.push(format!("home path ~/{name}"));
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

/// Is `text` eight or more whole numbers of 1 to 5 digits, single-space
/// separated, that are not one strictly consecutive run (`22 23 24 ...` is a
/// list of versions, not group ids)?
fn looks_like_group_list(text: &str) -> bool {
    let mut numbers = Vec::new();
    for token in text.trim().split(' ') {
        match token.parse::<u32>() {
            Ok(n)
                if !token.is_empty()
                    && token.len() <= 5
                    && token.bytes().all(|b| b.is_ascii_digit()) =>
            {
                numbers.push(n);
            }
            _ => return false,
        }
    }
    let steps: Vec<i64> = numbers
        .windows(2)
        .map(|w| match w {
            [a, b] => i64::from(*b) - i64::from(*a),
            _ => 0,
        })
        .collect();
    let consecutive = steps.iter().all(|s| *s == 1) || steps.iter().all(|s| *s == -1);
    numbers.len() >= 8 && !consecutive
}

/// Group lists like the output of `id -G`: the whole line, or the whole
/// contents of a backtick, quote, bracket or parenthesis span, is 8 or more
/// numbers (see `looks_like_group_list`). A Rust byte string `b"..."` is
/// data, not a group list. Dotted versions such as `0.17.0` never count.
fn group_list(line: &str, found: &mut Vec<String>) {
    let mut hit = looks_like_group_list(line);
    for (open, close) in [('`', '`'), ('"', '"'), ('\'', '\''), ('[', ']'), ('(', ')')] {
        let mut from = 0;
        while let Some(rel) = line.get(from..).and_then(|rest| rest.find(open)) {
            let start = from + rel + open.len_utf8();
            let Some(len) = line.get(start..).and_then(|rest| rest.find(close)) else {
                break;
            };
            let byte_string =
                open == '"' && line.get(..from + rel).is_some_and(|s| s.ends_with('b'));
            if !byte_string
                && line
                    .get(start..start + len)
                    .is_some_and(looks_like_group_list)
            {
                hit = true;
            }
            from = start + len + close.len_utf8();
        }
    }
    if hit {
        found.push("a run of 8 or more small numbers, like an `id -G` group list".to_string());
    }
}

#[allow(clippy::indexing_slicing)] // every index is guarded by the loop bounds
fn emails(line: &str, found: &mut Vec<String>) {
    let bytes = line.as_bytes();
    for (at, _) in line.match_indices('@') {
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
        if !tld_is_letters {
            continue; // `@types/node`, `pkg@1.2.3`, a bare `@`
        }
        let local = if at > 0 && bytes[at - 1] == b'"' {
            // A quoted local part: "name"@host, where a backslash escapes the
            // next character, so an escaped quote does not open or close it.
            let mut open = None;
            let mut i = at - 1;
            while i > 0 {
                i -= 1;
                if bytes[i] == b'"' {
                    let slashes = bytes[..i].iter().rev().take_while(|b| **b == b'\\').count();
                    if slashes % 2 == 0 {
                        open = Some(i);
                        break;
                    }
                }
            }
            open.map_or("", |open| &line[open + 1..at - 1])
        } else {
            let mut start = at;
            while start > 0
                && (bytes[start - 1].is_ascii_alphanumeric()
                    || b"._%+-".contains(&bytes[start - 1]))
            {
                start -= 1;
            }
            &line[start..at]
        };
        if local.is_empty() {
            continue;
        }
        let address = format!("{local}@{domain}").to_lowercase();
        if ALLOWED_EMAILS.contains(&address.as_str())
            || ALLOWED_EMAIL_DOMAINS.contains(&domain.to_lowercase().as_str())
        {
            continue;
        }
        found.push(format!("email address {address}"));
    }
}

/// This machine's names. In a path (a word holding a slash or backslash) the
/// name is found even inside a longer segment; in prose only as a whole word.
fn check_identity(line: &str, who: &Identity) -> Vec<String> {
    let mut found = Vec::new();
    let lower = line.to_lowercase();
    for name in &who.names {
        for token in lower.split_whitespace() {
            let in_path = token.contains('/') || token.contains('\\');
            let hit = token.match_indices(name.as_str()).any(|(at, _)| {
                let before = token.get(..at).and_then(|s| s.chars().next_back());
                let after = token.get(at + name.len()..).and_then(|s| s.chars().next());
                let whole = !before.is_some_and(char::is_alphanumeric)
                    && !after.is_some_and(char::is_alphanumeric);
                whole || in_path
            });
            if hit {
                found.push("this machine's host or user name".to_string());
                break;
            }
        }
    }
    found
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `(is_symlink, path)` for every tracked file.
#[allow(clippy::expect_used, clippy::panic)] // no git, or a line we cannot read, means no test; say so
fn tracked_files(root: &Path) -> Vec<(bool, String)> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z", "-s"])
        .output()
        .expect("git must be installed to list the tracked files");
    assert!(
        out.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut files = Vec::new();
    for entry in out.stdout.split(|b| *b == 0).filter(|e| !e.is_empty()) {
        let text = String::from_utf8_lossy(entry);
        // `<mode> <hash> <stage>\t<path>`
        let Some((meta, path)) = text.split_once('\t') else {
            panic!("unexpected git ls-files line: {text}");
        };
        files.push((meta.starts_with("120000"), path.to_string()));
    }
    files
}

/// The text to scan for one tracked file: its contents, or a symlink's target.
/// `Ok(None)` for binary files and for files git lists but the working tree
/// has deleted; any other read error is a failure naming the path.
fn text_of(root: &Path, path: &str, is_link: bool) -> Result<Option<String>, String> {
    let full = root.join(path);
    if is_link {
        return match std::fs::read_link(&full) {
            Ok(target) => Ok(Some(target.to_string_lossy().into_owned())),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{path}: cannot read the symlink: {e}")),
        };
    }
    match std::fs::read(&full) {
        Ok(bytes) if bytes.contains(&0) => Ok(None),
        Ok(bytes) => Ok(String::from_utf8(bytes).ok()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{path}: cannot read the file: {e}")),
    }
}

/// Scan the whole tracked tree; returns the files scanned and one string per refusal.
fn scan_tree(root: &Path, who: &Identity) -> (usize, Vec<String>) {
    let mut refusals = Vec::new();
    let mut scanned = 0;
    for (is_link, path) in tracked_files(root) {
        if SKIP_FILES.iter().any(|(skip, _)| *skip == path) {
            continue;
        }
        let text = match text_of(root, &path, is_link) {
            Ok(Some(text)) => text,
            Ok(None) => continue,
            Err(failure) => {
                refusals.push(failure);
                continue;
            }
        };
        scanned += 1;
        for (index, line) in text.lines().enumerate() {
            for reason in check_line(line)
                .into_iter()
                .chain(check_identity(line, who))
            {
                refusals.push(format!("{path}:{}: {reason}", index + 1));
            }
        }
    }
    (scanned, refusals)
}

#[test]
fn public_files_hold_no_local_details() {
    let who = Identity::from_environment();
    if who.names.is_empty() {
        eprintln!(
            "NOTE: no usable host or user name found in the environment; the machine-name check did NOT run."
        );
        assert!(
            std::env::var_os("GD_REQUIRE_IDENTITY").is_none(),
            "GD_REQUIRE_IDENTITY is set but no host or user name could be read"
        );
    }
    let (scanned, refusals) = scan_tree(&repo_root(), &who);
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

/// `count` numbers, `first`, `first + step`, ..., as one space-separated string.
fn numbers(count: u32, first: u32, step: u32) -> String {
    (0..count)
        .map(|i| (first + i * step).to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn the_checker_catches_planted_details_and_leaves_ordinary_text_alone() {
    // Synthetic identities, built from pieces so nothing here is a real name.
    let host = ["zor", "bax-mac.local"].concat();
    let login = ["zor", "baxuser"].concat();
    let short_host = ["zor", "bax-mac"].concat();
    let who = Identity::from_names(&[host.clone(), login.clone(), "root".to_string()]);
    assert_eq!(who.names, [host.clone(), short_host.clone(), login.clone()]);

    let alias = ["al", "ice"].concat();
    let slash = ["/", "Users", "/"].concat();
    let home = ["/", "home", "/"].concat();
    let root = ["/", "root", "/"].concat();
    let private = ["/private", "/var/", "folders/"].concat();
    let mail_host = ["private", "-mail.org"].concat();
    let win = ["Us", "ers"].concat();

    // Deterministic checks: each must be caught with no identity at all.
    let planted_deterministic = [
        format!("see {slash}{alias}/Projects/x"),
        format!("cd {home}{alias}/node"),
        format!("ls {root}{alias}/keys"),
        format!("cd ~/{alias}/keys"),
        format!("open ~/{}/x", "Projects"),
        format!("C:\\{win}\\{alias}\\Desktop"),
        format!("\"C:\\\\{win}\\\\{alias}\\\\x\""),
        format!("https://h/?p=%2F{win}%2F{alias}%2Fx"),
        format!("https://h/?p=%2f{}%2f{alias}", win.to_lowercase()),
        format!("file://localhost{slash}{alias}/x"),
        format!("file://{slash}{alias}/x"),
        format!("export DIR={private}zz/0123"),
        format!("{}-501/x", ["/private", "/tmp/claude"].concat()),
        format!("{}7/x", ["/var/", "folders/"].concat()),
        numbers(9, 20, 7),
        ["20", "12", "61", "79", "80", "81", "98", "701"].join(" "),
        format!(
            "`{}`",
            ["20", "12", "61", "79", "80", "81", "98", "701"].join(" ")
        ),
        format!("\u{212A}{slash}{alias}/x"),
        format!("\"{alias}\\\"\"@{mail_host}"),
        format!("`{}`", numbers(8, 12, 3)),
        format!("[{}]", numbers(10, 100, 1111)),
        format!("\"{}\"", numbers(8, 65500, 4)),
        format!("contact {alias}@{mail_host} please"),
        format!("mail: Some.Else+tag@{}.", ["gm", "ail.com"].concat()),
        format!("\"{alias}\"@{mail_host}"),
        format!("{{\"to\": \"{alias}@{mail_host}\"}}"),
    ];
    for line in &planted_deterministic {
        assert!(
            !check_line(line).is_empty(),
            "planted detail not caught: {line}"
        );
    }

    // Identity checks.
    let planted_identity = [
        format!("written on {short_host}"),
        format!("host {host} up"),
        format!("user={login}"),
        format!("/tmp/backup{login}2/report"),
        format!("C:\\data\\{login}-old\\x"),
        format!("{} up", host.to_uppercase()),
    ];
    for line in &planted_identity {
        assert!(
            !check_identity(line, &who).is_empty(),
            "planted name not caught: {line}"
        );
    }

    // Ordinary text: neither check may flag it.
    let fine = [
        "TLS 1.3 only".to_string(),
        "tested on Bitcoin Core 0.17.0 0.18.4 0.19.2 0.20.1 0.21.2 22.0 23.0 24.0".to_string(),
        format!("seven numbers: {}", numbers(7, 20, 7)),
        format!("eight but dotted: {}", numbers(8, 0, 1).replace(' ', ".0 ")),
        format!("six digits are not groups: {}", numbers(9, 100_000, 1)),
        "docs/home/index.html and crates/ho/me and a/root/b".to_string(),
        "mkdir -p /srv/data and ~ and ~/ alone".to_string(),
        format!("volume {home}bitcoin/.bitcoin and {home}user and {home}admin and {home}umbrel/x"),
        format!("tmpfs {root}.lnd and {root}.lightning"),
        format!("placeholder {slash}<name>/ and {home}<you>/ and C:\\{win}\\%USERNAME%\\x"),
        "email you@yourwallet.com or jack@greensock.com".to_string(),
        "git@github.com:Owner/repo.git".to_string(),
        "12345+x@users.noreply.github.com and a@example.com".to_string(),
        "import @types/node and serde@1.0.200 and @media".to_string(),
        format!(
            "the {}es are not {short_host}s, nor {}S",
            &login[..6],
            login.to_uppercase()
        ),
        "root runs this as root".to_string(),
        format!("let bytes = [{}];", numbers(12, 0, 1).replace(' ', ", ")),
        format!("supported versions: `{}`", numbers(8, 22, 1)),
        format!("let x = b\"{}\";", numbers(9, 0, 7)),
    ];
    for line in &fine {
        assert!(
            check_line(line).is_empty(),
            "ordinary text refused: {line}: {:?}",
            check_line(line)
        );
        assert!(
            check_identity(line, &who).is_empty(),
            "ordinary text names the machine: {line}"
        );
    }
}

#[test]
fn symlink_targets_are_text_and_only_a_missing_file_is_forgiven() {
    let dir = std::env::temp_dir().join(format!("gd-public-files-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap_or_default();
    let target = ["/Us", "ers/x/y"].concat();
    #[cfg(unix)]
    {
        assert!(std::os::unix::fs::symlink(&target, dir.join("link")).is_ok());
        let text = text_of(&dir, "link", true);
        assert_eq!(text, Ok(Some(target.clone())));
        assert!(!check_line(&target).is_empty());
        // Listed by git but deleted in the working tree: skipped.
        assert_eq!(text_of(&dir, "gone", true), Ok(None));
        assert_eq!(text_of(&dir, "gone", false), Ok(None));
        // A directory where a file should be is a real read error: it names the path.
        assert!(std::fs::create_dir_all(dir.join("sub")).is_ok());
        let failure = text_of(&dir, "sub", false);
        assert!(failure.is_err_and(|m| m.starts_with("sub:")));
    }
    std::fs::remove_dir_all(&dir).unwrap_or_default();
}
