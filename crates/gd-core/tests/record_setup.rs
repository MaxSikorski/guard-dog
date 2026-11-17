//! Tests for `tools/record-setup.sh`, the recorder that turns a real node into a
//! redacted recording for Judge A.
//!
//! What they prove: the recorder refuses secret-looking files, unsafe paths and
//! bad arguments before it makes anything; ignores its caller's `PATH`, curl
//! settings and proxies; reads only the three Docker list endpoints; keeps only
//! named, type-checked fields of every source (everything else is dropped);
//! removes every planted canary (a fake secret or identifier) of every class
//! from every output byte, log and message; gives the same output every time and
//! a no-op on a second pass; and deletes its output if a value survives anywhere.
//! Each finding of the two reviews of the first version is pinned by a
//! `regression_*` test with its concrete input.
//!
//! Deterministic: no network (the Docker daemon is a fake on a Unix socket), no
//! clock, the machine's own tools are replaced by stubs in a test folder, and the
//! property tests run on a fixed seed (`GD_PROPTEST_SEED` explores another).
#![cfg(unix)]
// Test-only crate: its helper functions (not just `#[test]` ones) read files and
// check data, and a panic there is a failed check. The workspace panic lints
// protect shipped code; clippy.toml exempts `#[test]` functions and code under `#[cfg(test)]`,
// but not these unannotated helpers.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Tokens the recorder must leave alone (they are what Phase 1's sensors read).
const MUST_KEEP: [&str; 15] = [
    "0.0.0.0:8333",
    "127.0.0.1:10009",
    "[::]:9735",
    "[::1]:8080",
    "sha256:4f2b8c1d9e7a3b5f60c2d4e6a8b0c1d3e5f70912a4b6c8d0e2f4a6b8c0d2e4f6",
    "v0.19.2-beta",
    "29.1",
    "0.4.8.16",
    "docker.io/lightninglabs/lnd",
    "git+https://github.com/hoytech/strfry.git",
    "umbrel-app.yml",
    "da1ec0de5ba11ad0c0ffee15deadbeef00c0ffee",
    "bitcoind.service",
    "lnd.service",
    "tor@default.service",
];
const MUST_KEEP_DPKG: &str = "openssl\t1.2.3.4\tii \n";
const DIGEST: &str = "4f2b8c1d9e7a3b5f60c2d4e6a8b0c1d3e5f70912a4b6c8d0e2f4a6b8c0d2e4f6";

const SECRET_CLASSES: [&str; 10] = [
    "pem-private-key",
    "xprv",
    "nsec",
    "wif-key",
    "macaroon",
    "seed-words",
    "secret-value",
    "bearer-token",
    "url-userinfo",
    "token",
];

fn repo_file(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .join(rel)
}

fn script() -> PathBuf {
    repo_file("tools/record-setup.sh")
}

fn find_tool(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| {
            p.is_file()
                && fs::metadata(p)
                    .map(|m| m.permissions().mode() & 0o111 != 0)
                    .unwrap_or(false)
        })
}

fn tool(name: &str) -> PathBuf {
    find_tool(name).unwrap_or_else(|| panic!("{name} is required for this test"))
}

/// `<target tmp>/rs/<test>/<case>`, removed and recreated.
fn work_dir(test: &str, case: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("rs")
        .join(test)
        .join(case);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_stub(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// A folder holding only the commands the script may use: symlinks to the real
/// ones, and stubs (with planted canaries in what they print) for the ones that
/// would otherwise show the real machine. The script reads it only in test mode.
fn bin_farm(dir: &Path) -> PathBuf {
    let farm = dir.join("bin");
    if farm.exists() {
        return farm;
    }
    fs::create_dir_all(&farm).unwrap();
    for name in [
        "perl", "curl", "mktemp", "rm", "mkdir", "chmod", "cat", "sort", "grep", "head", "wc",
        "find", "env", "timeout", "tr",
    ] {
        let real = if name == "timeout" {
            match find_tool(name) {
                Some(p) => p,
                None => continue,
            }
        } else {
            tool(name)
        };
        symlink(real, farm.join(name)).unwrap();
    }
    write_stub(
        &farm,
        "systemctl",
        "echo 'bitcoind.service loaded active running Bitcoin daemon'\n\
         echo 'node-monitor.service loaded active running Monitor for canaryhost-7q run by canaryuser at 45.150.150.150'",
    );
    write_stub(
        &farm,
        "dpkg-query",
        "printf 'libfoo1\\t1.2.3.4\\tii \\n'\nprintf 'contact-canaryuser\\t2.0\\tii \\n'",
    );
    write_stub(
        &farm,
        "ss",
        "echo 'LISTEN 0 4096 192.168.150.150:50002 0.0.0.0:*'\necho 'LISTEN 0 4096 45.150.150.151:9735 0.0.0.0:*'",
    );
    write_stub(&farm, "hostname", "echo canaryhost-7q");
    write_stub(
        &farm,
        "id",
        "case \"$1\" in\n  -un) echo canaryuser ;;\nesac",
    );
    farm
}

/// Stubs that record that they were run. If the script ever looked up a tool on
/// its caller's `PATH`, one of these would leave a `TRAP-<name>` file.
fn trap_dir(work: &Path) -> PathBuf {
    let dir = work.join("trap");
    if dir.exists() {
        return dir;
    }
    fs::create_dir_all(&dir).unwrap();
    for name in [
        "perl",
        "curl",
        "id",
        "hostname",
        "systemctl",
        "dpkg-query",
        "ss",
        "env",
        "find",
    ] {
        write_stub(
            &dir,
            name,
            &format!(": > '{}'", work.join(format!("TRAP-{name}")).display()),
        );
    }
    dir
}

fn assert_no_trap(work: &Path) {
    let traps: Vec<String> = fs::read_dir(work)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("TRAP-"))
        .collect();
    assert!(
        traps.is_empty(),
        "the script ran a tool from its caller's PATH: {traps:?}"
    );
}

/// A temporary copy of the script whose two marked lines point at the stub
/// tools. The shipped script has no switch for this.
fn test_copy(work: &Path, farm: &Path) -> PathBuf {
    let text = fs::read_to_string(script()).unwrap();
    let dirs = "TRUSTED_DIRS=\"/usr/sbin /usr/bin /sbin /bin\" # test-injection-point";
    let mode = "TEST_MODE=0 # test-injection-point";
    assert!(text.contains(dirs) && text.contains(mode));
    let patched = text
        .replacen(dirs, &format!("TRUSTED_DIRS=\"{}\"", farm.display()), 1)
        .replacen(mode, "TEST_MODE=1", 1);
    let path = work.join("record-setup-test-copy.sh");
    fs::write(&path, patched).unwrap();
    path
}

/// Runs the script with an empty environment, `PATH` pointing at the trap
/// folder, and the work folder as the current folder (so paths in messages
/// are short). With `test_mode` the stub tools are used (through a copy of the
/// script); without it the real script runs with its real trusted folders.
fn run_inner(work: &Path, args: &[&str], env: &[(&str, &str)], test_mode: bool) -> Output {
    let farm = bin_farm(work);
    let trap = trap_dir(work);
    let tmp = work.join("tmp");
    fs::create_dir_all(&tmp).unwrap();
    let script_path = if test_mode {
        test_copy(work, &farm)
    } else {
        script()
    };
    let mut cmd = Command::new(tool("bash"));
    cmd.arg(script_path)
        .args(args)
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", trap.display()))
        .env("TMPDIR", &tmp)
        .envs(env.iter().copied())
        .current_dir(work);
    cmd.output().unwrap()
}

fn run(work: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let out = run_inner(work, args, env, true);
    assert_no_trap(work);
    out
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

fn tmp_is_empty(work: &Path) -> bool {
    fs::read_dir(work.join("tmp")).unwrap().next().is_none()
}

fn list_files(dir: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, acc: &mut Vec<String>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        for entry in rd {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(base, &path, acc);
            } else {
                let rel = path.strip_prefix(base).unwrap();
                acc.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    let mut acc = Vec::new();
    walk(dir, dir, &mut acc);
    acc.sort();
    acc
}

fn all_output_text(dir: &Path) -> String {
    list_files(dir)
        .iter()
        .map(|f| String::from_utf8_lossy(&fs::read(dir.join(f)).unwrap()).into_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

fn write_file(base: &Path, rel: &str, content: &str) {
    let p = base.join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, content).unwrap();
}

fn read(work: &Path, rel: &str) -> String {
    fs::read_to_string(work.join(rel)).unwrap()
}

/// Asserts that none of `values` appears (case-insensitively) in any output
/// file, stdout or stderr.
fn assert_absent(work: &Path, out: &Output, values: &[&str]) {
    let everything =
        format!("{}\n{}", all_output_text(&work.join("out")), text(out)).to_lowercase();
    for v in values {
        assert!(
            !everything.contains(&v.to_lowercase()),
            "value survived: {v}"
        );
    }
}

/// Redacts a folder `in/` of recording files in the work folder.
fn redact_dir(work: &Path, files: &[(&str, &str)], terms: &[&str]) -> Output {
    for (name, content) in files {
        write_file(&work.join("in"), name, content);
    }
    let mut args = vec!["--redact-dir", "in", "--out", "out"];
    for t in terms {
        args.push("--redact-term");
        args.push(t);
    }
    run(work, &args, &[])
}

fn binaries(lines: &[&str]) -> String {
    format!("== /usr/local/bin/x\n{}\n", lines.join("\n"))
}

/// Same constant, same seed variable as `crates/gd-core/src/untrusted.rs`.
fn proptest_config(cases: u32) -> ProptestConfig {
    const DEFAULT_PROPTEST_SEED: u64 = 0x6764_5f70_726f_7074;
    static ANNOUNCE: std::sync::Once = std::sync::Once::new();
    let seed = std::env::var("GD_PROPTEST_SEED")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_PROPTEST_SEED);
    ANNOUNCE.call_once(|| eprintln!("GD_PROPTEST_SEED={seed} (property test seed in use)"));
    ProptestConfig {
        cases,
        rng_seed: proptest::test_runner::RngSeed::Fixed(seed),
        ..ProptestConfig::default()
    }
}

#[test]
fn record_setup_refuses_secret_files() {
    let work = work_dir("refuse", "names");
    const CANARY: &str = "CanarySecretFileContent4242";
    let names = [
        "seed.txt",
        "my-mnemonic",
        "admin.macaroon",
        "nsec.txt",
        "wallet.dat",
        ".env",
        "prod.env",
        "exports.sh",
        "hsm_secret",
        "channel.backup",
        "tls.key",
        "hs_ed25519_secret_key",
        "lnd.db",
        "lightningd.sqlite3",
        "id_ed25519",
        "rpcauth.txt",
        "password.txt",
        "cookie",
        "token.json",
        "secrets.json",
        "private.pem",
        "backup.tar",
        "keys.json",
        "shadow",
        "raspiblitz.setup",
        "credentials",
    ];
    assert_eq!(names.len(), 26);
    for name in names {
        fs::write(work.join(name), CANARY).unwrap();
        let reply = format!("bitcoin-core/getnetworkinfo={name}");
        let out = run(&work, &["--out", "out", "--reply", &reply], &[]);
        assert_eq!(code(&out), 2, "{name}: {}", text(&out));
        assert!(!work.join("out").exists(), "{name}: --out was created");
        assert!(!text(&out).contains(CANARY), "{name}: canary in output");
        assert!(tmp_is_empty(&work), "{name}: staging folder left behind");
    }

    // A symlink to a harmless file.
    fs::write(work.join("benign.txt"), "{}").unwrap();
    symlink(work.join("benign.txt"), work.join("reply.json")).unwrap();
    let args = [
        "--out",
        "out",
        "--reply",
        "bitcoin-core/getnetworkinfo=reply.json",
    ];
    let out = run(&work, &args, &[]);
    assert_eq!(code(&out), 2, "symlink: {}", text(&out));
    assert!(!work.join("out").exists());

    // A harmless file inside a folder with a refused name.
    fs::create_dir_all(work.join("wallet")).unwrap();
    fs::write(work.join("wallet/reply.json"), "{}").unwrap();
    let args = [
        "--out",
        "out",
        "--reply",
        "bitcoin-core/getnetworkinfo=wallet/reply.json",
    ];
    let out = run(&work, &args, &[]);
    assert_eq!(code(&out), 2, "folder name: {}", text(&out));
    assert!(!work.join("out").exists());

    // One byte over 1 MiB.
    fs::write(work.join("big.json"), vec![b' '; 1024 * 1024 + 1]).unwrap();
    let args = [
        "--out",
        "out",
        "--reply",
        "bitcoin-core/getnetworkinfo=big.json",
    ];
    let out = run(&work, &args, &[]);
    assert_eq!(code(&out), 2, "too big: {}", text(&out));
    assert!(!work.join("out").exists());
    assert!(tmp_is_empty(&work));
}

#[test]
fn record_setup_refuses_bad_arguments() {
    let work = work_dir("badargs", "all");
    fs::write(work.join("f"), "{}").unwrap();
    fs::create_dir_all(work.join("full")).unwrap();
    fs::write(work.join("full/x"), "x").unwrap();

    type Case<'a> = (&'a str, Vec<&'a str>);
    let cases: Vec<Case> = vec![
        ("output folder not empty", vec!["--out", "full"]),
        ("term too short", vec!["--out", "o", "--redact-term", "abc"]),
        (
            "term with spaces",
            vec!["--out", "o", "--redact-term", "a b c d"],
        ),
        (
            "service with dots",
            vec!["--out", "o", "--reply", "../x/getinfo=f"],
        ),
        ("unknown call", vec!["--out", "o", "--reply", "lnd/rm=f"]),
        (
            "upper-case service",
            vec!["--out", "o", "--reply", "LND/getinfo=f"],
        ),
        (
            "same reply twice",
            vec![
                "--out",
                "o",
                "--reply",
                "lnd/getinfo=f",
                "--reply",
                "lnd/getinfo=f",
            ],
        ),
        ("unknown option", vec!["--out", "o", "--bogus"]),
        ("no --out", vec!["--redact-term", "abcd"]),
    ];
    for (label, args) in cases {
        let out = run(&work, &args, &[]);
        assert_eq!(code(&out), 1, "{label}: {}", text(&out));
        assert!(tmp_is_empty(&work), "{label}: staging folder left behind");
        if label != "output folder not empty" {
            assert!(!work.join("o").exists(), "{label}: --out was created");
        }
    }
}

fn parse_canaries() -> Vec<(String, String)> {
    let raw = fs::read_to_string(repo_file("tests/synthetic/record-setup/CANARIES.txt")).unwrap();
    raw.lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let (class, value) = l.split_once(' ').unwrap();
            (class.to_string(), value.to_string())
        })
        .collect()
}

#[test]
fn record_setup_redacts_the_golden_example() {
    let work = work_dir("golden", "run");
    let raw = repo_file("tests/synthetic/record-setup/raw")
        .canonicalize()
        .unwrap();
    let expected = repo_file("tests/synthetic/record-setup/expected");
    let out = run(
        &work,
        &[
            "--redact-dir",
            raw.to_str().unwrap(),
            "--out",
            "out",
            "--redact-term",
            "canaryhost-7q",
            "--redact-term",
            "canaryuser",
        ],
        &[],
    );
    assert_eq!(code(&out), 3, "{}", text(&out));

    let got = list_files(&work.join("out"));
    let want = list_files(&expected);
    assert_eq!(got, want, "the output file list differs from expected/");
    for f in &want {
        let mut got_bytes = fs::read(work.join("out").join(f)).unwrap();
        let mut want_bytes = fs::read(expected.join(f)).unwrap();
        if f == "record-log.txt" {
            // The expected log was made by a normal run; here test mode is on.
            got_bytes = String::from_utf8(got_bytes)
                .unwrap()
                .replace("mode redact-dir test-tools", "mode redact-dir")
                .into_bytes();
            want_bytes = String::from_utf8(want_bytes).unwrap().into_bytes();
        }
        assert_eq!(got_bytes, want_bytes, "{f} differs from expected/");
    }

    let everything =
        format!("{}\n{}", all_output_text(&work.join("out")), text(&out)).to_lowercase();
    let canaries = parse_canaries();
    assert!(canaries.len() >= 30, "CANARIES.txt looks too short");
    for (class, value) in &canaries {
        assert!(
            !everything.contains(&value.to_lowercase()),
            "canary of class {class} survived"
        );
    }
    let kept = all_output_text(&work.join("out"));
    for token in MUST_KEEP {
        assert!(kept.contains(token), "must-keep token was removed: {token}");
    }
    assert!(
        kept.contains(MUST_KEEP_DPKG),
        "the dpkg version column changed"
    );
    assert!(tmp_is_empty(&work));
}

#[test]
fn self_check_deletes_a_leaky_output() {
    let work = work_dir("selfcheck", "run");
    // The address is in an allowed field once, and glued into a word once.
    let out = redact_dir(
        &work,
        &[
            (
                "ss-tlnp.txt",
                "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 4096 45.160.160.160:9735 0.0.0.0:*\n",
            ),
            (
                "binaries-version.txt",
                "== /usr/local/bin/x\nnode45.160.160.160z\n",
            ),
        ],
        &[],
    );
    assert_eq!(code(&out), 4, "{}", text(&out));
    assert!(
        list_files(&work.join("out")).is_empty(),
        "the output folder still holds files"
    );
    assert!(!text(&out).contains("45.160.160.160"));
    assert!(tmp_is_empty(&work));
}

struct FakeDocker {
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl FakeDocker {
    fn start(sock: &Path) -> FakeDocker {
        let _ = fs::remove_file(sock);
        let listener = UnixListener::bind(sock).unwrap();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (reqs, stopped) = (requests.clone(), stop.clone());
        let handle = thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        let mut head = Vec::new();
                        let mut buf = [0u8; 512];
                        while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 8192 {
                            match stream.read(&mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => head.extend_from_slice(&buf[..n]),
                            }
                        }
                        let head = String::from_utf8_lossy(&head).into_owned();
                        let line = head.lines().next().unwrap_or("").to_string();
                        reqs.lock().unwrap().push(line.clone());
                        let (status, body) = match line.as_str() {
                            "GET /version HTTP/1.1" => (
                                "200 OK",
                                r#"{"Version":"27.3.1","Os":"linux","Hostname":"canaryhost-7q"}"#,
                            ),
                            "GET /containers/json?all=true HTTP/1.1" => (
                                "200 OK",
                                r#"[{"Names":["/lnd"],"Image":"docker.io/lightninglabs/lnd:v0.19.2-beta","Command":"canaryuser","Ports":[{"IP":"45.150.150.150","PrivatePort":9735,"Type":"tcp"}]}]"#,
                            ),
                            "GET /images/json HTTP/1.1" => (
                                "200 OK",
                                r#"[{"RepoTags":["docker.io/lightninglabs/lnd:v0.19.2-beta"],"Owner":"canaryuser"}]"#,
                            ),
                            _ => ("403 Forbidden", r#"{"message":"forbidden"}"#),
                        };
                        let reply = format!(
                            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(reply.as_bytes());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        FakeDocker {
            requests,
            stop,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> Vec<String> {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            h.join().unwrap();
        }
        self.requests.lock().unwrap().clone()
    }
}

fn sock_path(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("rs");
    fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

#[test]
fn record_mode_reads_only_the_list_endpoints() {
    let work = work_dir("endpoints", "run");
    let sock = sock_path("s5.sock");
    let daemon = FakeDocker::start(&sock);

    let root = work.join("root");
    write_file(
        &root,
        "etc/tor/torrc",
        "SocksPort 9050\n# contact canaryowner@canarymail.com\n",
    );
    write_file(
        &root,
        "home/admin/_version.info",
        "codeVersion=\"1.12.1\"\n",
    );
    write_file(
        &root,
        "mnt/hdd/app-data/raspiblitz.conf",
        "network=bitcoin\nhostname=canaryhost-7q\n",
    );
    write_file(
        &root,
        "home/admin/raspiblitz.info",
        "baseimage=raspios_arm64\n",
    );
    write_file(
        &root,
        "home/umbrel/umbrel/app-data/bitcoin/umbrel-app.yml",
        "name: Bitcoin Node\nversion: \"29.1\"\n",
    );
    write_file(
        &root,
        "home/umbrel/umbrel/app-data/bitcoin/.env",
        "BITCOIN_PASS=CanaryEnvSecret9981\n",
    );
    write_file(&work, "reply.json", "{\"alias\":\"canaryhost-7q\"}\n");

    let out = run(
        &work,
        &[
            "--out",
            "out",
            "--root",
            root.to_str().unwrap(),
            "--docker-socket",
            sock.to_str().unwrap(),
            "--reply",
            "lnd/getinfo=reply.json",
        ],
        &[],
    );
    let requests = daemon.finish();
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(
        requests,
        vec![
            "GET /version HTTP/1.1",
            "GET /containers/json?all=true HTTP/1.1",
            "GET /images/json HTTP/1.1",
        ]
    );
    assert!(!requests.iter().any(|r| r.contains("DELETE")));

    let got = list_files(&work.join("out"));
    let want = vec![
        "apps/bitcoin/umbrel-app.yml",
        "docker-images.json",
        "docker-ps.json",
        "docker-version.json",
        "dpkg-query.txt",
        "raspiblitz-conf.txt",
        "raspiblitz-info.txt",
        "raspiblitz-version.txt",
        "record-log.txt",
        "replies/lnd/getinfo.json",
        "ss-tlnp.txt",
        "ss-ulnp.txt",
        "systemctl-list-units.txt",
        "torrc",
    ];
    assert_eq!(got, want);

    assert_absent(
        &work,
        &out,
        &[
            "canaryhost-7q",
            "canaryuser",
            "45.150.150.150",
            "45.150.150.151",
            "192.168.150.150",
            "canaryenvsecret9981",
            "canaryowner@canarymail.com",
        ],
    );
    let log = read(&work, "out/record-log.txt");
    assert!(
        log.contains("skipped binaries-version.txt root-not-slash"),
        "{log}"
    );
    assert!(log.contains("platform-hint raspiblitz"), "{log}");
    assert!(log.contains("mode record test-tools"), "{log}");
    assert!(log.starts_with("record-setup.sh format 2\n"), "{log}");
    assert!(tmp_is_empty(&work));
}

#[test]
fn raspiblitz_conf_keeps_only_switches() {
    let work = work_dir("conf", "run");
    let root = work.join("root");
    write_file(
        &root,
        "mnt/hdd/app-data/raspiblitz.conf",
        "network=bitcoin\n\
         chain=main\n\
         hostname=canarynode\n\
         lightning=lnd\n\
         lnd=on\n\
         notifyMailPass='canarymailpass99'\n\
         cl=\"off\"\n\
         notifyMailUser=canarymailuser\n\
         dropboxBackupTarget=CanaryDropboxToken123abc\n\
         BTCPayServer=on\n\
         telegrafInfluxPassword='canaryinflux'\n\
         telegrafInfluxUrl='http://192.168.150.151:8086'\n\
         sshtunnel='root@45.170.170.170:22'\n",
    );
    let out = run(
        &work,
        &[
            "--out",
            "out",
            "--root",
            root.to_str().unwrap(),
            "--docker-socket",
            "none.sock",
        ],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    let kept = read(&work, "out/raspiblitz-conf.txt");
    assert_eq!(
        kept,
        "network=bitcoin\nchain=main\nlightning=lnd\nlnd=on\ncl=\"off\"\nBTCPayServer=on\n"
    );
    let log = read(&work, "out/record-log.txt");
    assert!(
        log.contains("filtered raspiblitz-conf.txt kept 6 dropped 7"),
        "{log}"
    );
    assert_absent(
        &work,
        &out,
        &[
            "canarynode",
            "canarymailpass99",
            "canarymailuser",
            "canarydropboxtoken123abc",
            "canaryinflux",
            "192.168.150.151",
            "45.170.170.170",
        ],
    );
}

#[test]
fn record_setup_never_names_a_forbidden_endpoint() {
    let text = fs::read_to_string(script()).unwrap();
    for forbidden in [
        "inspect",
        "/archive",
        "/export",
        "/logs",
        "/top",
        "docker exec",
        "systemctl show",
        "systemctl cat",
        "sudo",
        "eval ",
        "source ",
        " . /",
        "id -u",
        "BEGIN TLDS",
    ] {
        assert!(
            !text.contains(forbidden),
            "the script contains {forbidden:?}"
        );
    }
    assert!(text.contains("exec /usr/bin/env -i"));
    assert!(!text.contains("GD_RECORD"), "a runtime override is back");
    assert!(!text.contains("SELFTEST"), "a runtime override is back");
    assert_eq!(text.matches("# test-injection-point").count(), 2);
    let curl_flags = "-q --request GET --proto =http --noproxy";
    assert_eq!(
        text.matches(curl_flags).count(),
        1,
        "the curl call must appear exactly once"
    );
    let docker_get = text.split("docker_get() {").nth(1).unwrap();
    let body = docker_get.split("\n}\n").next().unwrap();
    assert!(
        body.contains(curl_flags),
        "the curl call must be in docker_get"
    );
    let allowed = [
        "http://localhost/version",
        "http://localhost/containers/json?all=true",
        "http://localhost/images/json",
    ];
    let mut seen = BTreeSet::new();
    for scheme in ["http://", "https://"] {
        for (at, _) in text.match_indices(scheme) {
            let rest = &text[at..];
            let end = rest.find('"').unwrap_or(rest.len());
            let url = &rest[..end];
            assert!(
                allowed.contains(&url),
                "unexpected URL in the script: {url}"
            );
            seen.insert(url.to_string());
        }
    }
    assert_eq!(seen.len(), 3, "all three Docker URLs must be present");
}

#[test]
fn record_setup_passes_shellcheck() {
    let Some(shellcheck) = find_tool("shellcheck") else {
        if std::env::var_os("CI").is_some() && cfg!(target_arch = "x86_64") {
            panic!("shellcheck is required in CI on x86_64");
        }
        eprintln!("shellcheck not installed; skipped (brew install shellcheck)");
        return;
    };
    let out = Command::new(shellcheck)
        .args(["--shell=bash", "--severity=style"])
        .arg(script())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "shellcheck found problems:\n{}",
        text(&out)
    );
}

// ---------- regression tests: one per review finding ----------

/// Codex HIGH: a `perl` or `id` earlier on `PATH` bypassed the root check and
/// the redaction.
#[test]
fn regression_path_tools_are_ignored() {
    let work = work_dir("regress", "path");
    fs::create_dir_all(work.join("root")).unwrap();
    let root = work.join("root");
    let out = run(
        &work,
        &[
            "--out",
            "o",
            "--root",
            root.to_str().unwrap(),
            "--docker-socket",
            "none.sock",
        ],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_no_trap(&work);
    let log = read(&work, "o/record-log.txt");
    assert!(log.contains("test-tools"), "{log}");
    assert!(text(&out).contains("TEST MODE"), "{}", text(&out));

    // Without test mode the trusted folders are used, never the caller's PATH.
    if Path::new("/usr/bin/perl").exists() {
        let work2 = work_dir("regress", "path2");
        write_file(
            &work2.join("in"),
            "binaries-version.txt",
            "== /usr/local/bin/x\nip 45.1.2.3\n",
        );
        let out = run_inner(&work2, &["--redact-dir", "in", "--out", "out"], &[], false);
        assert_no_trap(&work2);
        assert_eq!(code(&out), 0, "{}", text(&out));
        assert!(!text(&out).contains("TEST MODE"));
        let log = read(&work2, "out/record-log.txt");
        assert!(!log.contains("test-tools"), "{log}");
    }
}

/// Codex HIGH: root was only refused through `id -u`; now bash's own `$EUID`.
#[cfg(target_os = "linux")]
#[test]
fn regression_root_is_refused_by_builtin() {
    let sudo_works = Command::new("sudo")
        .args(["-n", "true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !sudo_works {
        assert!(
            std::env::var_os("CI").is_none(),
            "sudo -n must work in CI for this test"
        );
        eprintln!("sudo -n does not work here; skipped");
        return;
    }
    let work = work_dir("regress", "root");
    let out = Command::new("sudo")
        .args(["-n", "/usr/bin/env", "-i", "/bin/bash"])
        .arg(script())
        .args(["--out", work.join("o").to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(code(&out), 1, "{}", text(&out));
    assert!(text(&out).contains("root"), "{}", text(&out));
    assert!(!work.join("o").exists());
}

/// Codex HIGH: `~/.curlrc` with `request = DELETE` and proxy settings.
#[test]
fn regression_curlrc_and_proxy_are_ignored() {
    let work = work_dir("regress", "curlrc");
    let home = work.join("home");
    write_file(
        &home,
        ".curlrc",
        "request = DELETE\nproxy = http://127.0.0.1:9\n",
    );
    let sock = sock_path("s6.sock");
    let daemon = FakeDocker::start(&sock);
    let h = home.to_str().unwrap();
    let proxy = "http://127.0.0.1:9";
    fs::create_dir_all(work.join("root")).unwrap();
    let root = work.join("root");
    let out = run(
        &work,
        &[
            "--out",
            "out",
            "--root",
            root.to_str().unwrap(),
            "--docker-socket",
            sock.to_str().unwrap(),
        ],
        &[
            ("HOME", h),
            ("CURL_HOME", h),
            ("XDG_CONFIG_HOME", h),
            ("http_proxy", proxy),
            ("HTTP_PROXY", proxy),
            ("ALL_PROXY", proxy),
        ],
    );
    let requests = daemon.finish();
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(
        requests,
        vec![
            "GET /version HTTP/1.1",
            "GET /containers/json?all=true HTTP/1.1",
            "GET /images/json HTTP/1.1",
        ]
    );
}

/// Codex HIGH: `--redact-dir` followed a symlink to a folder holding `seed.txt`.
#[test]
fn regression_redact_dir_symlinked_input_is_refused() {
    let work = work_dir("regress", "symdir");
    write_file(&work.join("secrets_here"), "seed.txt", "CanarySeedFile7777");
    symlink(work.join("secrets_here"), work.join("linked")).unwrap();
    let out = run(&work, &["--redact-dir", "linked", "--out", "out"], &[]);
    assert_eq!(code(&out), 2, "(a) {}", text(&out));
    assert!(!work.join("out").exists());
    assert!(!text(&out).contains("CanarySeedFile7777"));

    write_file(&work.join("real"), "docker-ps.json", "[]");
    symlink(work.join("secrets_here"), work.join("real/replies")).unwrap();
    let out = run(&work, &["--redact-dir", "real", "--out", "out"], &[]);
    assert_eq!(code(&out), 2, "(b) {}", text(&out));
    assert!(!work.join("out").exists());

    let out = run(&work, &["--check-path", "linked"], &[]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "refused: symlink in path"
    );
}

/// Codex MED: a root-owned binary under a writable or symlinked parent.
#[test]
fn regression_binary_parent_must_be_trusted() {
    let work = work_dir("regress", "parent");
    write_file(&work.join("open"), "tool", "x");
    fs::set_permissions(work.join("open"), fs::Permissions::from_mode(0o775)).unwrap();
    let out = run(&work, &["--check-path", "open/tool"], &[]);
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(said.starts_with("refused: untrusted parent"), "{said}");

    write_file(&work.join("real"), "tool", "x");
    symlink(work.join("real"), work.join("via")).unwrap();
    let out = run(&work, &["--check-path", "via/tool"], &[]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "refused: symlink in path"
    );

    let out = run(&work, &["--check-path", "/usr/bin/env"], &[]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");
}

/// Codex HIGH: nested JSON secrets, `\u`-escaped keys.
#[test]
fn regression_nested_json_secret_is_dropped() {
    let work = work_dir("regress", "nested");
    let input = format!(
        "[{{\"Names\":[\"/bitcoind\"],\"Image\":\"lightninglabs/lnd:v0.19.2-beta\",\"ImageID\":\"sha256:{DIGEST}\",\"State\":\"running\",\"Status\":\"Up 2 hours\",\"Command\":\"bitcoind --rpcpassword hunter2Canary\",\"Labels\":{{\"com.example.password\":{{\"value\":\"CanaryNested1\"}},\"xpassword\":\"CanaryEscaped9\",\"com.docker.compose.service\":\"bitcoind\"}},\"Mounts\":[{{\"Source\":\"/home/alicecanary\"}}],\"Ports\":[{{\"IP\":\"0.0.0.0\",\"PrivatePort\":8333,\"PublicPort\":8333,\"Type\":\"tcp\"}}]}}]"
    );
    let out = redact_dir(&work, &[("docker-ps.json", &input)], &[]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(
        read(&work, "out/docker-ps.json"),
        format!(
            "[\n{{\"Image\":\"lightninglabs/lnd:v0.19.2-beta\",\"ImageID\":\"sha256:{DIGEST}\",\"Labels\":{{\"com.docker.compose.service\":\"bitcoind\"}},\"Names\":[\"/bitcoind\"],\"Ports\":[{{\"IP\":\"0.0.0.0\",\"PrivatePort\":8333,\"PublicPort\":8333,\"Type\":\"tcp\"}}],\"State\":\"running\",\"Status\":\"Up 2 hours\"}}\n]\n"
        )
    );
    assert_absent(
        &work,
        &out,
        &[
            "hunter2Canary",
            "CanaryNested1",
            "CanaryEscaped9",
            "alicecanary",
        ],
    );
}

/// Codex HIGH: a YAML block scalar kept its indented secret.
#[test]
fn regression_yaml_block_scalar_is_dropped() {
    let work = work_dir("regress", "yaml");
    let input = "manifestVersion: 1\nid: bitcoin\nname: Bitcoin Node\nversion: \"29.1\"\ndefaultPassword: |\n  CanaryBlockPass7\ndescription: >-\n  canary prose here\ndeterministicPassword: true\ndependencies:\n  - tor\n";
    let out = redact_dir(&work, &[("apps/bitcoin/umbrel-app.yml", input)], &[]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(
        read(&work, "out/apps/bitcoin/umbrel-app.yml"),
        "manifestVersion: 1\nid: bitcoin\nname: Bitcoin Node\nversion: \"29.1\"\ndependencies:\n  - tor\n"
    );
    assert_absent(&work, &out, &["CanaryBlockPass7", "canary prose"]);
}

/// Codex HIGH: `Basic` credentials were not redacted.
#[test]
fn regression_basic_auth_is_redacted() {
    let work = work_dir("regress", "basic");
    let input = binaries(&["Authorization: Basic YWJjOmRlZmdoaWpr", "Basic dTpw"]);
    let out = redact_dir(&work, &[("binaries-version.txt", &input)], &[]);
    assert_eq!(code(&out), 3, "{}", text(&out));
    assert_absent(&work, &out, &["YWJjOmRlZmdoaWpr", "dTpw"]);
    let got = read(&work, "out/binaries-version.txt");
    assert!(
        got.contains("REDACTED-BEARER-1") && got.contains("REDACTED-BEARER-2"),
        "{got}"
    );
}

/// Codex HIGH: a 12-word mnemonic separated by tabs or commas.
#[test]
fn regression_tab_separated_mnemonic() {
    let work = work_dir("regress", "mnemonic");
    let words =
        "cravat dolmen fennel gimlet hassock jerkin kirtle lintel mullet nimbus oriel plinth";
    let tabs = words.replace(' ', "\t");
    let commas = words.replace(' ', ", ");
    let input = binaries(&[&tabs, &commas]);
    let out = redact_dir(&work, &[("binaries-version.txt", &input)], &[]);
    assert_eq!(code(&out), 3, "{}", text(&out));
    let list: Vec<&str> = words.split(' ').collect();
    assert_absent(&work, &out, &list);
}

/// Codex HIGH: upper-case `NSEC1` and `.ONION` were missed.
#[test]
fn regression_uppercase_nsec_and_onion() {
    let work = work_dir("regress", "upper");
    let bech = "qpzry9x8gf2tvdw0s3jn54khce6mua7l".repeat(2);
    let nsec = format!("NSEC1{}", bech[..58].to_uppercase());
    let b32 = "abcdefghijklmnopqrstuvwxyz234567".repeat(2);
    let onion = format!("CANARY{}", b32[..50].to_uppercase());
    let line2 = format!("{onion}.ONION:9735");
    let input = binaries(&[&nsec, &line2]);
    let out = redact_dir(&work, &[("binaries-version.txt", &input)], &[]);
    assert_eq!(code(&out), 3, "{}", text(&out));
    assert_absent(&work, &out, &[&nsec, &onion]);
}

/// Codex HIGH: a short secret was not covered by the self-check.
#[test]
fn regression_short_secret_self_check() {
    let work = work_dir("regress", "short");
    let input = binaries(&["rpcpassword=Zq9x", "seen Zq9x here"]);
    let out = redact_dir(&work, &[("binaries-version.txt", &input)], &[]);
    assert_eq!(code(&out), 4, "{}", text(&out));
    assert!(list_files(&work.join("out")).is_empty());
    assert!(!text(&out).contains("Zq9x"));
}

/// Codex MED: an nsec in a secret-named field exited 0.
#[test]
fn regression_nsec_in_secret_field_exits_3() {
    let work = work_dir("regress", "nsecfield");
    let bech = "qpzry9x8gf2tvdw0s3jn54khce6mua7l".repeat(2);
    let nsec = format!("nsec1{}", &bech[..58]);
    let line = format!("password={nsec}");
    let input = binaries(&[&line]);
    let out = redact_dir(&work, &[("binaries-version.txt", &input)], &[]);
    assert_eq!(code(&out), 3, "{}", text(&out));
    assert_absent(&work, &out, &[&nsec]);
}

/// Codex MED: domains on unlisted TLDs, and subdomains of a kept domain.
#[test]
fn regression_unlisted_tld_domains() {
    let work = work_dir("regress", "tld");
    let images = format!(
        "[{{\"Id\":\"sha256:{DIGEST}\",\"RepoTags\":[\"registry.node.watch/app:1\",\"docker.io/lightninglabs/lnd:v0.19.2-beta\"],\"Labels\":{{\"org.opencontainers.image.source\":\"https://fritz.box/x\"}}}}]"
    );
    let nip11 = "{\"software\":\"https://relay.alicecanary.social/x\"}";
    let bin = binaries(&["see private-acct.github.com", "repo github.com"]);
    let out = redact_dir(
        &work,
        &[
            ("docker-images.json", &images),
            ("replies/strfry/nip11.json", nip11),
            ("binaries-version.txt", &bin),
        ],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(
        &work,
        &out,
        &[
            "node.watch",
            "alicecanary.social",
            "fritz.box",
            "private-acct",
        ],
    );
    let got = all_output_text(&work.join("out"));
    assert!(got.contains("repo github.com"), "{got}");
    assert!(got.contains("docker.io/lightninglabs/lnd"), "{got}");
}

/// Codex MED: `ip-8.8.4.4` and `[::ffff:192.168.77.8]`.
#[test]
fn regression_ip_with_prefix_and_mapped_v6() {
    let work = work_dir("regress", "ipmap");
    let ss = "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 4096 [::ffff:192.168.77.8]:8333 0.0.0.0:* users:((\"bitcoind\",pid=1,fd=3))\n";
    let bin = binaries(&["ip-8.8.4.4"]);
    let out = redact_dir(
        &work,
        &[("ss-tlnp.txt", ss), ("binaries-version.txt", &bin)],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(&work, &out, &["192.168.77.8", "8.8.4.4"]);
    assert!(read(&work, "out/ss-tlnp.txt").contains("[::ffff:10.200.1.8]:8333"));
    assert!(read(&work, "out/binaries-version.txt").contains("ip-203.0.113.1"));
}

/// Codex MED: `/home/élodie` (non-ASCII) and a quoted home path.
#[test]
fn regression_home_paths() {
    let work = work_dir("regress", "home");
    let input = binaries(&["cfg /home/élodie/x", "src \"/home/alicecanary\""]);
    let out = redact_dir(&work, &[("binaries-version.txt", &input)], &[]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(&work, &out, &["élodie", "alicecanary"]);
    assert!(read(&work, "out/binaries-version.txt").contains("/home/user-1/x"));
}

/// Opus: `--rpcpassword hunter2` as two words.
#[test]
fn regression_space_separated_flag_secret() {
    let work = work_dir("regress", "flag");
    let input = binaries(&["bitcoind --rpcpassword hunter2Canary -printtoconsole"]);
    let out = redact_dir(&work, &[("binaries-version.txt", &input)], &[]);
    assert_eq!(code(&out), 3, "{}", text(&out));
    assert_absent(&work, &out, &["hunter2Canary"]);
    assert!(read(&work, "out/binaries-version.txt").contains("-printtoconsole"));
}

/// Opus: any file was accepted as a reply.
#[test]
fn regression_reply_must_be_json() {
    let work = work_dir("regress", "notjson");
    fs::write(work.join("r.txt"), "version 0.19.2 CanaryFreeText").unwrap();
    let out = run(
        &work,
        &["--out", "out", "--reply", "lnd/getinfo=r.txt"],
        &[],
    );
    assert_eq!(code(&out), 1, "{}", text(&out));
    assert!(text(&out).contains("not JSON"), "{}", text(&out));
    assert!(!text(&out).contains("CanaryFreeText"));
}

/// Opus: alias, NIP-11 name, description and contact, and other free text.
#[test]
fn regression_reply_free_text_fields_dropped() {
    let work = work_dir("regress", "freetext");
    let lnd = "{\"alias\":\"CanaryAliasLnd\",\"color\":\"#3399ff\",\"identity_pubkey\":\"02ca11ab1e02ca11ab1e02ca11ab1e02ca11ab1e02ca11ab1e02ca11ab1e1234\",\"uris\":[\"02ca11ab1e@canary-uri.example:9735\"],\"version\":\"0.19.2-beta commit=v0.19.2-beta\",\"commit_hash\":\"da1ec0de5ba11ad0c0ffee15deadbeef00c0ffee\",\"chains\":[{\"chain\":\"bitcoin\",\"network\":\"mainnet\"}]}";
    let nip11 = "{\"name\":\"CanaryRelayName\",\"description\":\"CanaryRelayDesc\",\"contact\":\"CanaryContactX\",\"pubkey\":\"ca11ab1eca11ab1eca11ab1eca11ab1eca11ab1eca11ab1eca11ab1eca11ab1e\",\"software\":\"git+https://github.com/hoytech/strfry.git\",\"version\":\"1.0.4\",\"supported_nips\":[1,11]}";
    let cln = "{\"id\":\"03ca11ab1e\",\"alias\":\"CanaryAliasCln\",\"color\":\"ff9900\",\"address\":[{\"type\":\"ipv4\",\"address\":\"CanaryAddrCln\"}],\"version\":\"v25.05\",\"network\":\"bitcoin\"}";
    let nut = "{\"name\":\"CanaryMintName\",\"description\":\"CanaryMintDesc\",\"motd\":\"CanaryMotd\",\"contact\":[\"CanaryMintContact\"],\"version\":\"Nutshell/0.16.4\"}";
    let ni = "{\"version\":290100,\"subversion\":\"/Satoshi:29.1.0(canarycomment)/\",\"protocolversion\":70016,\"localaddresses\":[{\"address\":\"CanaryLocalAddr\",\"port\":8333}]}";
    let out = redact_dir(
        &work,
        &[
            ("replies/lnd/getinfo.json", lnd),
            ("replies/strfry/nip11.json", nip11),
            ("replies/core-lightning/getinfo.json", cln),
            ("replies/nutshell/nut06.json", nut),
            ("replies/bitcoin-core/getnetworkinfo.json", ni),
        ],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(
        read(&work, "out/replies/lnd/getinfo.json"),
        "{\"chains\":[{\"chain\":\"bitcoin\",\"network\":\"mainnet\"}],\"commit_hash\":\"da1ec0de5ba11ad0c0ffee15deadbeef00c0ffee\",\"version\":\"0.19.2-beta commit=v0.19.2-beta\"}\n"
    );
    assert_eq!(
        read(&work, "out/replies/strfry/nip11.json"),
        "{\"software\":\"git+https://github.com/hoytech/strfry.git\",\"supported_nips\":[1,11],\"version\":\"1.0.4\"}\n"
    );
    assert_eq!(
        read(&work, "out/replies/core-lightning/getinfo.json"),
        "{\"network\":\"bitcoin\",\"version\":\"v25.05\"}\n"
    );
    assert_eq!(
        read(&work, "out/replies/nutshell/nut06.json"),
        "{\"version\":\"Nutshell/0.16.4\"}\n"
    );
    assert_eq!(
        read(&work, "out/replies/bitcoin-core/getnetworkinfo.json"),
        "{\"protocolversion\":70016,\"version\":290100}\n"
    );
    assert_absent(
        &work,
        &out,
        &[
            "CanaryAliasLnd",
            "canary-uri",
            "CanaryRelayName",
            "CanaryRelayDesc",
            "CanaryContactX",
            "CanaryAliasCln",
            "CanaryAddrCln",
            "CanaryMintName",
            "CanaryMintDesc",
            "CanaryMotd",
            "CanaryMintContact",
            "canarycomment",
            "CanaryLocalAddr",
        ],
    );
}

/// Opus: `/private/tmp` was refused on macOS; the name check is now on the file
/// name and its parent folder only.
#[test]
fn regression_macos_private_tmp_is_not_refused() {
    let work = work_dir("regress", "privtmp");
    write_file(&work.join("private/sub"), "reply.json", "{}");
    write_file(&work.join("sub/private"), "reply.json", "{}");
    let out = run(&work, &["--check-path", "private/sub/reply.json"], &[]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");
    let out = run(&work, &["--check-path", "sub/private/reply.json"], &[]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "refused: name matches *private*"
    );
}

/// Opus: `REDACTED-TOKEN-N` was shared by two classes.
#[test]
fn regression_bearer_and_token_placeholders_differ() {
    let work = work_dir("regress", "ph");
    let input = binaries(&[
        "Authorization: Bearer Bb7aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "rune Rr9AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefghij",
    ]);
    let out = redact_dir(&work, &[("binaries-version.txt", &input)], &[]);
    assert_eq!(code(&out), 3, "{}", text(&out));
    let got = read(&work, "out/binaries-version.txt");
    assert!(
        got.contains("REDACTED-BEARER-1") && got.contains("REDACTED-TOKEN-1"),
        "{got}"
    );
}

/// Opus: missing RaspiBlitz files logged nothing.
#[test]
fn regression_missing_raspiblitz_files_are_logged() {
    let work = work_dir("regress", "missing");
    fs::create_dir_all(work.join("root")).unwrap();
    let out = run(
        &work,
        &[
            "--out",
            "out",
            "--root",
            work.join("root").to_str().unwrap(),
            "--docker-socket",
            "none.sock",
        ],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    let log = read(&work, "out/record-log.txt");
    for f in [
        "raspiblitz-version.txt",
        "raspiblitz-conf.txt",
        "raspiblitz-info.txt",
    ] {
        assert!(log.contains(&format!("skipped {f} not-present")), "{log}");
    }
}

/// Opus: an FQDN host name left its short name in the output.
#[test]
fn regression_fqdn_hostname_short_name() {
    let work = work_dir("regress", "fqdn");
    let farm = bin_farm(&work);
    write_stub(&farm, "hostname", "echo canarynode.fritz.box");
    write_stub(
        &farm,
        "systemctl",
        "echo 'canarynode-backup.service loaded active running x'",
    );
    fs::create_dir_all(work.join("root")).unwrap();
    let out = run(
        &work,
        &[
            "--out",
            "out",
            "--root",
            work.join("root").to_str().unwrap(),
            "--docker-socket",
            "none.sock",
        ],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(&work, &out, &["canarynode", "fritz.box"]);
}

/// Opus: torrc kept `CookieAuthentication` as redacted, but a `Bridge` line's
/// fingerprint and `cert=` survived; now only named directives are kept.
#[test]
fn regression_torrc_allowlist() {
    let work = work_dir("regress", "torrc");
    let input = "SocksPort 9050\nControlPort 9051\nCookieAuthentication 1\nHashedControlPassword 16:CANARYHASH0123456789\nBridge obfs4 45.180.180.180:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=CanaryCertAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA iat-mode=0\nHiddenServiceDir /mnt/hdd/tor/lnd9735\nHiddenServicePort 9735 127.0.0.1:9735\nDataDirectory /home/alicecanary/tor\n";
    let out = redact_dir(&work, &[("torrc", input)], &[]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_eq!(
        read(&work, "out/torrc"),
        "SocksPort 9050\nControlPort 9051\nCookieAuthentication 1\nHiddenServiceDir /REDACTED/lnd9735\nHiddenServicePort 9735 127.0.0.1:9735\n"
    );
    assert_absent(
        &work,
        &out,
        &[
            "CANARYHASH",
            "45.180.180.180",
            "CanaryCert",
            "alicecanary",
            "/mnt/hdd",
        ],
    );
}

// ---------- regression tests: second review ----------

fn bech32_body(n: usize) -> String {
    "qpzry9x8gf2tvdw0s3jn54khce6mua7l".repeat(3)[..n].to_string()
}

/// Codex HIGH: a mnemonic with the word `this`, and one separated by no-break spaces.
#[test]
fn regression_mnemonic_with_stop_word_and_nbsp() {
    let work = work_dir("regress2", "mnemonic");
    let stop = format!("this {} acid", ["abandon"; 10].join(" "));
    let nbsp = format!("{} about", ["abandon"; 11].join("\u{a0}"));
    let input = binaries(&[&stop, &nbsp]);
    let out = redact_dir(&work, &[("binaries-version.txt", &input)], &[]);
    assert_eq!(code(&out), 3, "{}", text(&out));
    assert_absent(&work, &out, &["abandon", "acid", "about"]);
    let got = read(&work, "out/binaries-version.txt");
    assert!(
        !got.contains("??"),
        "non-ASCII left recoverable text: {got}"
    );
}

/// Codex HIGH: `nsec1redacted` + q x 44 + `xkttpr` is a valid key, and the old
/// placeholder shape was trusted. Placeholders are never key-shaped now.
#[test]
fn regression_placeholder_is_not_a_key() {
    let work = work_dir("regress2", "placeholder");
    let fake = format!("nsec1redacted{}xkttpr", "q".repeat(44));
    assert_eq!(fake.len(), 63);
    let images = format!(
        "[{{\"Id\":\"sha256:{DIGEST}\",\"Labels\":{{\"org.opencontainers.image.title\":\"{fake}\"}}}}]"
    );
    let bin = binaries(&[&fake]);
    let out = redact_dir(
        &work,
        &[
            ("docker-images.json", &images),
            ("binaries-version.txt", &bin),
        ],
        &[],
    );
    assert_eq!(code(&out), 3, "{}", text(&out));
    assert_absent(&work, &out, &[&fake, "nsec1redacted"]);
    assert!(read(&work, "out/binaries-version.txt").contains("REDACTED-NSEC-1"));
}

/// Codex HIGH: a key inside a systemd unit name was kept by the unit-name exemption.
#[test]
fn regression_nsec_inside_unit_name() {
    let work = work_dir("regress2", "unit");
    let key = format!("nsec1{}smhltgl", "q".repeat(51));
    let line = format!("wallet-{key}.service loaded active running\n");
    let out = redact_dir(&work, &[("systemctl-list-units.txt", &line)], &[]);
    assert_eq!(code(&out), 3, "{}", text(&out));
    assert_absent(&work, &out, &[&key, "wallet-"]);
    // Since the fourth review the whole unit name is replaced, not only the key in it.
    assert!(read(&work, "out/systemctl-list-units.txt").contains("unit-1.service"));
}

/// Codex MED: `GD_RECORD_CLEAN=1`, an exported `printf` and a test-tools folder
/// from the environment must change nothing.
#[test]
fn regression_env_overrides_are_gone() {
    let work = work_dir("regress2", "env");
    let farm = work.join("fakebin");
    fs::create_dir_all(&farm).unwrap();
    write_stub(
        &farm,
        "perl",
        &format!(": > '{}'", work.join("TRAP-perl").display()),
    );
    let fn_value = format!("() {{ : > '{}'; }}", work.join("TRAP-printf").display());
    let farm_s = farm.to_str().unwrap();
    write_file(
        &work.join("in"),
        "binaries-version.txt",
        "== /usr/local/bin/x\nTor version 0.4.8.16.\n",
    );
    let out = run_inner(
        &work,
        &["--redact-dir", "in", "--out", "out"],
        &[
            ("GD_RECORD_CLEAN", "1"),
            ("GD_RECORD_SELFTEST_BIN", farm_s),
            ("BASH_FUNC_printf%%", &fn_value),
        ],
        false,
    );
    assert_no_trap(&work);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(!read(&work, "out/record-log.txt").contains("test-tools"));

    // A caller that fakes the launcher marker with a dirty environment is stopped.
    let out = run_inner(
        &work,
        &["--gd-clean-launch", "--help"],
        &[("PERL5OPT", "-e1")],
        false,
    );
    assert_eq!(code(&out), 1, "{}", text(&out));
    assert!(text(&out).contains("not clean"), "{}", text(&out));
}

/// Codex MED: a root-owned binary under a user-owned parent was accepted.
#[test]
fn regression_binary_ancestors_must_be_root_owned() {
    let work = work_dir("regress2", "binary");
    write_file(&work.join("mine"), "tool", "x");
    let out = run(&work, &["--check-binary", "mine/tool"], &[]);
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(said.starts_with("refused:"), "{said}");
    let out = run(&work, &["--check-binary", "/usr/bin/env"], &[]);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");
}

/// Codex MED: an empty 0777 output folder was accepted.
#[test]
fn regression_output_dir_must_be_private() {
    let work = work_dir("regress2", "outdir");
    write_file(&work.join("in"), "torrc", "SocksPort 9050\n");
    fs::create_dir_all(work.join("open")).unwrap();
    fs::set_permissions(work.join("open"), fs::Permissions::from_mode(0o777)).unwrap();
    let out = run(&work, &["--redact-dir", "in", "--out", "open"], &[]);
    assert_eq!(code(&out), 2, "{}", text(&out));
    assert!(list_files(&work.join("open")).is_empty());

    fs::create_dir_all(work.join("private_out")).unwrap();
    fs::set_permissions(work.join("private_out"), fs::Permissions::from_mode(0o700)).unwrap();
    let out = run(&work, &["--redact-dir", "in", "--out", "private_out"], &[]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let mode = fs::metadata(work.join("private_out/torrc"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

/// Codex MED: private image hosts, compose projects, unit instances, package and
/// process names and tor targets survived.
#[test]
fn regression_private_names_are_pseudonymised() {
    let work = work_dir("regress2", "names");
    let ps = "[{\"Names\":[\"/alice-worker\"],\"Image\":\"vault:5000/alice/node:1\",\"Labels\":{\"com.docker.compose.project\":\"alice-shop\",\"com.docker.compose.service\":\"bitcoind\"},\"State\":\"running\"}]";
    let units = "backup@alice.service loaded active running x\ntor@default.service loaded active running x\n";
    let dpkg = "alice-worker\t1.0\tii \nopenssl\t3.0.11\tii \n";
    let ss = "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 128 0.0.0.0:8333 0.0.0.0:* users:((\"alice-worker\",pid=1,fd=3),(\"bitcoind\",pid=2,fd=4))\n";
    let torrc = "HiddenServicePort 80 AliceNode\nSocksPort 9050 IsolateClientAddr\n";
    let out = redact_dir(
        &work,
        &[
            ("docker-ps.json", ps),
            ("systemctl-list-units.txt", units),
            ("dpkg-query.txt", dpkg),
            ("ss-tlnp.txt", ss),
            ("torrc", torrc),
        ],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(&work, &out, &["alice", "AliceNode", "vault"]);
    let got = all_output_text(&work.join("out"));
    for kept in [
        "bitcoind",
        "tor@default.service",
        "openssl",
        "IsolateClientAddr",
    ] {
        assert!(got.contains(kept), "public name lost: {kept}");
    }
}

/// Codex MED: a hostname value equal to a Docker label key was exempt.
#[test]
fn regression_hostnames_are_not_exempt_as_keys() {
    let work = work_dir("regress2", "keys");
    let images = format!(
        "[{{\"Id\":\"sha256:{DIGEST}\",\"RepoTags\":[\"com.docker.compose.project/x:1\",\"registry-alice.rs/x:1\"],\"Labels\":{{\"com.docker.compose.project\":\"shop\"}}}}]"
    );
    let nip11 = "{\"software\":\"https://com.docker.compose.project/x\"}";
    let bin = binaries(&["see registry-alice.rs and com.docker.compose.project"]);
    let out = redact_dir(
        &work,
        &[
            ("docker-images.json", &images),
            ("replies/strfry/nip11.json", nip11),
            ("binaries-version.txt", &bin),
        ],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(&work, &out, &["registry-alice", "shop"]);
    assert!(!read(&work, "out/replies/strfry/nip11.json").contains("com.docker.compose"));
    assert!(!read(&work, "out/binaries-version.txt").contains("com.docker.compose"));
    // The JSON key itself is kept.
    assert!(read(&work, "out/docker-images.json").contains("\"com.docker.compose.project\":"));
}

/// Codex MED: `Ports[].IP` values that already looked like placeholders stayed.
#[test]
fn regression_every_port_address_is_mapped() {
    let work = work_dir("regress2", "ports");
    let ps = "[{\"Names\":[\"/lnd\"],\"Ports\":[{\"IP\":\"10.200.17.42\",\"PrivatePort\":1},{\"IP\":\"fd00::abcd\",\"PrivatePort\":2},{\"IP\":\"fe80::1234\",\"PrivatePort\":3},{\"IP\":\"203.0.113.77\",\"PrivatePort\":4}]}]";
    let out = redact_dir(&work, &[("docker-ps.json", ps)], &[]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(
        &work,
        &out,
        &["10.200.17.42", "fd00::abcd", "fe80::1234", "203.0.113.77"],
    );
}

/// Codex MED: `ip-8.8.4.4-node` kept its address.
#[test]
fn regression_hyphen_delimited_address() {
    let work = work_dir("regress2", "hyphen");
    let bin = binaries(&["see ip-8.8.4.4-node", "and x_9.9.9.9_y"]);
    let out = redact_dir(&work, &[("binaries-version.txt", &bin)], &[]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(&work, &out, &["8.8.4.4", "9.9.9.9"]);
}

/// Codex MED: `replies/alicecanary/getinfo.json` kept the private name.
#[test]
fn regression_reply_path_is_pseudonymised() {
    let work = work_dir("regress2", "replypath");
    write_file(
        &work,
        "r.json",
        "{\"version\":\"0.19.2-beta commit=v0.19.2-beta\"}\n",
    );
    fs::create_dir_all(work.join("root")).unwrap();
    let out = run(
        &work,
        &[
            "--out",
            "out",
            "--root",
            work.join("root").to_str().unwrap(),
            "--docker-socket",
            "none.sock",
            "--reply",
            "alicecanary/getinfo=r.json",
            "--redact-term",
            "alicecanary",
        ],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    let files = list_files(&work.join("out"));
    assert!(
        files.contains(&"replies/service-1/getinfo.json".to_string()),
        "{files:?}"
    );
    assert!(
        files.iter().all(|f| !f.contains("alicecanary")),
        "{files:?}"
    );
    assert_absent(&work, &out, &["alicecanary"]);
    let log = read(&work, "out/record-log.txt");
    assert!(
        log.contains("collected replies/service-1/getinfo.json"),
        "{log}"
    );

    let work2 = work_dir("regress2", "replypath2");
    let out = redact_dir(
        &work2,
        &[(
            "replies/alicecanary/getinfo.json",
            "{\"version\":\"0.19.2\"}",
        )],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(
        list_files(&work2.join("out"))
            .iter()
            .all(|f| !f.contains("alicecanary"))
    );
}

/// Codex MED: a dropped `Labels.password=<nsec>` still allowed exit 0.
#[test]
fn regression_dropped_secret_still_exits_3() {
    let work = work_dir("regress2", "dropped");
    let key = format!("nsec1{}", bech32_body(58));
    let ps = format!("[{{\"Names\":[\"/lnd\"],\"Labels\":{{\"password\":\"{key}\"}}}}]");
    let out = redact_dir(&work, &[("docker-ps.json", &ps)], &[]);
    assert_eq!(code(&out), 3, "{}", text(&out));
    assert_absent(&work, &out, &[&key]);
}

// ---------- regression tests: third review ----------

/// Codex 3 HIGH: a mnemonic wrapped with a space then a newline (or a newline
/// then a space) between words survived.
#[test]
fn regression3_mnemonic_with_mixed_whitespace() {
    let work = work_dir("regress3", "mixed");
    let a = ["abandon"; 6].join(" ");
    let b = format!("{} about", ["abandon"; 5].join(" "));
    // space + newline after word 6
    let one = format!("== /usr/local/bin/x\n{a} \n{b}\n");
    // newline + space after word 6
    let two = format!("== /usr/local/bin/y\n{a}\n {b}\n");
    let input = format!("{one}{two}");
    let out = redact_dir(&work, &[("binaries-version.txt", &input)], &[]);
    assert_eq!(code(&out), 3, "{}", text(&out));
    assert_absent(&work, &out, &["abandon", "about"]);
}

/// Codex 3 HIGH: `PASS=REDACTED-NSEC1` followed by a real-looking key body was
/// kept because the placeholder shape was trusted before the secret was checked.
#[test]
fn regression3_placeholder_prefix_does_not_hide_a_key() {
    let work = work_dir("regress3", "placeholder");
    let body = format!("{}SMHLTGL", "Q".repeat(51));
    let reply = format!("{{\"version\":\"PASS=REDACTED-NSEC1{body}\"}}");
    let out = redact_dir(&work, &[("replies/lnd/getinfo.json", &reply)], &[]);
    assert_eq!(code(&out), 3, "{}", text(&out));
    assert_absent(&work, &out, &[&body]);
    assert!(read(&work, "out/replies/lnd/getinfo.json").contains("REDACTED-SECRET-1"));
}

/// Codex 3 HIGH: `sha256:` + 64 hex characters in a version field could be a
/// private-key scalar. Only typed digest fields (`Id`, `ImageID`, `RepoDigests`,
/// `RepoTags`) keep one.
#[test]
fn regression3_digest_only_in_typed_fields() {
    let work = work_dir("regress3", "digest");
    let scalar = "a1".repeat(32);
    let label_scalar = "b2".repeat(32);
    let reply = format!("{{\"version\":\"sha256:{scalar}\"}}");
    let images = format!(
        "[{{\"Id\":\"sha256:{DIGEST}\",\"Labels\":{{\"org.opencontainers.image.version\":\"sha256:{label_scalar}\"}}}}]"
    );
    let out = redact_dir(
        &work,
        &[
            ("replies/lnd/getinfo.json", &reply),
            ("docker-images.json", &images),
        ],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(&work, &out, &[&scalar, &label_scalar]);
    assert!(read(&work, "out/docker-images.json").contains(&format!("sha256:{DIGEST}")));
}

/// Codex 3 MED: `--gd-clean-launch` plus exported shell functions named like
/// the commands the clean check used (`compgen`, `printf`) hid a dirty
/// environment; an exported `[` or `exec` must not change anything either.
#[test]
fn regression3_clean_launch_cannot_be_shadowed() {
    let work = work_dir("regress3", "shadow");
    write_file(
        &work.join("in"),
        "binaries-version.txt",
        "== /usr/local/bin/x\nTor version 0.4.8.16.\n",
    );
    let noop = "() { :; }";
    let trap = |name: &str| format!("() {{ : > '{}'; }}", work.join(name).display());
    let printf_trap = trap("TRAP-printf");
    let out = run_inner(
        &work,
        &["--gd-clean-launch", "--redact-dir", "in", "--out", "out-a"],
        &[
            ("BASH_FUNC_compgen%%", noop),
            ("BASH_FUNC_printf%%", &printf_trap),
        ],
        false,
    );
    assert_eq!(code(&out), 1, "{}", text(&out));
    assert!(text(&out).contains("not clean"), "{}", text(&out));
    assert_no_trap(&work);
    assert!(!work.join("out-a").exists());

    // An exported `[` (what the old launcher test used) or `exec`, no marker.
    for (case, name) in [("bracket", "["), ("exec", "exec")] {
        let var = format!("BASH_FUNC_{name}%%");
        let body = trap(&format!("TRAP-{case}"));
        let out_dir = format!("out-{case}");
        let out = run_inner(
            &work,
            &["--redact-dir", "in", "--out", &out_dir],
            &[(var.as_str(), body.as_str())],
            false,
        );
        if case == "bracket" {
            // The clean relaunch ignores the hostile function entirely.
            assert_eq!(code(&out), 0, "{case}: {}", text(&out));
            assert!(work.join(&out_dir).join("record-log.txt").exists());
            assert!(!work.join("TRAP-bracket").exists(), "bracket function ran");
        } else {
            // The hostile `exec` is the caller's own code; what matters is that
            // the script then refuses to go on in the dirty environment.
            assert_eq!(code(&out), 1, "{case}: {}", text(&out));
            assert!(!work.join(&out_dir).exists(), "{case}: wrote output");
        }
    }
}

/// Codex 3 MED: `alice-worker.service` survived, and so did the name of a Tor
/// hidden-service folder. Unit names and tor folder names are pseudonymised
/// unless they are on the reviewed public list.
#[test]
fn regression3_unit_and_tor_names_are_pseudonymised() {
    let work = work_dir("regress3", "units");
    let units = "alice-worker.service loaded active running x\n\
bitcoind.service loaded active running x\n\
cron.service loaded active running x\n\
systemd-journald.service loaded active running x\n\
getty@tty1.service loaded active running x\n\
tor@default.service loaded active running x\n\
alice-worker.service loaded failed failed x\n";
    let torrc =
        "HiddenServiceDir /var/lib/tor/alicehs/\nHiddenServiceDir /var/lib/tor/hidden_service\n";
    let out = redact_dir(
        &work,
        &[("systemctl-list-units.txt", units), ("torrc", torrc)],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(&work, &out, &["alice"]);
    let got = read(&work, "out/systemctl-list-units.txt");
    for kept in [
        "bitcoind.service loaded active running",
        "cron.service loaded active running",
        "systemd-journald.service loaded active running",
        "getty@tty1.service loaded active running",
        "tor@default.service loaded active running",
    ] {
        assert!(got.contains(kept), "public unit lost: {kept}\n{got}");
    }
    // The same private unit gets the same name.
    assert_eq!(got.matches("unit-1.service").count(), 2, "{got}");
    let tor = read(&work, "out/torrc");
    assert!(
        tor.contains("HiddenServiceDir /REDACTED/hidden_service"),
        "{tor}"
    );
    assert!(tor.contains("HiddenServiceDir /REDACTED/hs-1"), "{tor}");
}

/// Codex 3 MED: the first replacement addresses (`10.200.1.42`, `fd00::1`,
/// `fe80::1`, `203.0.113.1`) were also real source values, so the self-check
/// could not tell a replacement from a leak. Replacements are chosen so that
/// they never equal a value in the input.
#[test]
fn regression3_replacements_differ_from_sources() {
    let work = work_dir("regress3", "disjoint");
    let ps = "[{\"Names\":[\"/lnd\"],\"Ports\":[{\"IP\":\"10.200.1.42\",\"PrivatePort\":1},{\"IP\":\"fd00::1\",\"PrivatePort\":2},{\"IP\":\"fe80::1\",\"PrivatePort\":3},{\"IP\":\"203.0.113.1\",\"PrivatePort\":4},{\"IP\":\"2001:db8::1\",\"PrivatePort\":5}]}]";
    let out = redact_dir(&work, &[("docker-ps.json", ps)], &[]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let got = read(&work, "out/docker-ps.json");
    for source in [
        "10.200.1.42",
        "\"fd00::1\"",
        "\"fe80::1\"",
        "\"203.0.113.1\"",
        "\"2001:db8::1\"",
    ] {
        assert!(
            !got.contains(source),
            "source address kept: {source}\n{got}"
        );
    }
}

/// Codex 3 MED: `apps/tor/alicecanary.json` (a file name chosen by the node's
/// owner) reached the output and the log.
#[test]
fn regression3_file_names_are_pseudonymised() {
    let work = work_dir("regress3", "basenames");
    let out = redact_dir(
        &work,
        &[
            ("apps/tor/alicecanary.json", "{\"name\":\"Tor\"}"),
            ("apps/tor/umbrel-app.yml", "id: tor\n"),
            ("replies/lnd/getinfo.json", "{\"version\":\"0.19.2\"}"),
        ],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(&work, &out, &["alicecanary"]);
    let files = list_files(&work.join("out"));
    assert!(
        files.iter().any(|f| f == "apps/tor/umbrel-app.yml"),
        "{files:?}"
    );
    assert!(
        files.iter().any(|f| f.starts_with("apps/tor/file-")),
        "{files:?}"
    );
    let log = read(&work, "out/record-log.txt");
    assert!(!log.contains("alicecanary"), "{log}");
}

/// Codex 3 MED: a secret followed by thousands of spaces made the string
/// "too long", and it was dropped without being scanned.
#[test]
fn regression3_oversized_string_is_scanned_before_it_is_dropped() {
    let work = work_dir("regress3", "oversize");
    let key = format!("nsec1{}smhltgl", "q".repeat(51));
    let ps = format!(
        "[{{\"Names\":[\"/lnd\"],\"Labels\":{{\"password\":\"{key}{}\"}}}}]",
        " ".repeat(4034)
    );
    let out = redact_dir(&work, &[("docker-ps.json", &ps)], &[]);
    assert_eq!(code(&out), 3, "{}", text(&out));
    assert_absent(&work, &out, &[&key]);

    // A long string with no secret in it is still just dropped, exit 0.
    let work = work_dir("regress3", "oversize2");
    let ps = format!(
        "[{{\"Names\":[\"/lnd\"],\"Labels\":{{\"note\":\"hello{}\"}}}}]",
        " ".repeat(5000)
    );
    let out = redact_dir(&work, &[("docker-ps.json", &ps)], &[]);
    assert_eq!(code(&out), 0, "{}", text(&out));
}

// ---------- regression tests: fourth review ----------

/// Twelve words of the public BIP39 test vectors (never a real wallet): the
/// "abandon ... accident" run, and the 12-word "legal winner" phrase.
const WORDS_A: [&str; 12] = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
    "abuse", "access", "accident",
];
const WORDS_B: [&str; 12] = [
    "legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal", "winner",
    "thank", "yellow",
];
/// Words that cannot be part of a message the script prints itself.
const WORD_PROBES: [&str; 9] = [
    "ability", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident", "abandon",
];

fn joined_with(words: &[&str], seps: &[&str]) -> String {
    let mut s = String::new();
    for (i, w) in words.iter().enumerate() {
        if i > 0 {
            s.push_str(seps[(i - 1) % seps.len()]);
        }
        s.push_str(w);
    }
    s
}

fn numbered(words: &[&str], style: &str) -> String {
    words
        .iter()
        .enumerate()
        .map(|(i, w)| format!("{}{style} {w}", i + 1))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Fourth review HIGH: a mnemonic joined by `-`, `_` or `:` in a kept field
/// (a `getinfo` version, an image label) survived with exit 0.
#[test]
fn regression4_joined_mnemonic_in_kept_fields() {
    let legal = WORDS_B.join("-");
    let work = work_dir("regress4", "getinfo");
    let reply = format!("{{\"version\":\"{legal}\"}}");
    let out = redact_dir(&work, &[("replies/lnd/getinfo.json", &reply)], &[]);
    assert_eq!(code(&out), 3, "{}", text(&out));
    assert_absent(&work, &out, &[&legal, "sausage", "thank-year"]);
    assert!(read(&work, "out/replies/lnd/getinfo.json").contains("REDACTED-WORDS-"));

    for (case, key, sep) in [
        ("version", "org.opencontainers.image.version", "_"),
        ("revision", "org.opencontainers.image.revision", ":"),
    ] {
        let work = work_dir("regress4", case);
        let images = format!(
            "[{{\"Id\":\"sha256:{DIGEST}\",\"Labels\":{{\"{key}\":\"{}\"}}}}]",
            WORDS_B.join(sep)
        );
        let out = redact_dir(&work, &[("docker-images.json", &images)], &[]);
        assert_eq!(code(&out), 3, "{case}: {}", text(&out));
        assert_absent(&work, &out, &["sausage", "winner", "yellow"]);
    }
}

/// Fourth review HIGH: every separator of 1 to 3 characters, mixes of them,
/// and numbered lists, in the free-text file and in a JSON value.
#[test]
fn regression4_mnemonic_separators() {
    let singles = [
        " ", "\t", ",", "-", "_", ":", ".", "/", "|", "\n", ", ", " - ", "\t|\t", "::", "...",
    ];
    for (n, sep) in singles.iter().enumerate() {
        let work = work_dir("regress4", &format!("sep{n}"));
        let input = binaries(&[&joined_with(&WORDS_A, &[sep])]);
        let out = redact_dir(&work, &[("binaries-version.txt", &input)], &[]);
        assert_eq!(code(&out), 3, "separator {sep:?}: {}", text(&out));
        assert_absent(&work, &out, &WORD_PROBES);
    }
    // Mixed separators, in the free-text file.
    let mixed = [
        " ", "-", "_", ", ", ":", "|", "\t", "/", ".", "\n", " - ", "-",
    ];
    let work = work_dir("regress4", "mixed");
    let input = binaries(&[&joined_with(&WORDS_A, &mixed)]);
    let out = redact_dir(&work, &[("binaries-version.txt", &input)], &[]);
    assert_eq!(code(&out), 3, "{}", text(&out));
    assert_absent(&work, &out, &WORD_PROBES);

    // Numbered lists, on one line and one word per line.
    for (case, style) in [("dot", "."), ("paren", ")")] {
        let work = work_dir("regress4", &format!("num-{case}"));
        let input = binaries(&[&numbered(&WORDS_A, style)]);
        let out = redact_dir(&work, &[("binaries-version.txt", &input)], &[]);
        assert_eq!(code(&out), 3, "numbered {style}: {}", text(&out));
        assert_absent(&work, &out, &WORD_PROBES);

        let work = work_dir("regress4", &format!("numlines-{case}"));
        let lines: Vec<String> = WORDS_A
            .iter()
            .enumerate()
            .map(|(i, w)| format!("{}{style} {w}", i + 1))
            .collect();
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        let input = binaries(&refs);
        let out = redact_dir(&work, &[("binaries-version.txt", &input)], &[]);
        assert_eq!(code(&out), 3, "numbered lines {style}: {}", text(&out));
        assert_absent(&work, &out, &WORD_PROBES);
    }

    // In a JSON value (the characters its schema allows).
    for (n, sep) in ["-", "_", ":", ".", " ", "+", "="].iter().enumerate() {
        let work = work_dir("regress4", &format!("json{n}"));
        let reply = format!("{{\"version\":\"{}\"}}", WORDS_B.join(sep));
        let out = redact_dir(&work, &[("replies/lnd/getinfo.json", &reply)], &[]);
        assert_eq!(code(&out), 3, "json separator {sep:?}: {}", text(&out));
        assert_absent(&work, &out, &["sausage", "winner", "yellow"]);
    }
}

/// Ordinary rows of the table files are not mnemonics: nothing is replaced and
/// the exit code stays 0 (the separator rule must not chain lines together).
#[test]
fn regression4_table_files_do_not_chain_into_a_mnemonic() {
    let work = work_dir("regress4", "tables");
    let units: String = [
        "cron.service loaded active running Regular background program processing daemon",
        "ssh.service loaded active running OpenSSH server daemon",
        "docker.service loaded active running Docker Application Container Engine",
        "dbus.service loaded active running D-Bus System Message Bus",
        "tor@default.service loaded active running Anonymizing overlay network for TCP",
        "nginx.service loaded active running A high performance web server",
    ]
    .iter()
    .map(|l| format!("{l}\n"))
    .collect();
    let conf: String = (0..16)
        .map(|_| "rtl=\"off\"\nlnd=\"off\"\ntor=\"off\"\n".to_string())
        .collect();
    let out = redact_dir(
        &work,
        &[
            ("systemctl-list-units.txt", &units),
            ("raspiblitz-conf.txt", &conf),
        ],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(!read(&work, "out/record-log.txt").contains("seed-words"));
    assert!(read(&work, "out/systemctl-list-units.txt").contains("cron.service loaded"));
}

/// Fourth review HIGH (addendum): `seed=<12 words>` replaced only the first word.
#[test]
fn regression4_seed_assignment_redacts_every_word() {
    for (n, line) in [
        format!("seed={}", WORDS_A.join(" ")),
        format!("mnemonic: {}", WORDS_A.join(" ")),
        format!("--seed {}", WORDS_A.join(" ")),
    ]
    .iter()
    .enumerate()
    {
        let work = work_dir("regress4", &format!("seedkv{n}"));
        let input = binaries(&[line]);
        let out = redact_dir(&work, &[("binaries-version.txt", &input)], &[]);
        assert_eq!(code(&out), 3, "{line}: {}", text(&out));
        assert_absent(&work, &out, &WORD_PROBES);
        let log = read(&work, "out/record-log.txt");
        assert!(log.contains("replaced seed-words 1 1"), "{log}");
    }
}

/// Fourth review LOW: a mnemonic split across two JSON values (a `build_tags`
/// array) survived, and the recording was kept.
#[test]
fn regression4_mnemonic_split_across_json_values() {
    let work = work_dir("regress4", "split");
    let reply = format!(
        "{{\"lnd\":{{\"build_tags\":[\"{}\",\"{}\"]}}}}",
        WORDS_A[..6].join(" "),
        WORDS_A[6..].join(" ")
    );
    let out = redact_dir(&work, &[("replies/lnd/getversion.json", &reply)], &[]);
    assert_eq!(code(&out), 3, "{}", text(&out));
    assert_absent(&work, &out, &WORD_PROBES);
}

/// Fourth review MEDIUM: the NIP-11 `software` URL kept the operator's account.
#[test]
fn regression4_nip11_software_only_if_public() {
    for (n, software) in [
        "https://github.com/alicecanary/relay",
        "git+https://git.alicecanary.lan/bobcanary/relay.git",
        "https://alicecanary.example/relay",
    ]
    .iter()
    .enumerate()
    {
        let work = work_dir("regress4", &format!("nip11-{n}"));
        let reply = format!("{{\"software\":\"{software}\",\"version\":\"1.0.4\"}}");
        let out = redact_dir(&work, &[("replies/strfry/nip11.json", &reply)], &[]);
        assert_eq!(code(&out), 0, "{software}: {}", text(&out));
        assert_absent(&work, &out, &["alicecanary", "bobcanary"]);
    }
    let work = work_dir("regress4", "nip11-public");
    let reply =
        "{\"software\":\"git+https://github.com/hoytech/strfry.git\",\"version\":\"1.0.4\"}";
    let out = redact_dir(&work, &[("replies/strfry/nip11.json", reply)], &[]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(
        read(&work, "out/replies/strfry/nip11.json").contains("github.com/hoytech/strfry"),
        "a public source was not kept"
    );
}

/// Fourth review MEDIUM: input that is dropped as a whole was never scanned, so
/// the exit-3 warning was lost. A secret in it still gives exit 3 and a log line
/// (which never holds the value).
#[test]
fn regression4_dropped_input_is_still_scanned() {
    let key = format!("nsec1{}", bech32_body(58));
    let deep = format!("{}\"{key}\"{}", "[".repeat(40), "]".repeat(40));
    let cases: Vec<(&str, &str, String)> = vec![
        // A top-level array where an object is expected.
        (
            "wrongtype",
            "replies/lnd/getinfo.json",
            format!("[\"{key}\"]"),
        ),
        // More than 32 levels deep: the reader gives up on the whole file.
        ("deep", "replies/lnd/getinfo.json", deep),
        // The description column is never kept.
        (
            "description",
            "systemctl-list-units.txt",
            format!("cron.service loaded active running Daemon {key}\n"),
        ),
        // The folder above a hidden-service folder is never kept.
        (
            "torparent",
            "torrc",
            format!("HiddenServiceDir /var/lib/tor/{key}/lnd9735/\n"),
        ),
    ];
    for (case, name, content) in &cases {
        let work = work_dir("regress4", case);
        let out = redact_dir(&work, &[(name, content)], &[]);
        assert_eq!(code(&out), 3, "{case}: {}", text(&out));
        assert_absent(&work, &out, &[&key]);
        let log = read(&work, "out/record-log.txt");
        assert!(
            log.contains("secret-shape-in-dropped-input"),
            "{case}: {log}"
        );
    }
}

/// Records a root folder (no Docker socket) in record mode.
fn record_root(work: &Path, files: &[(&str, &str)]) -> Output {
    let root = work.join("root");
    fs::create_dir_all(&root).unwrap();
    for (rel, content) in files {
        write_file(&root, rel, content);
    }
    run(
        work,
        &[
            "--out",
            "out",
            "--root",
            root.to_str().unwrap(),
            "--docker-socket",
            "none.sock",
        ],
        &[],
    )
}

/// Fourth review MEDIUM: a refused myNode or Umbrel file was logged by its full
/// path on the box (the private app name in it), and with a collected file in
/// the same folder the self-check then deleted the whole recording.
#[test]
fn regression4_refused_app_paths_are_not_logged() {
    // myNode: one collected file and one refused file (its name says "wallet").
    let work = work_dir("regress4", "mynode-refused");
    let out = record_root(
        &work,
        &[
            (
                "usr/share/mynode_apps/alicecanary/alicecanary.json",
                "{\"name\":\"Tor\",\"latest_version\":\"1.0\"}",
            ),
            ("usr/share/mynode_apps/alicecanary/wallet.json", "{}"),
        ],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(
        work.join("out/record-log.txt").exists(),
        "recording deleted"
    );
    assert_absent(&work, &out, &["alicecanary"]);
    let log = read(&work, "out/record-log.txt");
    assert!(log.contains("refused apps/app-1/refused-file "), "{log}");

    // Umbrel: the folder's name says "secret", so its manifest is refused.
    let work = work_dir("regress4", "umbrel-refused");
    let out = record_root(
        &work,
        &[(
            "home/umbrel/umbrel/app-data/alicecanary-secret/umbrel-app.yml",
            "id: alicecanary-secret\n",
        )],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(&work, &out, &["alicecanary"]);
    let log = read(&work, "out/record-log.txt");
    assert!(log.contains("refused apps/app-1/refused-file "), "{log}");
}

/// Fourth review MEDIUM: myNode's display names (`name`, `short_name`) were kept.
#[test]
fn regression4_mynode_display_names_are_private_unless_public() {
    let work = work_dir("regress4", "mynode-names");
    let out = redact_dir(
        &work,
        &[
            (
                "apps/alicecanary/alicecanary.json",
                "{\"name\":\"Alice Canary App\",\"short_name\":\"AliceApp\",\"latest_version\":\"1.0\"}",
            ),
            (
                "apps/lnd/lnd.json",
                "{\"name\":\"LND\",\"short_name\":\"lnd\",\"latest_version\":\"0.19.2\"}",
            ),
        ],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(&work, &out, &["alice"]);
    let lnd = read(&work, "out/apps/lnd/lnd.json");
    assert!(lnd.contains("\"name\":\"LND\""), "{lnd}");
    assert!(lnd.contains("0.19.2"), "{lnd}");
}

/// Fourth review MEDIUM: `id: <private>` stayed while the folder became `app-1`,
/// so the self-check threw the whole recording away.
#[test]
fn regression4_umbrel_id_follows_the_folder() {
    let work = work_dir("regress4", "umbrel-id");
    let out = redact_dir(
        &work,
        &[
            (
                "apps/alicecanary/umbrel-app.yml",
                "manifestVersion: 1\nid: alicecanary\nversion: \"1.2.3\"\n",
            ),
            ("apps/bitcoin/umbrel-app.yml", "id: bitcoin\n"),
            ("apps/quoted/umbrel-app.yml", "id: \"quoted\"\nversion: 2\n"),
        ],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(
        work.join("out/record-log.txt").exists(),
        "recording deleted"
    );
    assert_absent(&work, &out, &["alicecanary", "quoted"]);
    let got = read(&work, "out/apps/app-1/umbrel-app.yml");
    assert!(got.contains("id: app-1"), "{got}");
    assert!(read(&work, "out/apps/bitcoin/umbrel-app.yml").contains("id: bitcoin"));
}

/// Fourth review LOW: Docker never puts a digest in `RepoTags`, so a
/// `sha256:` + hex there is a scalar and goes.
#[test]
fn regression4_repotags_are_not_digest_fields() {
    let work = work_dir("regress4", "repotags");
    let scalar = "c3".repeat(32);
    let images = format!(
        "[{{\"Id\":\"sha256:{DIGEST}\",\"RepoTags\":[\"sha256:{scalar}\"],\"RepoDigests\":[\"docker.io/lightninglabs/lnd@sha256:{DIGEST}\"]}}]"
    );
    let out = redact_dir(&work, &[("docker-images.json", &images)], &[]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(&work, &out, &[&scalar]);
    let got = read(&work, "out/docker-images.json");
    assert!(got.contains(&format!("sha256:{DIGEST}")), "{got}");
}

/// Fourth review LOW: a public repository with a private tag kept the tag.
#[test]
fn regression4_public_repo_private_tag() {
    let work = work_dir("regress4", "tags");
    let ps = "[{\"Names\":[\"/lnd\"],\"Image\":\"docker.io/lightninglabs/lnd:alicecanary-build7\"},{\"Names\":[\"/lnd2\"],\"Image\":\"lightninglabs/lnd:v0.19.2-beta\"}]";
    let out = redact_dir(&work, &[("docker-ps.json", ps)], &[]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(&work, &out, &["alicecanary"]);
    let got = read(&work, "out/docker-ps.json");
    assert!(got.contains("lightninglabs/lnd:v0.19.2-beta"), "{got}");
    assert!(got.contains("docker.io/lightninglabs/lnd:"), "{got}");
}

/// Fourth review LOW: a private prefix in front of a key in a unit name was kept.
#[test]
fn regression4_unit_with_a_key_loses_its_private_prefix() {
    let work = work_dir("regress4", "unitkey");
    let key = format!("nsec1{}smhltgl", "q".repeat(51));
    let line = format!("alicecanary-{key}.service loaded active running\n");
    let out = redact_dir(&work, &[("systemctl-list-units.txt", &line)], &[]);
    assert_eq!(code(&out), 3, "{}", text(&out));
    assert_absent(&work, &out, &[&key, "alicecanary"]);
    assert!(read(&work, "out/systemctl-list-units.txt").contains("unit-1.service"));
}

/// Fourth review LOW: addresses were compared as text, so `fd00:0:0:0:0:0:0:1`
/// and `fd00::1` counted as different and the replacement equalled a source.
#[test]
fn regression4_replacements_differ_from_sources_in_normal_form() {
    let work = work_dir("regress4", "normal");
    let ps = "[{\"Names\":[\"/lnd\"],\"Ports\":[{\"IP\":\"fd00:0:0:0:0:0:0:1\",\"PrivatePort\":1},{\"IP\":\"FE80::0001\",\"PrivatePort\":2},{\"IP\":\"203.0.113.001\",\"PrivatePort\":3},{\"IP\":\"2001:0db8:0:0:0:0:0:1\",\"PrivatePort\":4}]}]";
    let out = redact_dir(&work, &[("docker-ps.json", ps)], &[]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let got = read(&work, "out/docker-ps.json").to_lowercase();
    for equal_to_source in [
        "\"fd00::1\"",
        "\"fe80::1\"",
        "\"203.0.113.1\"",
        "\"2001:db8::1\"",
    ] {
        assert!(
            !got.contains(equal_to_source),
            "a replacement equals a source address: {equal_to_source}\n{got}"
        );
    }
}

/// Fourth review LOW: the owner and mode check of `TMPDIR` was skipped when the
/// clean-launch marker was passed directly. It is repeated before `mktemp`.
#[test]
fn regression4_tmpdir_is_checked_before_mktemp() {
    let work = work_dir("regress4", "tmpdir");
    let farm = bin_farm(&work);
    let log = work.join("mktemp-args.txt");
    let real = tool("mktemp");
    fs::remove_file(farm.join("mktemp")).unwrap();
    write_stub(
        &farm,
        "mktemp",
        &format!(
            "printf '%s\\n' \"$*\" >> '{}'\nexec '{}' \"$@\"",
            log.display(),
            real.display()
        ),
    );
    fs::create_dir_all(work.join("root")).unwrap();
    let shared = work.join("shared");
    fs::create_dir_all(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    let root_s = work.join("root").to_str().unwrap().to_string();
    let args = [
        "--gd-clean-launch",
        "--out",
        "out",
        "--root",
        root_s.as_str(),
        "--docker-socket",
        "none.sock",
    ];
    let out = run_inner(&work, &args, &[("TMPDIR", shared.to_str().unwrap())], true);
    assert_eq!(code(&out), 0, "{}", text(&out));
    let used = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        !used.contains(shared.to_str().unwrap()),
        "mktemp was given a shared TMPDIR: {used}"
    );
    assert!(!used.is_empty(), "mktemp never ran");
}

/// Umbrel's `name:` display line is kept only for a public app id; for any other
/// app it becomes `name-N` (the same number for the same app).
#[test]
fn regression4_umbrel_display_name_is_private_unless_public() {
    let work = work_dir("regress4", "umbrel-name");
    let out = redact_dir(
        &work,
        &[
            (
                "apps/alicecanary/umbrel-app.yml",
                "name: Alicecanary Vault\nid: alicecanary\nversion: \"1.2.3\"\n",
            ),
            (
                "apps/bitcoin/umbrel-app.yml",
                "id: bitcoin\nname: Bitcoin Node\n",
            ),
            (
                "apps/other/umbrel-app.yml",
                "id: other\nname: Bobcanary Notes\n",
            ),
        ],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(&work, &out, &["alicecanary", "bobcanary", "vault"]);
    let private = read(&work, "out/apps/app-1/umbrel-app.yml");
    assert!(private.contains("name: name-"), "{private}");
    assert!(read(&work, "out/apps/bitcoin/umbrel-app.yml").contains("name: Bitcoin Node"));
}
// ---------- regression tests: fifth review ----------

/// The files of a realistic recording (an Umbrel docker pair with digest-pinned
/// images, compose labels, a bind mount, ten exposed ports, a real `lncli
/// getinfo` with its features, a NIP-11 reply with a five-word name).
fn realistic_files() -> Vec<(String, String)> {
    let dir = repo_file("tests/synthetic/record-setup-realistic");
    list_files(&dir)
        .into_iter()
        .map(|f| {
            let body = fs::read_to_string(dir.join(&f)).unwrap();
            (f, body)
        })
        .collect()
}

fn redact_owned(work: &Path, files: &[(String, String)]) -> Output {
    let refs: Vec<(&str, &str)> = files
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    redact_dir(work, &refs, &[])
}

/// Fifth review HIGH 1 and 2 and MEDIUM 1: an ordinary Umbrel node with an LND
/// must give exit 0, keep its digests and enum values, and replace nothing as a
/// mnemonic.
#[test]
fn regression5_realistic_umbrel_recording_exits_0() {
    let work = work_dir("regress5", "realistic");
    let out = redact_owned(&work, &realistic_files());
    assert_eq!(code(&out), 0, "{}", text(&out));
    let log = read(&work, "out/record-log.txt");
    assert!(!log.contains("seed-words"), "{log}");
    assert!(!log.contains("secret-shape-in-dropped-input"), "{log}");
    assert!(log.contains("secret-shaped-values-removed 0"), "{log}");
    let ps = read(&work, "out/docker-ps.json");
    let images = read(&work, "out/docker-images.json");
    for c in ["a", "b", "c", "d"] {
        let digest = c.repeat(64);
        assert!(ps.contains(&format!("@sha256:{digest}")), "{ps}");
        assert!(images.contains(&format!("@sha256:{digest}")), "{images}");
    }
    assert_eq!(ps.matches("\"tcp\"").count(), 16, "{ps}");
    assert_eq!(ps.matches("\"running\"").count(), 4, "{ps}");
    assert!(read(&work, "out/replies/lnd/getinfo.json").contains("0.18.3-beta"));
}

/// Fifth review HIGH 1: `Image` is `repo:tag@sha256:X` and RepoDigests holds the
/// same X; the digest stays in both (exit 4 before).
#[test]
fn regression5_digest_pinned_image_keeps_its_digest() {
    let work = work_dir("regress5", "pinned");
    let x = "d".repeat(64);
    let ps = format!(
        "[{{\"Names\":[\"/lnd\"],\"Image\":\"lightninglabs/lnd:v0.18.0-beta@sha256:{x}\",\"ImageID\":\"sha256:{DIGEST}\",\"State\":\"running\"}}]"
    );
    let images = format!(
        "[{{\"Id\":\"sha256:{DIGEST}\",\"RepoTags\":[\"lightninglabs/lnd:v0.18.0-beta\"],\"RepoDigests\":[\"lightninglabs/lnd@sha256:{x}\"]}}]"
    );
    let out = redact_dir(
        &work,
        &[("docker-ps.json", &ps), ("docker-images.json", &images)],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert!(read(&work, "out/docker-ps.json").contains(&format!("@sha256:{x}")));
    assert!(read(&work, "out/docker-images.json").contains(&format!("@sha256:{x}")));
    // A digest alone in the middle of an Image value is still a scalar.
    let work = work_dir("regress5", "pinned2");
    let scalar = "f".repeat(64);
    let ps = format!("[{{\"Names\":[\"/lnd\"],\"Image\":\"lnd-sha256:{scalar}-x\"}}]");
    let out = redact_dir(&work, &[("docker-ps.json", &ps)], &[]);
    assert_absent(&work, &out, &[&scalar]);
}

/// Fifth review HIGH 2: files an ordinary node has, one by one.
#[test]
fn regression5_ordinary_node_files_exit_0() {
    let files = realistic_files();
    let get = |n: &str| files.iter().find(|(f, _)| f == n).unwrap().1.clone();
    let cases: Vec<(&str, &str, String)> = vec![
        ("g1", "replies/lnd/getinfo.json", get("replies/lnd/getinfo.json")),
        (
            "n1",
            "replies/strfry/nip11.json",
            get("replies/strfry/nip11.json"),
        ),
        (
            "fp1b",
            "docker-ps.json",
            "[{\"Names\":[\"/bitcoin_app_proxy_1\"],\"State\":\"running\",\"Labels\":{\"com.docker.compose.project.config_files\":\"/home/umbrel/umbrel/app-data/bitcoin/docker-compose.yml,/home/umbrel/umbrel/app-data/bitcoin/docker-compose.app_proxy.yml\"}}]".to_string(),
        ),
        (
            "fp2",
            "docker-ps.json",
            "[{\"Names\":[\"/bitcoin_bitcoind_1\"],\"Image\":\"getumbrel/bitcoind:v27.0\",\"State\":\"running\",\"Mounts\":[{\"Type\":\"bind\",\"Source\":\"/home/umbrel/umbrel/app-data/bitcoin/data/bitcoin\",\"Destination\":\"/data/.bitcoin\",\"Mode\":\"\",\"RW\":true,\"Propagation\":\"rprivate\"}]}]".to_string(),
        ),
    ];
    for (case, name, body) in &cases {
        let work = work_dir("regress5", case);
        let out = redact_dir(&work, &[(name, body)], &[]);
        assert_eq!(code(&out), 0, "{case}: {}", text(&out));
        let log = read(&work, "out/record-log.txt");
        assert!(!log.contains("secret-shape-in"), "{case}: {log}");
    }
}

/// Fifth review MEDIUM 1: enum, port and name fields are never joined into a
/// "mnemonic" (ten exposed ports, a source and a title label).
#[test]
fn regression5_enum_fields_are_never_joined() {
    let ports: Vec<String> = [
        8332, 8333, 18332, 18333, 18443, 18444, 28332, 28333, 38332, 38333,
    ]
    .iter()
    .map(|p| format!("{{\"PrivatePort\":{p},\"Type\":\"tcp\"}}"))
    .collect();
    let ps1 = format!(
        "[{{\"Names\":[\"/bitcoind\"],\"State\":\"running\",\"Ports\":[{}]}},{{\"Names\":[\"/tor\"],\"State\":\"running\",\"Ports\":[{{\"PrivatePort\":9050,\"Type\":\"tcp\"}}]}}]",
        ports.join(",")
    );
    let strfry = "{\"Names\":[\"/strfry\"],\"Image\":\"hoytech/strfry:1.0.4\",\"State\":\"running\",\"Status\":\"Up 2 hours\",\"Labels\":{\"org.opencontainers.image.source\":\"https://github.com/hoytech/strfry\",\"org.opencontainers.image.title\":\"strfry\"},\"Ports\":[{\"PrivatePort\":7777,\"Type\":\"tcp\"},{\"PrivatePort\":7778,\"Type\":\"tcp\"},{\"PrivatePort\":7779,\"Type\":\"tcp\"},{\"PrivatePort\":7780,\"Type\":\"tcp\"}]}";
    let tor = "{\"Names\":[\"/tor\"],\"Image\":\"tor:latest\",\"State\":\"running\",\"Status\":\"Up 2 hours\",\"Ports\":[{\"PrivatePort\":9050,\"Type\":\"tcp\"}]}";
    for (case, ps) in [
        ("ps1", ps1),
        ("fp3a", format!("[{strfry}]")),
        ("fp3", format!("[{strfry},{tor}]")),
    ] {
        let work = work_dir("regress5", case);
        let out = redact_dir(&work, &[("docker-ps.json", &ps)], &[]);
        assert_eq!(code(&out), 0, "{case}: {}", text(&out));
        let got = read(&work, "out/docker-ps.json");
        assert_eq!(
            got.matches("\"tcp\"").count(),
            ps.matches("\"tcp\"").count(),
            "{case}: {got}"
        );
        assert_eq!(
            got.matches("\"running\"").count(),
            ps.matches("\"running\"").count(),
            "{case}: {got}"
        );
    }
}

/// Fifth review MEDIUM 2: the ids in an Umbrel `dependencies:` list get the same
/// pseudonym as a folder of that name.
#[test]
fn regression5_umbrel_dependencies_are_pseudonymised() {
    // The dependency is not installed (t7).
    let work = work_dir("regress5", "deps-alone");
    let out = redact_dir(
        &work,
        &[(
            "apps/bitcoin/umbrel-app.yml",
            "id: bitcoin\ndependencies:\n  - alicecanary-vault\n",
        )],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(&work, &out, &["alicecanary"]);
    // The dependency is installed too (t6): same pseudonym, no exit 4.
    let work = work_dir("regress5", "deps-both");
    let out = redact_dir(
        &work,
        &[
            (
                "apps/alicecanary-vault/umbrel-app.yml",
                "id: alicecanary-vault\n",
            ),
            (
                "apps/bitcoin/umbrel-app.yml",
                "id: bitcoin\ndependencies:\n  - lightning\n  - alicecanary-vault\n",
            ),
        ],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(&work, &out, &["alicecanary"]);
    let got = read(&work, "out/apps/bitcoin/umbrel-app.yml");
    assert!(got.contains("  - lightning\n"), "{got}");
    assert!(got.contains("  - app-1\n"), "{got}");
}

/// Fifth review MEDIUM (pi 2 and L4, L5): free operator text in version-like
/// fields goes; versions stay.
#[test]
fn regression5_version_fields_keep_only_versions() {
    let work = work_dir("regress5", "versions");
    let images = "[{\"Id\":\"sha256:aa\",\"Labels\":{\"org.opencontainers.image.version\":\"alicecanary-notes\",\"org.opencontainers.image.revision\":\"0123abc\"}},{\"Id\":\"sha256:bb\",\"Labels\":{\"org.opencontainers.image.version\":\"v0.19.2-beta\"}}]"
        .replace("sha256:aa", &format!("sha256:{DIGEST}"))
        .replace("sha256:bb", &format!("sha256:{}", "ab".repeat(32)));
    let ps = "[{\"Names\":[\"/a\"],\"Image\":\"lightninglabs/lnd:v0.19.2-alicecanary\"},{\"Names\":[\"/b\"],\"Image\":\"lightninglabs/lnd:v0.19.2-beta\"},{\"Names\":[\"/c\"],\"Image\":\"lightninglabs/lnd:v0.19.2-rc1\"}]";
    let umbrel =
        "id: bitcoin\nname: Bitcoin Node\nversion: \"alicecanary-1\"\ncategory: bobcanary\n";
    let umbrel2 = "id: lightning\nversion: \"0.19.2\"\ncategory: bitcoin\n";
    let dpkg = "tor\t0.4.8.16-1\tii \nopenssl\t1:3.0.11-1~deb12u2\tii \ncurl\talicecanary\tii \n";
    let out = redact_dir(
        &work,
        &[
            ("docker-images.json", &images),
            ("docker-ps.json", ps),
            ("apps/bitcoin/umbrel-app.yml", umbrel),
            ("apps/lightning/umbrel-app.yml", umbrel2),
            ("dpkg-query.txt", dpkg),
        ],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(&work, &out, &["alicecanary", "bobcanary"]);
    let all = all_output_text(&work.join("out"));
    for kept in [
        "v0.19.2-beta",
        "v0.19.2-rc1",
        "lnd:v0.19.2\"",
        "0123abc",
        "version: \"0.19.2\"",
        "category: bitcoin",
        "category: category-other",
        "0.4.8.16-1",
        "1:3.0.11-1~deb12u2",
    ] {
        assert!(all.contains(kept), "lost: {kept}\n{all}");
    }
}

/// Fifth review MEDIUM (pi 4): every removed secret counts, whatever its class.
#[test]
fn regression5_every_removed_secret_gives_exit_3() {
    let cases = [
        ("password", "bitcoind --rpcpassword Hunter2Hunter2xx"),
        (
            "bearer",
            "Authorization: Bearer CanaryBearer9TokenValue0123456789abcdefABC",
        ),
        (
            "userinfo",
            "connect redis://canaryuser2:canarypw99@192.168.150.150:6379",
        ),
        ("token", "rune CanaryTokenCanary1234567890abcdefXYZ"),
    ];
    for (case, line) in cases {
        let work = work_dir("regress5", case);
        let input = binaries(&[line]);
        let out = redact_dir(&work, &[("binaries-version.txt", &input)], &[]);
        assert_eq!(code(&out), 3, "{case}: {}", text(&out));
        let log = read(&work, "out/record-log.txt");
        assert!(
            !log.contains("secret-shaped-values-removed 0"),
            "{case}: {log}"
        );
    }
}

/// Fifth review LOW (pi 5): an interface name chosen by the owner is replaced.
#[test]
fn regression5_ss_zone_ids_are_pseudonymised() {
    let work = work_dir("regress5", "zones");
    let ss = "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n\
LISTEN 0 4096 [fe80::1%alicevpn]:9735 [::]:*\n\
LISTEN 0 4096 [fe80::1%eth0]:9736 [::]:*\n\
LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\n";
    let out = redact_dir(&work, &[("ss-tlnp.txt", ss)], &[]);
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(&work, &out, &["alicevpn"]);
    let got = read(&work, "out/ss-tlnp.txt");
    assert!(got.contains("%eth0]"), "{got}");
    assert!(got.contains("%lo:53"), "{got}");
    assert!(got.contains("%iface-1]"), "{got}");
}

/// Fifth review LOW (pi 8): an input value that equals a placeholder is not
/// emitted as it is.
#[test]
fn regression5_placeholder_shaped_input_is_not_emitted_verbatim() {
    let work = work_dir("regress5", "placeholder");
    let out = redact_dir(
        &work,
        &[
            ("apps/app-1/umbrel-app.yml", "id: app-1\n"),
            ("apps/alicecanary/umbrel-app.yml", "id: alicecanary\n"),
        ],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    let files = list_files(&work.join("out"));
    assert!(
        files.iter().all(|f| !f.contains("app-1/")),
        "an input name came out as it was: {files:?}"
    );
    assert_absent(&work, &out, &["alicecanary"]);

    // The same in record mode (a real run): the log's first line is always the
    // script's own there, so it must not switch the guard off.
    let work = work_dir("regress5", "placeholder-record");
    let out = record_root(
        &work,
        &[
            (
                "home/umbrel/umbrel/app-data/alice-shop/umbrel-app.yml",
                "id: alice-shop\nname: Alice Shop\n",
            ),
            (
                "home/umbrel/umbrel/app-data/other/umbrel-app.yml",
                "id: other\nname: name-1\n",
            ),
        ],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    let first = read(&work, "out/apps/app-1/umbrel-app.yml");
    assert!(!first.contains("name: name-1"), "{first}");
    assert!(!read(&work, "out/apps/app-2/umbrel-app.yml").contains("name: name-1\n"));
}

/// Fifth review LOW C: a version-shaped value keeps no private suffix: a hex
/// build token needs a digit, a long number is not a build number, and the
/// Debian revision is checked token by token.
#[test]
fn regression5_version_suffixes_are_checked() {
    let work = work_dir("regress5", "suffix");
    let ps = "[{\"Names\":[\"/a\"],\"Image\":\"lightninglabs/lnd:v1.0-defaced\"},{\"Names\":[\"/b\"],\"Image\":\"lightninglabs/lnd:v1.0-5551234567\"},{\"Names\":[\"/c\"],\"Image\":\"lightninglabs/lnd:v1.0-3f2a9c1\"}]";
    let umbrel = "id: bitcoin\nversion: \"v1.0-defaced\"\n";
    let dpkg = "alpha\t1.0-alicecanary1\tii \nbeta\t2:1.0+maxbuild\tii \ntor\t0.4.8.16-1\tii \nopenssl\t1:3.0.11-1~deb12u2\tii \nlibx\t1.2.3+dfsg-4+b1\tii \nlibz\t1.0-0ubuntu0.22.04.1\tii \n";
    let out = redact_dir(
        &work,
        &[
            ("docker-ps.json", ps),
            ("apps/bitcoin/umbrel-app.yml", umbrel),
            ("dpkg-query.txt", dpkg),
        ],
        &[],
    );
    assert_eq!(code(&out), 0, "{}", text(&out));
    assert_absent(
        &work,
        &out,
        &["defaced", "5551234567", "alicecanary1", "maxbuild"],
    );
    let all = all_output_text(&work.join("out"));
    for kept in [
        "lnd:v1.0-3f2a9c1",
        "0.4.8.16-1",
        "1:3.0.11-1~deb12u2",
        "1.2.3+dfsg-4+b1",
        "1.0-0ubuntu0.22.04.1",
    ] {
        assert!(all.contains(kept), "lost: {kept}\n{all}");
    }
}

/// Fifth review LOW 1: the kept value columns of a table file are also searched,
/// joined, for 12 different words (flag only: exit 3 and a log line); a list of
/// `off` switches is not a phrase.
#[test]
fn regression5_table_value_columns_are_flagged() {
    let words = [
        "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
        "abuse", "access", "accident",
    ];
    let deps: String = words.iter().map(|w| format!("  - {w}\n")).collect();
    let umbrel = format!("id: bitcoin\ndependencies:\n{deps}");
    let dpkg: String = words
        .iter()
        .enumerate()
        .map(|(i, w)| format!("pkg{i}\t{w}\tii \n"))
        .collect();
    let version: String = "codeVersion=\"abandon\"\ncodeRelease=\"ability\"\n".to_string();
    for (case, name, body) in [
        ("umbrel", "apps/bitcoin/umbrel-app.yml", umbrel),
        ("dpkg", "dpkg-query.txt", dpkg),
        ("rbversion", "raspiblitz-version.txt", version.clone()),
    ] {
        let work = work_dir("regress5", case);
        let out = redact_dir(&work, &[(name, &body)], &[]);
        if case == "rbversion" {
            // Two words are not a phrase.
            assert_eq!(code(&out), 0, "{case}: {}", text(&out));
            continue;
        }
        assert_eq!(code(&out), 3, "{case}: {}", text(&out));
        let log = read(&work, "out/record-log.txt");
        assert!(
            log.contains("seed-shaped-values-in-columns"),
            "{case}: {log}"
        );
    }
    let work = work_dir("regress5", "offs");
    let conf: String = (0..20)
        .map(|i| format!("sw{i}=\"off\"\nlnd=\"off\"\nrtl=\"off\"\n"))
        .collect();
    let out = redact_dir(&work, &[("raspiblitz-conf.txt", &conf)], &[]);
    assert_eq!(code(&out), 0, "{}", text(&out));
}

// ---------- property tests ----------

const SEPARATORS: [&str; 8] = [" ", "\t", ", ", "-", "_", ":", "\n", " - "];

const PLATFORM_DEFAULTS: [&str; 26] = [
    "admin",
    "bitcoin",
    "lnd",
    "btcpay",
    "electrs",
    "fulcrum",
    "rtl",
    "thunderhub",
    "mempool",
    "tor",
    "debian-tor",
    "lndg",
    "joinmarket",
    "umbrel",
    "start9",
    "mynode",
    "pi",
    "ubuntu",
    "debian",
    "root",
    "raspiblitz",
    "raspberrypi",
    "localhost",
    "nixos",
    "operator",
    "user",
];

const SEED_WORDS: [&str; 24] = [
    "zorble", "plinth", "quorra", "mavrik", "tenzo", "brivel", "colmar", "yeston", "fandro",
    "glimmer", "huxley", "nimbus", "orvane", "pelter", "quillon", "ravel", "sundry", "tarnish",
    "umbral", "vexil", "wombat", "xylem", "yarrow", "zephyl",
];

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const LOWER_DIGITS: &str = "abcdefghijklmnopqrstuvwxyz0123456789";
const ALNUM: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const HEX: &str = "0123456789abcdef";
const B58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BECH: &str = "023456789acdefghjklmnpqrstuvwxyz";
const B32: &str = "abcdefghijklmnopqrstuvwxyz234567";
const B64URL: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Lines that must come through untouched: valid in a `--version` line.
fn fillers() -> Vec<String> {
    vec![
        "Bitcoind".into(),
        "port=8333".into(),
        "0.0.0.0:8333".into(),
        "127.0.0.1".into(),
        "running".into(),
        "v0.19.2-beta".into(),
        "lnd.service".into(),
        "8333/tcp".into(),
    ]
}

/// One planted fake: what class the recorder should file it under, the exact
/// value that must vanish, and where it is planted.
#[derive(Clone, Debug)]
struct Planted {
    class: &'static str,
    value: String,
    line: String,
}

fn planted(class: &'static str, value: String, line: String) -> Planted {
    Planted { class, value, line }
}

fn chars(alphabet: &'static str, len: std::ops::RangeInclusive<usize>) -> BoxedStrategy<String> {
    let set: Vec<char> = alphabet.chars().collect();
    proptest::collection::vec(proptest::sample::select(set), len)
        .prop_map(|v| v.into_iter().collect::<String>())
        .boxed()
}

/// Canaries that sit in a `--version` line (text classes: secrets, keys,
/// home paths, e-mail addresses, MACs, tokens, seed words).
fn text_canary() -> BoxedStrategy<Planted> {
    let mut all: Vec<BoxedStrategy<Planted>> = Vec::new();
    all.push(
        proptest::collection::vec(16u32..=255, 6)
            .prop_filter("first byte 02 is the placeholder form", |b| b[0] != 0x02)
            .prop_map(|b| {
                let v = b
                    .iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<Vec<_>>()
                    .join(":");
                planted("mac", v.clone(), v)
            })
            .boxed(),
    );
    all.push(
        chars(B32, 56..=56)
            .prop_filter("placeholder form", |c| !c.starts_with("redacted"))
            .prop_map(|c| planted("onion", c.clone(), format!("{c}.onion")))
            .boxed(),
    );
    for (class, prefixes) in [
        ("xpub", ["xpub", "tpub", "zpub"]),
        ("xprv", ["xprv", "tprv", "zprv"]),
    ] {
        all.push(
            (
                proptest::sample::select(prefixes.to_vec()),
                chars(B58, 107..=107),
            )
                .prop_map(move |(p, rest)| {
                    let v = format!("{p}{rest}");
                    planted(class, v.clone(), v)
                })
                .boxed(),
        );
    }
    for (class, prefix) in [("npub", "npub1"), ("nsec", "nsec1")] {
        all.push(
            chars(BECH, 58..=58)
                .prop_map(move |rest| {
                    let v = format!("{prefix}{rest}");
                    planted(class, v.clone(), v)
                })
                .boxed(),
        );
    }
    all.push(
        chars(B64URL, 57..=57)
            .prop_map(|rest| {
                let v = format!("Rr9{rest}");
                planted("token", v.clone(), v)
            })
            .boxed(),
    );
    all.push(
        chars(B64URL, 37..=37)
            .prop_map(|rest| {
                let v = format!("Bb7{rest}");
                planted(
                    "bearer-token",
                    v.clone(),
                    format!("Authorization: Bearer {v}"),
                )
            })
            .boxed(),
    );
    all.push(
        chars(LOWER, 6..=10)
            .prop_filter("platform default or a filler word", |c| {
                !PLATFORM_DEFAULTS.contains(&c.as_str()) && !c.contains("running")
            })
            .prop_map(|c| planted("home-user", c.clone(), format!("/home/{c}/.config")))
            .boxed(),
    );
    all.push(
        (chars(LOWER, 6..=6), chars(LOWER, 6..=10))
            .prop_map(|(a, b)| {
                let v = format!("{a}@{b}.com");
                planted("email", v.clone(), v)
            })
            .boxed(),
    );
    all.push(
        chars(ALNUM, 16..=24)
            .prop_filter("needs a digit", |c| c.chars().any(|x| x.is_ascii_digit()))
            .prop_map(|c| planted("secret-value", c.clone(), format!("rpcpassword={c}")))
            .boxed(),
    );
    all.push(
        (
            proptest::collection::vec(proptest::sample::select(SEED_WORDS.to_vec()), 12),
            proptest::sample::select(SEPARATORS.to_vec()),
        )
            .prop_map(|(w, sep)| {
                let v = w.join(sep);
                planted("seed-words", v.clone(), v)
            })
            .boxed(),
    );
    all.push(
        chars(HEX, 64..=64)
            .prop_map(|c| planted("hex64", c.clone(), format!("key {c}")))
            .boxed(),
    );
    all.push(
        (
            proptest::sample::select(vec!["02", "03"]),
            chars(HEX, 64..=64),
        )
            .prop_map(|(p, c)| {
                let v = format!("{p}{c}");
                planted("node-pubkey", v.clone(), v)
            })
            .boxed(),
    );
    all.push(
        chars(B58, 51..=51)
            .prop_map(|c| {
                let v = format!("K{c}");
                planted("wif-key", v.clone(), v)
            })
            .boxed(),
    );
    proptest::strategy::Union::new(all).boxed()
}

fn public_ipv4() -> BoxedStrategy<String> {
    (11u32..=99, 101u32..=199, 101u32..=199, 101u32..=199)
        .prop_map(|(a, b, c, d)| format!("{a}.{b}.{c}.{d}"))
        .boxed()
}

fn address_canary() -> BoxedStrategy<Planted> {
    let all: Vec<BoxedStrategy<Planted>> = vec![
        public_ipv4()
            .prop_map(|v| planted("ipv4-public", v.clone(), v))
            .boxed(),
        (any::<bool>(), 16u32..=31, 101u32..=199, 101u32..=199)
            .prop_map(|(first, mid, c, d)| {
                let v = if first {
                    format!("192.168.{c}.{d}")
                } else {
                    format!("172.{mid}.{c}.{d}")
                };
                planted("ipv4-private", v.clone(), v)
            })
            .boxed(),
        (1u32..=15, proptest::collection::vec(chars(HEX, 4..=4), 7))
            .prop_map(|(first, rest)| {
                let v = format!("2a0{first:x}:{}", rest.join(":"));
                planted("ipv6-global", v.clone(), v)
            })
            .boxed(),
        proptest::collection::vec(chars(HEX, 4..=4), 4)
            .prop_map(|g| {
                let v = format!("fe80::{}", g.join(":"));
                planted("ipv6-link-local", v.clone(), v)
            })
            .boxed(),
    ];
    proptest::strategy::Union::new(all).boxed()
}

fn term_canary() -> BoxedStrategy<Planted> {
    (chars(LOWER, 5..=8), chars(LOWER_DIGITS, 4..=4))
        .prop_map(|(a, b)| format!("{a}-{b}"))
        .prop_filter("a filler word inside", |t| !t.contains("running"))
        .prop_map(|t| planted("term", t.clone(), t))
        .boxed()
}

fn domain_canary() -> BoxedStrategy<Planted> {
    (
        chars(LOWER, 6..=10),
        chars(LOWER, 6..=10),
        proptest::sample::select(vec!["com", "io", "net", "local", "watch", "social"]),
    )
        .prop_map(|(a, b, tld)| {
            let v = format!("{a}.{b}.{tld}");
            planted("domain", v.clone(), v)
        })
        .boxed()
}

/// One generated case: canaries placed in allowlisted fields (where layer 2 is
/// the only defence), fillers, and one canary in each dropped field.
#[derive(Clone, Debug)]
struct Case {
    text: Vec<Planted>,
    addresses: Vec<(Planted, bool)>,
    terms: Vec<Planted>,
    domains: Vec<(Planted, u8)>,
    fillers: Vec<usize>,
    dropped: Vec<String>,
    /// Sometimes the docker files are an Umbrel-style pair: a digest-pinned image,
    /// labels, a bind mount and ten exposed ports.
    rich: bool,
}

/// The label value of the rich container that the recorder must replace.
const RICH_CONFIG_FILES: &str = "/home/umbrel/umbrel/app-data/bitcoin/docker-compose.yml";

fn case_strategy() -> BoxedStrategy<Case> {
    (
        proptest::collection::vec(text_canary(), 0..=12),
        proptest::collection::vec((address_canary(), any::<bool>()), 0..=6),
        proptest::collection::vec(term_canary(), 0..=3),
        proptest::collection::vec((domain_canary(), 0u8..3), 0..=4),
        proptest::collection::vec(0..fillers().len(), 0..=8),
        proptest::collection::vec(chars(ALNUM, 12..=12), 4),
        any::<bool>(),
    )
        .prop_map(
            |(text, addresses, terms, domains, fillers, dropped, rich)| Case {
                text,
                addresses,
                terms,
                domains,
                fillers,
                dropped,
                rich,
            },
        )
        .boxed()
}

impl Case {
    /// Where each domain canary really goes: only one can be the NIP-11 software.
    fn domain_places(&self) -> Vec<(Planted, u8)> {
        let mut software_set = false;
        let mut out = Vec::new();
        for (p, place) in &self.domains {
            let mut place = *place;
            if place == 2 && software_set {
                place = 1;
            }
            if place == 2 {
                software_set = true;
            }
            out.push((p.clone(), place));
        }
        out
    }

    /// The canaries, each filed under the class the recorder should use: a
    /// container name and an image reference are pseudonymised by field.
    fn planted(&self) -> Vec<Planted> {
        let mut all = self.text.clone();
        all.extend(self.addresses.iter().map(|(p, _)| p.clone()));
        for t in &self.terms {
            all.push(Planted {
                class: "container-name",
                ..t.clone()
            });
        }
        for (p, place) in self.domain_places() {
            let class = if place == 2 { "software" } else { "image" };
            all.push(Planted { class, ..p });
        }
        all
    }

    fn terms(&self) -> Vec<String> {
        let mut t: Vec<String> = self.terms.iter().map(|p| p.value.clone()).collect();
        t.sort();
        t.dedup();
        t
    }

    /// The `--version` text, and the filler lines in it.
    fn binaries(&self) -> String {
        let fill = fillers();
        let mut lines: Vec<(String, bool)> = Vec::new();
        for p in &self.text {
            lines.push((p.line.clone(), p.class == "seed-words"));
        }
        for i in &self.fillers {
            lines.push((fill[*i].clone(), false));
        }
        // A mnemonic gets a block to itself: it must not touch other lowercase words.
        let mut chunks: Vec<Vec<String>> = Vec::new();
        let mut closed = true;
        for (line, seed) in lines {
            if seed || closed || chunks.last().is_none_or(|c| c.len() >= 3) {
                chunks.push(vec![line]);
                closed = seed;
            } else if let Some(c) = chunks.last_mut() {
                c.push(line);
            }
        }
        let mut out = String::new();
        for (n, chunk) in chunks.iter().enumerate() {
            out.push_str(&format!("== /usr/local/bin/t{n}\n{}\n", chunk.join("\n")));
        }
        out
    }

    fn files(&self) -> Vec<(String, String)> {
        let d = &self.dropped;
        let mut containers: Vec<String> = Vec::new();
        for p in &self.terms {
            containers.push(format!(
                "{{\"Names\":[\"/{}\"],\"Image\":\"docker.io/lightninglabs/lnd:v0.19.2-beta\",\"Command\":\"{}\",\"State\":\"running\",\"Status\":\"Up 1 hour\"}}",
                p.value, d[0]
            ));
        }
        let mut images: Vec<String> = Vec::new();
        let mut software = String::from("git+https://github.com/hoytech/strfry.git");
        for (p, place) in &self.domain_places() {
            match place {
                0 => containers.push(format!(
                    "{{\"Names\":[\"/lnd\"],\"Image\":\"{}/app:1\",\"Mounts\":[{{\"Source\":\"/data/{}\"}}]}}",
                    p.value, d[1]
                )),
                1 => images.push(format!("\"{}/app:1\"", p.value)),
                _ => software = format!("https://{}/x", p.value),
            }
        }
        let mut ss = String::from(
            "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nLISTEN 0 128 0.0.0.0:8333 0.0.0.0:*\n",
        );
        for (p, in_docker) in &self.addresses {
            if *in_docker {
                containers.push(format!(
                    "{{\"Names\":[\"/lnd\"],\"Image\":\"docker.io/lightninglabs/lnd:v0.19.2-beta\",\"Ports\":[{{\"IP\":\"{}\",\"PrivatePort\":8333,\"Type\":\"tcp\"}}]}}",
                    p.value
                ));
            } else if p.value.contains(':') {
                ss.push_str(&format!("LISTEN 0 128 [{}]:9735 [::]:*\n", p.value));
            } else {
                ss.push_str(&format!("LISTEN 0 128 {}:9735 0.0.0.0:*\n", p.value));
            }
        }
        let mut extra_images = String::new();
        if self.rich {
            let ports: Vec<String> = (0..10)
                .map(|i| format!("{{\"PrivatePort\":{},\"Type\":\"tcp\"}}", 8300 + i))
                .collect();
            containers.push(format!(
                "{{\"Names\":[\"/lnd\"],\"Image\":\"lightninglabs/lnd:v0.19.2-beta@sha256:{DIGEST}\",\"ImageID\":\"sha256:{DIGEST}\",\"State\":\"running\",\"Status\":\"Up 2 hours\",\"Labels\":{{\"com.docker.compose.project.config_files\":\"{RICH_CONFIG_FILES}\",\"org.opencontainers.image.source\":\"https://github.com/hoytech/strfry\",\"org.opencontainers.image.title\":\"strfry\"}},\"Mounts\":[{{\"Type\":\"bind\",\"Source\":\"/home/umbrel/umbrel/app-data/bitcoin/data/bitcoin\",\"Destination\":\"/data/.bitcoin\"}}],\"Ports\":[{}]}}",
                ports.join(",")
            ));
            extra_images = format!(
                ",{{\"Id\":\"sha256:{DIGEST}\",\"RepoDigests\":[\"lightninglabs/lnd@sha256:{DIGEST}\"]}}"
            );
        }
        let ps = format!("[{}]", containers.join(","));
        let imgs = format!(
            "[{{\"Id\":\"sha256:{DIGEST}\",\"RepoTags\":[{}]}}{extra_images}]",
            if images.is_empty() {
                "\"docker.io/lightninglabs/lnd:v0.19.2-beta\"".to_string()
            } else {
                images.join(",")
            }
        );
        let nip11 = format!(
            "{{\"description\":\"{}\",\"software\":\"{software}\",\"version\":\"1.0.4\"}}",
            d[2]
        );
        let lnd = format!("{{\"alias\":\"{}\",\"version\":\"0.19.2-beta\"}}", d[3]);
        vec![
            ("docker-ps.json".into(), ps),
            ("docker-images.json".into(), imgs),
            ("replies/strfry/nip11.json".into(), nip11),
            ("replies/lnd/getinfo.json".into(), lnd),
            ("ss-tlnp.txt".into(), ss),
            ("binaries-version.txt".into(), self.binaries()),
        ]
    }
}

/// The text with every replacement address (the recorder's own ranges) set to `ADDR`.
fn mask_addresses(bytes: &[u8]) -> String {
    let re = regex::Regex::new(
        r"10\.200\.\d+\.\d+|203\.0\.113\.\d+|198\.51\.100\.\d+|192\.0\.2\.\d+|fd00::[0-9a-f]+|fe80::[0-9a-f]+|2001:db8::[0-9a-f]+",
    )
    .unwrap();
    re.replace_all(&String::from_utf8_lossy(bytes), "ADDR")
        .into_owned()
}

static CASE: AtomicUsize = AtomicUsize::new(0);

struct Run {
    work: PathBuf,
    out: Output,
}

fn run_case(test: &str, case: &Case) -> Run {
    let n = CASE.fetch_add(1, Ordering::SeqCst);
    let work = work_dir(test, &format!("c{n}"));
    let files = case.files();
    let refs: Vec<(&str, &str)> = files
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    let terms = case.terms();
    let term_refs: Vec<&str> = terms.iter().map(String::as_str).collect();
    let out = redact_dir(&work, &refs, &term_refs);
    Run { work, out }
}

fn data_files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    list_files(dir)
        .into_iter()
        .map(|f| {
            let bytes = fs::read(dir.join(&f)).unwrap();
            (f, bytes)
        })
        .collect()
}

proptest! {
    #![proptest_config(proptest_config(64))]

    #[test]
    fn redaction_never_leaks_a_canary(case in case_strategy()) {
        let r = run_case("leak", &case);
        let planted = case.planted();
        let expected_code = if planted.iter().any(|p| SECRET_CLASSES.contains(&p.class)) { 3 } else { 0 };
        prop_assert_eq!(code(&r.out), expected_code, "{}", text(&r.out));

        let out_dir = r.work.join("out");
        let everything = format!("{}\n{}", all_output_text(&out_dir), text(&r.out)).to_lowercase();
        for p in &planted {
            prop_assert!(
                !everything.contains(&p.value.to_lowercase()),
                "a canary of class {} survived: {}", p.class, p.value
            );
        }
        for d in &case.dropped {
            prop_assert!(!everything.contains(&d.to_lowercase()), "a dropped-field canary survived: {}", d);
        }
        if case.rich {
            // The compose label is not a kept field: its path is dropped.
            prop_assert!(!everything.contains(RICH_CONFIG_FILES), "a dropped label survived");
        }

        let fill = fillers();
        let before = case.binaries();
        let after = fs::read_to_string(out_dir.join("binaries-version.txt")).unwrap_or_default();
        for f in &fill {
            prop_assert_eq!(
                before.matches(f.as_str()).count(),
                after.matches(f.as_str()).count(),
                "filler {:?} changed", f
            );
        }
    }
}

proptest! {
    #![proptest_config(proptest_config(32))]

    #[test]
    fn redaction_is_stable_and_idempotent(case in case_strategy()) {
        let first = run_case("stable-a", &case);
        let second = run_case("stable-b", &case);
        let a = data_files(&first.work.join("out"));
        let b = data_files(&second.work.join("out"));
        prop_assert_eq!(&a, &b, "two runs on the same input differ");

        // Redact the first output again: every data file must stay as it is.
        let again = first.work.join("again");
        let out2 = run(
            &first.work,
            &["--redact-dir", "out", "--out", again.to_str().unwrap()],
            &[],
        );
        prop_assert_eq!(code(&out2), 0, "{}", text(&out2));
        let c = data_files(&again);
        for (name, bytes) in &a {
            if name == "record-log.txt" { continue; }
            // Replacement addresses are chosen to differ from every address in the
            // input, so the second pass numbers them again; everything else is fixed.
            let again_bytes = c.get(name).map(|b| mask_addresses(b));
            prop_assert_eq!(Some(mask_addresses(bytes)), again_bytes, "{} changed on the second pass", name);
        }

        // The log's distinct count per class equals the number planted.
        let log = String::from_utf8_lossy(&a["record-log.txt"]).into_owned();
        let mut logged: BTreeMap<String, usize> = BTreeMap::new();
        for line in log.lines() {
            let parts: Vec<&str> = line.split(' ').collect();
            if parts.len() == 4 && parts[0] == "replaced" {
                logged.insert(parts[1].to_string(), parts[3].parse().unwrap());
            }
        }
        let mut planted: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for p in &case.planted() {
            planted.entry(p.class.to_string()).or_default().insert(p.value.to_lowercase());
        }
        let planted_counts: BTreeMap<String, usize> =
            planted.iter().map(|(k, v)| (k.clone(), v.len())).collect();
        prop_assert_eq!(logged, planted_counts, "log counts differ from what was planted");
    }
}

/// A torrc mixing kept directives with dropped ones, all carrying canaries.
#[derive(Clone, Debug)]
struct TorCase {
    kept_ips: Vec<String>,
    folders: Vec<(String, String)>,
    dropped: Vec<String>,
    bridge_ips: Vec<String>,
    homes: Vec<String>,
}

fn tor_strategy() -> BoxedStrategy<TorCase> {
    let ip = prop_oneof![
        public_ipv4(),
        (1u32..=15, proptest::collection::vec(chars(HEX, 4..=4), 7))
            .prop_map(|(first, rest)| format!("2a0{first:x}:{}", rest.join(":"))),
    ];
    (
        proptest::collection::vec(ip, 1..=4),
        proptest::collection::vec(
            // A folder name that can never be a public name: it starts with "xq".
            (
                chars(LOWER, 6..=10),
                chars(LOWER_DIGITS, 3..=10).prop_map(|b| format!("xq{b}")),
            ),
            1..=3,
        ),
        proptest::collection::vec(chars(ALNUM, 20..=30), 1..=3),
        proptest::collection::vec(public_ipv4(), 1..=2),
        proptest::collection::vec(chars(LOWER, 7..=10), 1..=2),
    )
        .prop_map(|(kept_ips, folders, dropped, bridge_ips, homes)| TorCase {
            kept_ips,
            folders,
            dropped,
            bridge_ips,
            homes,
        })
        .boxed()
}

proptest! {
    #![proptest_config(proptest_config(32))]

    #[test]
    fn torrc_never_leaks_a_canary(case in tor_strategy()) {
        let n = CASE.fetch_add(1, Ordering::SeqCst);
        let work = work_dir("torrc", &format!("c{n}"));
        let mut torrc = String::new();
        for ip in &case.kept_ips {
            let addr = if ip.contains(':') { format!("[{ip}]") } else { ip.clone() };
            torrc.push_str(&format!("SocksPort {addr}:9050\nHiddenServicePort 80 {addr}:80\n"));
        }
        for (parent, base) in &case.folders {
            torrc.push_str(&format!("HiddenServiceDir /mnt/hdd/{parent}/{base}\n"));
        }
        for d in &case.dropped {
            torrc.push_str(&format!("HashedControlPassword 16:{d}\nBridge obfs4 {}:443 {} cert={d}\n", case.bridge_ips[0], "0123456789ABCDEF0123456789ABCDEF01234567"));
        }
        for h in &case.homes {
            torrc.push_str(&format!("DataDirectory /home/{h}/tor\n"));
        }
        for ip in &case.bridge_ips {
            torrc.push_str(&format!("Bridge obfs4 {ip}:443 0123456789ABCDEF0123456789ABCDEF01234567\n"));
        }
        let out = redact_dir(&work, &[("torrc", &torrc)], &[]);
        prop_assert_eq!(code(&out), 0, "{}", text(&out));
        let everything = format!("{}\n{}", all_output_text(&work.join("out")), text(&out)).to_lowercase();
        let canaries = case.kept_ips.iter().chain(&case.dropped).chain(&case.bridge_ips).chain(&case.homes)
            .chain(case.folders.iter().map(|(p, _)| p));
        for c in canaries {
            prop_assert!(!everything.contains(&c.to_lowercase()), "a canary survived: {}", c);
        }
        let got = read(&work, "out/torrc");
        // Every folder name is gone from every output byte, not only from one spelling.
        for (_, base) in &case.folders {
            prop_assert!(!everything.contains(&base.to_lowercase()), "folder name kept: {}", base);
        }
        // Every hidden-service line, and every `hs-` anywhere, is a pseudonym line.
        let dir_lines: Vec<&str> = got.lines().filter(|l| l.starts_with("HiddenServiceDir")).collect();
        prop_assert_eq!(dir_lines.len(), case.folders.len(), "{}", got);
        for l in &dir_lines {
            let ok = l
                .strip_prefix("HiddenServiceDir /REDACTED/hs-")
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
            prop_assert!(ok, "not a pseudonym line: {}", l);
        }
        prop_assert_eq!(got.matches("hs-").count(), case.folders.len(), "{}", got);
    }
}
