//! `gd-egress`: makes Judge C's canaries and checks an egress capture.
//!
//! Exit codes for `check`: 0 pass, 1 fail, 2 usage or file error.

use clap::{Parser, Subcommand};
use gd_egress::allowlist::Allowlist;
use gd_egress::canary::{CanarySet, generate};
use gd_egress::capture::RawCapture;
use gd_egress::{setup, verdict};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "gd-egress",
    about = "Judge C: canary generator and egress-capture checker (test tooling)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Make the planted canaries, the file tree that holds them and the side files.
    Canaries {
        /// A number, or `random` (8 bytes from /dev/urandom).
        #[arg(long)]
        seed: String,
        /// Where to write `judge/`, `root/`, `teeth/` and `control.env`.
        #[arg(long)]
        out: PathBuf,
    },
    /// Judge a capture directory.
    Check {
        /// The capture directory (`dns.log`, `mitm/`, `pcap/`).
        #[arg(long)]
        capture: PathBuf,
        /// `canaries.json` from the `canaries` command.
        #[arg(long)]
        canaries: PathBuf,
        /// `allowlist.toml`.
        #[arg(long)]
        allowlist: PathBuf,
        /// The reviewed firewall and route dump.
        #[arg(long)]
        expected_rules: PathBuf,
        /// Where to write the report.
        #[arg(long)]
        report: PathBuf,
        /// Where to write the details.
        #[arg(long)]
        details: PathBuf,
    },
}

fn usage_error(message: &str) -> ExitCode {
    eprintln!("gd-egress: {message}");
    ExitCode::from(2)
}

fn parse_seed(text: &str) -> Result<u64, String> {
    if text != "random" {
        return text
            .parse::<u64>()
            .map_err(|_| "the seed must be a number or `random`".to_string());
    }
    let mut bytes = [0u8; 8];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| format!("cannot read /dev/urandom: {e}"))?;
    Ok(u64::from_le_bytes(bytes))
}

fn run_canaries(seed: &str, out: &Path) -> ExitCode {
    let seed = match parse_seed(seed) {
        Ok(s) => s,
        Err(e) => return usage_error(&e),
    };
    eprintln!("GD_CANARY_SEED={seed}");
    match setup::write_all(out, &generate(seed)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => usage_error(&format!("cannot write the canaries: {e}")),
    }
}

fn read_text(path: &Path, what: &str) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("cannot read {what}: {e}"))
}

fn run_check(args: [&Path; 6]) -> Result<ExitCode, String> {
    let [
        capture,
        canaries,
        allowlist,
        expected_rules,
        report,
        details,
    ] = args;
    let set = CanarySet::from_json(&read_text(canaries, "--canaries")?)
        .map_err(|e| format!("bad --canaries file: {e}"))?;
    let allow = Allowlist::parse(&read_text(allowlist, "--allowlist")?)
        .map_err(|e| format!("bad --allowlist file: {e:?}"))?;
    let rules = read_text(expected_rules, "--expected-rules")?;
    let result = verdict::judge(&RawCapture::load(capture), &set, &allow, &rules);
    print!("{}", result.report);
    fs::write(report, &result.report).map_err(|e| format!("cannot write --report: {e}"))?;
    fs::write(details, &result.details).map_err(|e| format!("cannot write --details: {e}"))?;
    Ok(if result.pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn main() -> ExitCode {
    match Cli::try_parse() {
        Ok(Cli {
            command: Command::Canaries { seed, out },
        }) => run_canaries(&seed, &out),
        Ok(Cli {
            command:
                Command::Check {
                    capture,
                    canaries,
                    allowlist,
                    expected_rules,
                    report,
                    details,
                },
        }) => run_check([
            &capture,
            &canaries,
            &allowlist,
            &expected_rules,
            &report,
            &details,
        ])
        .unwrap_or_else(|e| usage_error(&e)),
        Err(e) => {
            let _ = e.print();
            ExitCode::from(2)
        }
    }
}
