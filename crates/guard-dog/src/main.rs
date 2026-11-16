//! The `guard-dog` command. Pre-alpha: for now it answers `--version` and
//! `--help`; scanning arrives in Phase 1.

use clap::Parser;

/// The release number and the exact source commit it was built from.
const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (commit ",
    env!("GD_GIT_COMMIT"),
    ")"
);

/// Guard Dog watches your self-hosted Bitcoin and Nostr setup and tells you,
/// privately, when something you run becomes dangerous.
#[derive(Parser)]
#[command(name = "guard-dog", version = VERSION, about, arg_required_else_help = true)]
struct Cli {}

fn main() {
    Cli::parse();
}
