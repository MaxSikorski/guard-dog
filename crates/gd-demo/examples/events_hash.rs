//! `cargo run --locked --example events_hash`: prints the SHA-256 of the demo's
//! events JSON, the exact bytes the browser engine hands the page.
//!
//! `docs/demo/README.md` pins this hash and a test recomputes it, so changing a
//! scene's text or verdict fails `cargo test` until the engine is rebuilt
//! (`docs/demo/build.sh`) and the hash is pinned again.

use gd_egress::encode::{hex, sha256};

fn main() {
    println!(
        "{}  events.json",
        hex(&sha256(gd_demo::to_json(&gd_demo::run()).as_bytes()))
    );
}
