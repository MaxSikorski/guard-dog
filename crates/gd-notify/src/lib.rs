//! Guard Dog's alerts as private Nostr direct messages (NIP-17).
//!
//! In this version the only relay it may talk to is the regtest lab's own
//! (`ws://strfry:7777`), and it only sends when the node is on regtest or
//! signet. Everything is built from RustCrypto primitives (the `nostr` crate
//! depends on libsecp256k1, which `deny.toml` refuses): NIP-44 v2 encryption,
//! NIP-59 seal and gift wrap, NIP-17 kind-14 rumors, and BIP-340 signatures.
//!
//! Time and randomness come only through [`Clock`] and [`Entropy`], so tests
//! are deterministic. Guard Dog's own key pair is never the user's `nsec`; it
//! lives in `<state_dir>/notify.key`. No key and no message text ever reaches
//! a log or `Debug` output.

pub mod alert;
pub mod encoding;
pub mod event;
pub mod keyfile;
pub mod keys;
pub mod nip44;
pub mod relay;

mod error;
mod sources;

pub use error::NotifyError;
pub use keys::Keys;
pub use sources::{Clock, Entropy, OsEntropy, SystemClock};

use alert::{Alert, Chain, notify_allowed, plan_dms_noting};
use relay::{PublishOutcome, RelayUrl};

/// Plans the direct messages for `alerts` (policy, cap and summary included),
/// wraps each for `recipient`, and publishes them to the lab relay.
///
/// Refuses, before touching the network, unless [`notify_allowed`] says the
/// node's chains are regtest or signet only. An alert about any other chain
/// (or an unknown one) is dropped, never sent, and counted in the summary.
pub fn send_alerts(
    relay: &RelayUrl,
    sender: &Keys,
    recipient: &[u8; 32],
    alerts: &[Alert],
    chains: &[Chain],
    clock: &dyn Clock,
    entropy: &mut dyn Entropy,
) -> Result<Vec<PublishOutcome>, NotifyError> {
    if !notify_allowed(chains) {
        return Err(NotifyError::Refused(
            "notifications are only sent when the node is on regtest or signet",
        ));
    }
    // Each alert's own chain must be one the node set reported and one we may
    // notify about. An alert that is not is dropped (never sent) and counted
    // in the summary, so one odd finding cannot silence the rest; a mixed run
    // cannot carry a mainnet finding.
    let (allowed, dropped): (Vec<&Alert>, Vec<&Alert>) = alerts
        .iter()
        .partition(|a| notify_allowed(&[a.chain()]) && chains.contains(&a.chain()));
    let allowed: Vec<Alert> = allowed.into_iter().cloned().collect();
    let mut wraps = Vec::new();
    for message in plan_dms_noting(&allowed, dropped.len()) {
        wraps.push(event::gift_wrap_dm(
            sender, recipient, &message, clock, entropy,
        )?);
    }
    if wraps.is_empty() {
        return Ok(Vec::new());
    }
    relay::publish(relay, &wraps)
}
