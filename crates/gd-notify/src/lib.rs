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
//!
//! # Logging
//!
//! Nothing here logs. An app that installs a logger must not enable TRACE for
//! `tungstenite`: at that level it prints frame contents. Keep it at WARN.
//!
//! # No sender copy
//!
//! NIP-17 suggests a sender also wraps a copy of each message to itself.
//! Guard Dog's alert key is a send-only notifier, so it does not: this is an
//! intentional deviation from NIP-17's sender copy, and it means no
//! sender-side history of what was sent exists anywhere.
//!
//! # Inbox list (kind 10050)
//!
//! Before sending, Guard Dog asks the relay for the recipient's kind-10050
//! direct-message inbox list and sends only if the newest validly signed one
//! lists that relay. Otherwise nothing is sent and the error says why (NIP-17
//! asks senders not to send to someone without one). Blind spot: the list is
//! looked for only on the lab relay being sent to. A live lab send needs a
//! kind-10050 for the test recipient on the lab relay, which the later
//! lab-check work will publish.
//!
//! # Sending
//!
//! ```
//! use gd_notify::send_alerts;
//! ```
//!
//! # The raw publisher is private
//!
//! ```compile_fail
//! use gd_notify::relay::publish;
//! ```
//!
//! ```compile_fail
//! use gd_notify::event::gift_wrap_dm;
//! ```

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

/// Test-only access to message building, for this crate's integration tests.
/// It builds events on this machine and never touches the network; the only
/// way to send is [`send_alerts`].
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support {
    /// Builds the gift wrap for one direct message (no network).
    pub fn gift_wrap_dm(
        sender: &crate::Keys,
        recipient: &[u8; 32],
        message: &str,
        clock: &dyn crate::Clock,
        entropy: &mut dyn crate::Entropy,
    ) -> Result<crate::event::Event, crate::NotifyError> {
        crate::event::gift_wrap_dm(sender, recipient, message, clock, entropy)
    }
}

use alert::{Alert, Chain, notify_allowed, plan_dms_noting};
use relay::{PublishOutcome, RelayUrl};

/// Plans the direct messages for `alerts` (policy, cap and summary included),
/// wraps each for `recipient`, and publishes them to the lab relay.
///
/// Before sending anything it asks the relay for the recipient's kind-10050
/// inbox list and sends only if the newest validly signed one lists that relay;
/// otherwise nothing is sent and the error says why.
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
    // Nothing eligible: send nothing at all, not even a summary.
    if allowed.is_empty() {
        return Ok(Vec::new());
    }
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
    relay::publish(relay, recipient, &wraps)
}
