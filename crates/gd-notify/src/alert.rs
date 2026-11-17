//! The alert message, the sending policy and the chain guard.
//!
//! An [`Alert`] holds only values that were validated or escaped when it was
//! built, so rendering it cannot let outside text add a headline, a "Fix:"
//! line or a second message. One alert is one direct message.
//!
//! There is no "evidence" section in the message on purpose (design R1.8):
//! text a service supplied (a banner, a version string, a label) never
//! reaches a direct message. Only validated tokens, the advisory's own
//! escaped and capped text, and Guard Dog's fixed sentences do.

use crate::NotifyError;
use gd_core::Untrusted;
use std::fmt;

/// Most direct messages one run may send; the rest become one summary.
pub const MAX_DMS_PER_RUN: usize = 20;
const SUMMARY_CAP: usize = 500;
const PLAYBOOK_CAP: usize = 1_000;
const QUESTION_CAP: usize = 500;
/// Longest display name or blind-spot sentence, in characters.
const LINE_CAP: usize = 120;
/// Most blind-spot sentences one alert may carry.
const MAX_BLIND_SPOTS: usize = 16;
const FOOTER: &str = "No known issues is not the same as secure.";

/// Which Bitcoin network a node reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    /// The real network.
    Mainnet,
    /// A public test network.
    Testnet,
    /// Signet.
    Signet,
    /// A private test chain.
    Regtest,
    /// The node did not say, or said something else.
    Unknown,
}

impl Chain {
    fn name(self) -> &'static str {
        match self {
            Chain::Mainnet => "mainnet",
            Chain::Testnet => "testnet",
            Chain::Signet => "signet",
            Chain::Regtest => "regtest",
            Chain::Unknown => "an unknown chain",
        }
    }
}

/// How sure the match is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchResult {
    /// The installed version is in the affected range.
    Affected,
    /// It could be; something needed to be sure was not visible.
    PossiblyAffected,
}

/// How serious the advisory says it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Critical.
    Critical,
    /// High.
    High,
    /// Medium.
    Medium,
    /// Low.
    Low,
    /// The advisory did not say. Treated as worth sending.
    Unknown,
}

impl Severity {
    fn name(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Unknown => "not stated",
        }
    }

    /// Lower sorts first (worst first).
    fn rank(self) -> u8 {
        match self {
            Severity::Critical => 0,
            Severity::High => 1,
            Severity::Unknown => 2,
            Severity::Medium => 3,
            Severity::Low => 4,
        }
    }
}

/// Everything an alert is made of, before validation.
pub struct AlertParts {
    /// Display name from the catalog.
    pub product: &'static str,
    /// Installed version, `[0-9A-Za-z.+~-]{1,64}`.
    pub version: String,
    /// The chain the node reports.
    pub chain: Chain,
    /// Advisory id, `[A-Za-z0-9._-]{1,100}`.
    pub advisory_id: String,
    /// Affected or possibly affected.
    pub result: MatchResult,
    /// Severity.
    pub severity: Severity,
    /// The advisory's fixed version, same form as `version`.
    pub fixed_in: Option<String>,
    /// The advisory's summary (outside text).
    pub summary: Untrusted<String>,
    /// The advisory's playbook (outside text).
    pub playbook: Untrusted<String>,
    /// A question for the user (outside text).
    pub question: Option<Untrusted<String>>,
    /// When the check ran, Unix seconds (injected).
    pub checked_at: u64,
    /// Fixed sentences saying what could not be seen.
    pub blind_spots: Vec<&'static str>,
}

/// A validated alert. `Debug` shows nothing.
#[derive(Clone)]
pub struct Alert {
    product: &'static str,
    version: String,
    chain: Chain,
    advisory_id: String,
    result: MatchResult,
    severity: Severity,
    fixed_in: Option<String>,
    // Already escaped and capped.
    summary: String,
    playbook: String,
    question: Option<String>,
    checked_at: u64,
    blind_spots: Vec<&'static str>,
}

impl fmt::Debug for Alert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Alert(<redacted>)")
    }
}

fn token_ok(text: &str, max: usize, extra: &[char]) -> bool {
    !text.is_empty()
        && text.len() <= max
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(&c))
}

/// Escapes for a terminal, then cuts to `cap` characters on a character
/// boundary, ending in "..." when it was cut. Only the first `cap + 1`
/// characters are ever looked at, so a huge field cannot use unbounded memory.
/// (Escaping works one character at a time and never shortens, so escaping
/// that prefix gives the same first `cap` characters as escaping everything.)
fn quote_text(text: &Untrusted<String>, cap: usize) -> String {
    let prefix: String = text.expose_untrusted().chars().take(cap + 1).collect();
    let escaped = Untrusted::new(prefix).escape_for_terminal();
    if escaped.chars().count() <= cap {
        return escaped;
    }
    let mut cut: String = escaped.chars().take(cap.saturating_sub(3)).collect();
    cut.push_str("...");
    cut
}

/// Unicode format characters (category Cf): the bidi controls, zero-width and
/// joiner characters, the byte order mark, tag characters and the rest.
fn is_format_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{0600}'..='\u{0605}' | '\u{061C}' | '\u{06DD}' | '\u{070F}'
        | '\u{0890}'..='\u{0891}' | '\u{08E2}' | '\u{180E}' | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}'
        | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}' | '\u{110BD}' | '\u{110CD}'
        | '\u{13430}'..='\u{1343F}' | '\u{1BCA0}'..='\u{1BCA3}' | '\u{1D173}'..='\u{1D17A}'
        | '\u{E0001}' | '\u{E0020}'..='\u{E007F}')
}

/// A bounded single-line value of ours: not empty, at most [`LINE_CAP`]
/// characters, no control character, no line or paragraph separator and no
/// bidi or other invisible format character.
fn single_line_ok(text: &str) -> bool {
    !text.is_empty()
        && text.chars().count() <= LINE_CAP
        && !text
            .chars()
            .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') || is_format_char(c))
}

impl Alert {
    /// Validates the parts. Version, fixed version and advisory id must match
    /// their patterns; outside text is escaped and capped here.
    pub fn new(parts: AlertParts) -> Result<Alert, NotifyError> {
        let version_chars = ['.', '+', '~', '-'];
        if !token_ok(&parts.version, 64, &version_chars) {
            return Err(NotifyError::Invalid("version is not a plain version token"));
        }
        if let Some(fixed) = &parts.fixed_in
            && !token_ok(fixed, 64, &version_chars)
        {
            return Err(NotifyError::Invalid(
                "fixed version is not a plain version token",
            ));
        }
        if !token_ok(&parts.advisory_id, 100, &['.', '_', '-']) {
            return Err(NotifyError::Invalid("advisory id is not a plain id"));
        }
        if !single_line_ok(parts.product) {
            return Err(NotifyError::Invalid(
                "product name is not a bounded single line",
            ));
        }
        if parts.blind_spots.len() > MAX_BLIND_SPOTS
            || !parts.blind_spots.iter().all(|s| single_line_ok(s))
        {
            return Err(NotifyError::Invalid(
                "blind spots are not bounded single lines",
            ));
        }
        Ok(Alert {
            product: parts.product,
            version: parts.version,
            chain: parts.chain,
            advisory_id: parts.advisory_id,
            result: parts.result,
            severity: parts.severity,
            fixed_in: parts.fixed_in,
            summary: quote_text(&parts.summary, SUMMARY_CAP),
            playbook: quote_text(&parts.playbook, PLAYBOOK_CAP),
            question: parts.question.as_ref().map(|q| quote_text(q, QUESTION_CAP)),
            checked_at: parts.checked_at,
            blind_spots: parts.blind_spots,
        })
    }

    /// The chain this alert is about.
    pub fn chain(&self) -> Chain {
        self.chain
    }

    /// The plain-text message: the headline sentence first, then what is
    /// affected, why, what to do, the question if any, when it was checked,
    /// the blind spots and the footer. Every line of outside text starts with
    /// `  > `, so it is visibly quoted and can never pass as one of ours.
    pub fn render(&self) -> String {
        let verb = match self.result {
            MatchResult::Affected => "is affected by",
            MatchResult::PossiblyAffected => "may be affected by",
        };
        let mut out = String::new();
        out.push_str(&format!(
            "{} {} on this node {verb} {}.\n\n",
            self.product, self.version, self.advisory_id
        ));
        out.push_str(&format!(
            "What is affected: {} {} on {}.\nSeverity: {}.\n\n",
            self.product,
            self.version,
            self.chain.name(),
            self.severity.name()
        ));
        out.push_str(&format!("Why:\n  > {}\n\nWhat to do:\n", self.summary));
        if let Some(fixed) = &self.fixed_in {
            out.push_str(&format!("Update to {fixed} or later.\n"));
        }
        out.push_str(&format!("  > {}\n", self.playbook));
        if let Some(q) = &self.question {
            out.push_str(&format!("\nQuestion:\n  > {q}\n"));
        }
        out.push_str(&format!("\nChecked: {}.\n", format_utc(self.checked_at)));
        if self.blind_spots.is_empty() {
            out.push_str("Blind spots: none reported.\n");
        } else {
            out.push_str("Blind spots:\n");
            for spot in &self.blind_spots {
                out.push_str(&format!("- {spot}\n"));
            }
        }
        out.push('\n');
        out.push_str(FOOTER);
        out
    }
}

/// "2026-11-17 12:00 UTC".
fn format_utc(unix: u64) -> String {
    let days = i64::try_from(unix / 86_400).unwrap_or(0);
    let secs = unix % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        secs / 3_600,
        secs % 3_600 / 60
    )
}

/// Critical, high or unknown severity, affected or possibly affected: send
/// now. Medium and low wait for a later digest.
pub fn should_send_now(alert: &Alert) -> bool {
    matches!(
        alert.severity,
        Severity::Critical | Severity::High | Severity::Unknown
    )
}

/// The messages for one run: the alerts that should be sent now, worst first
/// (input order within a severity), at most [`MAX_DMS_PER_RUN`] of them, then
/// one summary message if anything was not sent as its own message (held back
/// by the cap, or medium and low ones that wait for a digest).
pub fn plan_dms(alerts: &[Alert]) -> Vec<String> {
    plan_dms_noting(alerts, 0)
}

/// [`plan_dms`], where `dropped_chain` more findings were already left out
/// because they are about a chain that notifications are not allowed for; the
/// summary says how many, and why.
pub fn plan_dms_noting(alerts: &[Alert], dropped_chain: usize) -> Vec<String> {
    let mut due: Vec<&Alert> = alerts.iter().filter(|a| should_send_now(a)).collect();
    due.sort_by_key(|a| a.severity.rank());
    let mut out: Vec<String> = due
        .iter()
        .take(MAX_DMS_PER_RUN)
        .map(|a| a.render())
        .collect();
    let more = due.len().saturating_sub(MAX_DMS_PER_RUN);
    let held = alerts.len().saturating_sub(due.len());
    let mut lines = Vec::new();
    if more > 0 {
        let noun = if more == 1 { "finding" } else { "findings" };
        lines.push(format!(
            "{more} more {noun}; run guard-dog scan to see them."
        ));
    }
    if held > 0 {
        let noun = if held == 1 { "finding" } else { "findings" };
        lines.push(format!(
            "{held} medium or low {noun} not sent as direct messages (they wait for a digest); run guard-dog scan to see them."
        ));
    }
    if dropped_chain > 0 {
        let noun = if dropped_chain == 1 {
            "finding"
        } else {
            "findings"
        };
        lines.push(format!(
            "{dropped_chain} {noun} not sent because they are about a chain other than regtest or signet, or an unknown one; run guard-dog scan to see them."
        ));
    }
    if !lines.is_empty() {
        out.push(format!("{}\n\n{FOOTER}", lines.join("\n")));
    }
    out
}

/// True only when at least one chain is regtest or signet and none is
/// anything else. An unknown chain, or none at all, is false.
pub fn notify_allowed(chains: &[Chain]) -> bool {
    chains
        .iter()
        .any(|c| matches!(c, Chain::Regtest | Chain::Signet))
        && chains
            .iter()
            .all(|c| matches!(c, Chain::Regtest | Chain::Signet))
}
