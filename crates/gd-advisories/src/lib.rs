//! Guard Dog's advisory intake.
//!
//! Phase 2.1, step 1: OSV 1.9.2 records become bounded typed data with their
//! provenance and explicit gaps ([`parse_advisory`]), and package names get one
//! canonical form ([`canonical_package`]). This crate is pure: no network, no
//! files, no clock, no subprocess, no AI. Range evaluation ([`evaluate_entry`]) and the
//! SemVer, Go tag, Bitcoin Core and channel schemes are here; the product
//! dispatch arrives in a later step.

mod osv;
mod package;
mod range;
mod version;

pub use osv::{
    Advisory, AdvisoryId, AffectedEntry, Curation, Event, Gap, GapKind, MAX_AFFECTED, MAX_DEPTH,
    MAX_GAPS, MAX_RANGES_AND_EVENTS, MAX_RECORD_BYTES, MAX_VERSION_BYTES, MAX_VERSIONS, OsvError,
    Package, Range, RangeKind, Reference, ReferenceKind, Refusal, Scope, Severity, SeverityKind,
    Source, Timestamp, parse_advisory, parse_advisory_from,
};
pub use package::{Ecosystem, MAX_PACKAGE_NAME, PackageError, PackageKey, canonical_package};
pub use range::{Location, Place, UnknownReason, VersionEvidence, evaluate_entry};
pub use version::{
    BitcoinCore, Calver, Candidate, Channel, ChannelScheme, ChannelVersion, ClnVersion, Commit,
    CoreVersion, Described, GitDescribe, GoTag, Pep440, Pep440Version, RcEvidence, SemVer,
    SemVerVersion, TagVersion, VersionError, VersionScheme, evaluate_channel_entry,
};
