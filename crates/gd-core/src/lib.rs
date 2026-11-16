//! Guard Dog's core types.
//!
//! Everything here is plain data. The rule these types enforce: text that came
//! from outside Guard Dog is [`Untrusted`], and the compiler won't let it be
//! printed, shown or passed on without an escape function or an explicit,
//! greppable [`Untrusted::expose_untrusted`].

mod untrusted;

pub use untrusted::Untrusted;

/// Something a sensor observed: a service and its version, a listening port,
/// a router mapping, a registered hardware wallet's firmware.
///
/// A stub until the fact model and local store are built (Phase 1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Fact {}

/// The matcher's verdict that an advisory applies to this setup: affected,
/// not affected, or possibly affected plus the question that would settle it.
///
/// A stub until the matcher is built (Phase 2).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Finding {}

/// A security advisory in OSV format, with Guard Dog's conditions and its
/// "what to do" playbook in OSV's `database_specific` field.
///
/// A stub until advisory parsing is built (Phase 2).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Advisory {}
