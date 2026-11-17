//! Guard Dog's core types.
//!
//! Everything here is plain data. The rule these types enforce: text that came
//! from outside Guard Dog is [`Untrusted`], and the compiler won't let it be
//! printed, shown or passed on without an escape function or an explicit,
//! greppable [`Untrusted::expose_untrusted`].

mod fact;
mod json;
pub mod privilege;
mod untrusted;
mod view;

pub use fact::*;
pub use json::to_ascii_json;
pub use untrusted::Untrusted;
pub use view::{SetupView, setup_view};

/// The matcher's verdict that an advisory applies to this setup: affected,
/// not affected, or possibly affected plus the question that would settle it.
///
/// A placeholder until the matcher is built.
#[non_exhaustive]
pub struct Finding {}

/// A security advisory in OSV format, with Guard Dog's conditions and its
/// "what to do" playbook in OSV's `database_specific` field.
///
/// A placeholder until advisory parsing is built.
#[non_exhaustive]
pub struct Advisory {}
