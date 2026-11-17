use gd_core::{Unknown, UnknownReason, Untrusted};

fn main() {
    // The detail is private: only `Unknown::with_detail` (which caps it) sets it.
    let _unknown = Unknown {
        reason: UnknownReason::NoReply,
        detail: Some(Untrusted::new("x".repeat(100_000))),
    };
}
