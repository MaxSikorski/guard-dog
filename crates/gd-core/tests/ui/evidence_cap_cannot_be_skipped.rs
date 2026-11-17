use gd_core::{CallId, Evidence, Untrusted};

fn main() {
    let call = CallId::parse("c").unwrap_or_else(|_| std::process::abort());
    // Built by hand, the 1 KiB cap would be bypassed: the fields are private.
    let _evidence = Evidence {
        call,
        raw: Untrusted::new("x".repeat(100_000)),
    };
}
