//! Proves, by compiling code that must fail, that untrusted text can't leave
//! `Untrusted<T>` except through an escape function or `expose_untrusted()`.
//!
//! The expected compiler errors are in `tests/ui/*.stderr`. They depend on the
//! exact Rust version, which `rust-toolchain.toml` pins. After a toolchain bump,
//! regenerate them with `TRYBUILD=overwrite cargo test --locked -p gd-core
//! --test compile_fail` and check each diff by hand: every case must still fail
//! for the same reason.

#[test]
fn untrusted_text_cannot_escape_without_saying_so() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/*.rs");
}
