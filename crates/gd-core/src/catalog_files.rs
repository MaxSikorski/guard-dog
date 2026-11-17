//! The catalog entries compiled into the binary, so there is no file to read at
//! run time and no `build.rs`. A test (`tests/catalog.rs`) checks this list is
//! exactly the `catalog/` folder: no entry missing, none extra, same text.
//! Add a line here, in sorted order, when an entry is added.
//!
//! Every embedded text is checked at compile time (`catalog_scan.rs`): a file
//! with a credential-shaped line fails `cargo build` itself, before a binary
//! exists, whether or not anyone runs the tests. The build error is a fixed
//! message that never shows file text; to find the line, read the rules in
//! `catalog/README.md` and look at the comments and long values of that file.

/// One catalog file as (id, text), with the compile-time credential check.
macro_rules! entry {
    ($id:literal) => {{
        const TEXT: &str = include_str!(concat!("../../../catalog/", $id, ".toml"));
        const _: () = assert!(
            crate::catalog_scan::credential_line(TEXT) == 0,
            concat!(
                "catalog/",
                $id,
                ".toml has a credential-shaped line; see the compile-time guard rules in catalog/README.md"
            )
        );
        ($id, TEXT)
    }};
}

/// (id, text) of every `catalog/<id>.toml`, sorted by id.
pub const FILES: &[(&str, &str)] = &[
    entry!("alby-hub"),
    entry!("bitcoin-core"),
    entry!("btcpay-server"),
    entry!("core-lightning"),
    entry!("fedimintd"),
    entry!("gatewayd"),
    entry!("lightning-terminal"),
    entry!("lnd"),
    entry!("nutshell"),
    entry!("rtl"),
    entry!("strfry"),
    entry!("tapd"),
    entry!("umbrelos"),
];
