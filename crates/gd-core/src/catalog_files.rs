//! The catalog entries compiled into the binary, so there is no file to read at
//! run time and no `build.rs`. A test (`tests/catalog.rs`) checks this list is
//! exactly the `catalog/` folder: no entry missing, none extra, same text.
//! Add a line here, in sorted order, when an entry is added.

/// (id, text) of every `catalog/<id>.toml`, sorted by id.
pub const FILES: &[(&str, &str)] = &[
    ("alby-hub", include_str!("../../../catalog/alby-hub.toml")),
    (
        "bitcoin-core",
        include_str!("../../../catalog/bitcoin-core.toml"),
    ),
    (
        "btcpay-server",
        include_str!("../../../catalog/btcpay-server.toml"),
    ),
    (
        "core-lightning",
        include_str!("../../../catalog/core-lightning.toml"),
    ),
    ("fedimintd", include_str!("../../../catalog/fedimintd.toml")),
    ("gatewayd", include_str!("../../../catalog/gatewayd.toml")),
    (
        "lightning-terminal",
        include_str!("../../../catalog/lightning-terminal.toml"),
    ),
    ("lnd", include_str!("../../../catalog/lnd.toml")),
    ("nutshell", include_str!("../../../catalog/nutshell.toml")),
    ("rtl", include_str!("../../../catalog/rtl.toml")),
    ("strfry", include_str!("../../../catalog/strfry.toml")),
    ("tapd", include_str!("../../../catalog/tapd.toml")),
    ("umbrelos", include_str!("../../../catalog/umbrelos.toml")),
];
