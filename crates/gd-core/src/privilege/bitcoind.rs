//! Bitcoin Core: a login is narrow only if `rpcwhitelist` stops it.
//!
//! The proof is three canary calls (`getblockcount`, `getbestblockhash`, `uptime`),
//! each harmless if allowed. A whitelisted login gets HTTP 403 for every one;
//! the first other answer stops the check. This proves the login is not
//! unrestricted, not that its whitelist is exactly the two methods asked for. The user name is
//! the user's own config value, so it is never printed: messages say "this
//! login".

use std::fmt;

/// What the node said to the canary call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryReply {
    /// An HTTP status code came back.
    Status(u16),
    /// No usable answer: no connection, a timeout, or a reply that isn't HTTP.
    NoReply,
}

/// The one thing this check needs from the outside: make one RPC call as the
/// login being checked and report the HTTP status.
pub trait CanaryRpc {
    /// Calls `method` with no parameters.
    fn call(&mut self, method: &str) -> CanaryReply;
}

/// A login proved limited by `rpcwhitelist`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NarrowLogin {}

impl NarrowLogin {
    /// What this proof does and does not show, in plain English.
    pub fn note(&self) -> &'static str {
        "Guard Dog can't read your rpcwhitelist line; it should list only getnetworkinfo,getblockchaininfo. A whitelist with extra methods would still pass this check."
    }
}

/// Why a Bitcoin Core login was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BitcoindRefusal {
    /// The user is `__cookie__`; refused without any call.
    CookieLogin,
    /// A call Guard Dog needs was refused with 403: the login can't read what it
    /// needs (or something other than `rpcwhitelist` is refusing it).
    CannotReadWhatItNeeds,
    /// The canary call was allowed (HTTP 200).
    TooWide,
    /// The node said 401: wrong user or password.
    WrongPassword,
    /// Any other answer, or none.
    CouldNotProve,
}

impl fmt::Display for BitcoindRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BitcoindRefusal::CookieLogin => f.write_str(
                "That's Bitcoin Core's full-access cookie login, which can do anything on your node. Guard Dog won't use it. \
                 Create its own login with `rpcauth` and limit it with `rpcwhitelist=<user>:getnetworkinfo,getblockchaininfo` and `rpcwhitelistdefault=0`.",
            ),
            BitcoindRefusal::CannotReadWhatItNeeds => f.write_str(
                "Guard Dog won't use this login, because this login can't read what Guard Dog needs: Bitcoin Core refused getnetworkinfo or getblockchaininfo. \
                 Add `rpcwhitelist=<user>:getnetworkinfo,getblockchaininfo` and `rpcwhitelistdefault=0` to bitcoin.conf, and check `rpcallowip` and any proxy in front of Bitcoin Core allow Guard Dog.",
            ),
            BitcoindRefusal::TooWide => f.write_str(
                "This login can call more than Guard Dog needs: Bitcoin Core answered a call it should have refused. \
                 Add `rpcwhitelist=<user>:getnetworkinfo,getblockchaininfo` and `rpcwhitelistdefault=0` to bitcoin.conf, then restart Bitcoin Core.",
            ),
            BitcoindRefusal::WrongPassword => f.write_str(
                "Bitcoin Core refused this login: the user name or password is wrong. Check the credential you gave Guard Dog against your `rpcauth` line.",
            ),
            BitcoindRefusal::CouldNotProve => f.write_str(
                "Guard Dog couldn't prove this login is limited, so it won't use it. Check that Bitcoin Core is running and reachable, \
                 and that bitcoin.conf has `rpcwhitelist=<user>:getnetworkinfo,getblockchaininfo` and `rpcwhitelistdefault=0`.",
            ),
        }
    }
}

impl std::error::Error for BitcoindRefusal {}

/// The calls Guard Dog needs; each must get HTTP 200 before the canaries mean anything.
const NEEDED_METHODS: [&str; 2] = ["getnetworkinfo", "getblockchaininfo"];
/// Harmless, read-only methods that are not on the whitelist Guard Dog asks for.
/// Each must get HTTP 403. Never a wallet or spending method.
const CANARY_METHODS: [&str; 3] = ["getblockcount", "getbestblockhash", "uptime"];

/// Proves a login narrow, or says why not. `user` is the RPC user name; it is
/// only compared, never shown. The cookie login is refused before any call.
pub fn check(user: &str, rpc: &mut dyn CanaryRpc) -> Result<NarrowLogin, BitcoindRefusal> {
    if user == "__cookie__" {
        return Err(BitcoindRefusal::CookieLogin);
    }
    for method in NEEDED_METHODS {
        match rpc.call(method) {
            CanaryReply::Status(200) => {}
            CanaryReply::Status(403) => return Err(BitcoindRefusal::CannotReadWhatItNeeds),
            CanaryReply::Status(401) => return Err(BitcoindRefusal::WrongPassword),
            _ => return Err(BitcoindRefusal::CouldNotProve),
        }
    }
    for method in CANARY_METHODS {
        match rpc.call(method) {
            CanaryReply::Status(403) => {}
            CanaryReply::Status(200) => return Err(BitcoindRefusal::TooWide),
            CanaryReply::Status(401) => return Err(BitcoindRefusal::WrongPassword),
            _ => return Err(BitcoindRefusal::CouldNotProve),
        }
    }
    Ok(NarrowLogin {})
}
