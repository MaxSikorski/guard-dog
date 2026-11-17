//! Bitcoin Core: a login is narrow only if `rpcwhitelist` stops it.
//!
//! The proof is a canary call, `getblockcount`, which is harmless if it were
//! allowed. A properly whitelisted login gets HTTP 403 for it. The user name is
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

/// Why a Bitcoin Core login was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BitcoindRefusal {
    /// The user is `__cookie__`; refused without any call.
    CookieLogin,
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

/// Proves a login narrow, or says why not. `user` is the RPC user name; it is
/// only compared, never shown. The cookie login is refused before any call.
pub fn check(user: &str, rpc: &mut dyn CanaryRpc) -> Result<NarrowLogin, BitcoindRefusal> {
    if user == "__cookie__" {
        return Err(BitcoindRefusal::CookieLogin);
    }
    match rpc.call("getblockcount") {
        CanaryReply::Status(403) => Ok(NarrowLogin {}),
        CanaryReply::Status(200) => Err(BitcoindRefusal::TooWide),
        CanaryReply::Status(401) => Err(BitcoindRefusal::WrongPassword),
        _ => Err(BitcoindRefusal::CouldNotProve),
    }
}
