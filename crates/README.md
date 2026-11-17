# Crates

One line per crate: what it owns. A new crate arrives only when its first real caller does (sensors, advisories and notifications come next).

| Crate | Owns |
|---|---|
| `guard-dog` | The `guard-dog` binary: the command line, and later the daemon and the local status page. It holds no logic of its own; that lives in the library crates. `--version` names the release, plus the exact git commit for release builds (which set `GD_GIT_COMMIT`); local builds say "development build". |
| `gd-core` | The shared types. `Untrusted<T>` is outside text as a type the compiler tracks: it can't be printed, compared or passed on except through `escape_for_terminal()`, `escape_for_html()` or a greppable `expose_untrusted()`, and every use of the last one needs a reviewer's OK. `Fact`, `Finding` and `Advisory` are placeholders until the inventory and the matcher are built. |
| `gd-egress` | Judge C's tooling: makes the planted canary secrets and checks an egress capture against `allowlist.toml`, decoding gzip, deflate and brotli request bodies before it scans them. Test tooling only; never in a release. |

Rules that hold in every crate: no `unsafe` (the workspace forbids it), no network access outside the allowlist, no shell commands built from outside text, and the core works with no AI model.
