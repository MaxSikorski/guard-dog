# Crates

One line per crate: what it owns. A new crate arrives only when its first real caller does (sensors, advisories and notifications come next).

| Crate | Owns |
|---|---|
| `guard-dog` | The `guard-dog` binary: the command line, and later the daemon and the local status page. It holds no logic of its own; that lives in the library crates. `--version` names the release, plus the exact git commit for release builds (which set `GD_GIT_COMMIT`); local builds say "development build". |
| `gd-core` | The shared types. `Untrusted<T>` is outside text as a type the compiler tracks: it can't be printed, compared or passed on except through `escape_for_terminal()`, `escape_for_html()` or a greppable `expose_untrusted()`, and every use of the last one needs a reviewer's OK. The fact model (`fact.rs`, `view.rs`): `Fact`, `Observed<T>` (`Seen` or `Unknown`, with no default and no bool conversion), the ordered detection `Method`, validated id and version types, and `setup_view`, which derives setup-level facts from per-service facts. `Untrusted<T>` also serialises as `{"untrusted": ...}`. `Finding` and `Advisory` are placeholders until the matcher is built. `privilege` proves credentials narrow with no IO: an LND macaroon must allow exactly `info:read`, a Core Lightning rune only `getinfo` with no parameters, a Bitcoin Core login must be allowed the two calls Guard Dog needs and refused three canary calls, and the process must not be root; anything wider is refused with a plain-English fix. |
| `gd-egress` | Judge C's tooling: makes the planted canary secrets and checks an egress capture against `allowlist.toml`, decoding gzip, deflate and brotli request bodies before it scans them. Test tooling only; never in a release. |
| `gd-advisories` | Advisory intake, pure and with no network: OSV 1.9.2 records read into bounded typed data (`parse_advisory`: size, depth, count limits, duplicate keys refused, outside text kept `Untrusted`, anything not understood listed as a gap) and one canonical form for package names (`canonical_package`: PyPI by PEP 503, GIT URLs, Go exact). Version ordering and range matching come in later steps. |

The judge tests (Judges A, B and D) and the tests for `tools/record-setup.sh` live in `crates/gd-core/tests/` until a judges crate earns its place.

Rules that hold in every crate: no `unsafe` (the workspace forbids it), no network access outside the allowlist, no shell commands built from outside text, and the core works with no AI model.
