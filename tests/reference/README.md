# Reference vectors

Ordering vectors copied from independent sources, so the version parsers are
checked against something other than their own code. They are read offline by
`crates/gd-advisories/tests/version_order.rs`; no generator runs at test time.

| File | Source | How made |
|---|---|---|
| `semver-precedence.txt` | The item 11 example chain of the SemVer 2.0.0 specification, https://semver.org/#spec-item-11 | Copied by hand from the published list, 2026-11-17. |

Not recorded here yet: vectors from `golang.org/x/mod/semver`. No Go toolchain is
available in the build environment, so the Go adapter is tested against the
specification list above and the design's own examples (`v0.5.1` equals `0.5.1`,
the `v` removal is exact, pseudo-versions stay whole prereleases). Recording a
pinned Go generator's output is a later, explicit development step.

No Go reference vectors yet: nothing here is checked against
`golang.org/x/mod/semver` output, so the Go adapter's agreement with real Go
tooling is untested. Nor is there external ground truth for the Bitcoin Core and
`semver-beta` channel orders beyond the design's own examples.
