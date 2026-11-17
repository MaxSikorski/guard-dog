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
Nor is there external ground truth for the Bitcoin Core and `semver-beta`
channel orders beyond the design's own examples.

Also not tested against anything external: the Core Lightning calver order and the git-describe (strfry) order. Both are checked against the design's own examples and an independent integer model written for the tests, not against Core Lightning's or git's own tools. PEP 440 is the exception: it is checked against `packaging` (`crates/gd-advisories/tests/reference/pep440-source.md`), as a strict subset (no Unicode whitespace, no Kelvin sign or long s).
