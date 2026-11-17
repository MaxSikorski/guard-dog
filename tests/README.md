# Tests

Every test and judge, one line each. Run them all from the repository root with `cargo test --locked`; the full local gate is:

```bash
cargo fmt --all --check && cargo clippy --locked --all-targets -- -D warnings && cargo build --locked && cargo test --locked && cargo deny --locked check
```

## Unit and integration tests

| Test | Where | What it proves |
|---|---|---|
| `terminal_escaping_neutralises_attacks` | `crates/gd-core/src/untrusted.rs` | Colour codes, cursor moves, OSC 8 hyperlinks, title changes, the C1 escape starter and NEL, newlines, NUL, bidirectional overrides, zero-width and tag characters, smuggling variation selectors, blank look-alikes and a leading combining mark all come out as visible text. |
| `terminal_escaping_leaves_ordinary_text_alone` | same | Accents, emoji (with their one presentation selector), quotes, arrows and right-to-left scripts pass through unchanged. |
| `html_escaping_neutralises_markup` | same | Script tags, event-handler attributes and quote breakouts are escaped, exactly once. |
| `debug_never_shows_the_content` | same | `{:?}` on untrusted text prints `Untrusted(<hidden>)`, never the text. |
| `expose_untrusted_returns_the_raw_value` | same | The one explicit way out returns the value unchanged. |
| `exactly_the_listed_characters_are_escaped_after_a_letter` | same (every one of Unicode's 1.1 million code points) | The escaped set is exactly control characters plus a reference table written separately in the test from Unicode 16 (default-ignorable, format, line and paragraph separators, blank braille). Dropping or adding a character on either side fails it. |
| `terminal_output_is_safe_and_reversible` | same (property test, 256 random hostile strings per run) | No control or invisible character survives terminal escaping, and unescaping the output gives back the exact input, so nothing is lost or ambiguous. |
| `html_output_is_safe_and_reversible` | same (property test) | No `<`, `>`, `"`, `'`, control or invisible character survives HTML escaping, every `&` starts one of our five references, and undoing the escaping gives back the exact input. |
| `ordinary_text_passes_through_unchanged` | same (property test) | Escaping never mangles ordinary text. |
| `untrusted_text_cannot_escape_without_saying_so` | `crates/gd-core/tests/compile_fail.rs` with `tests/ui/*.rs` | Code that prints, formats, `to_string()`s, dereferences, `AsRef`s, `Borrow`s, compares with `==`, converts or reads the field of `Untrusted<T>` does not compile (8 cases). The expected compiler errors are in `tests/ui/*.stderr` and depend on the pinned Rust version. |
| `version_names_the_release_and_its_source` | `crates/guard-dog/tests/version.rs` | `guard-dog --version` prints `guard-dog <version> (commit <full id>)` when the build was given `GD_GIT_COMMIT` (CI sets it), and `(development build)` otherwise. The expected text comes from the build's input, never from the baked-in value. |
| `every_advisory_is_valid_osv_json` and 8 more checks | `crates/gd-core/tests/advisory_corpus.rs` (Judge B, corpus part) | The 23 advisories in `advisories/corpus/*.json`, read in sorted order with no network, are exactly the reviewed list in the test (deleting or adding a file fails), are valid against the vendored OSV schema (`advisories/schema/`) with date and web-address formats checked, are named after their `id`, have an `https` primary-source reference, a 2 to 4 step plain-English playbook, a real `source_checked` date and well-formed ranges, and say "unknown" on every unknown range start. Two mutation tests show the schema and these rules reject broken records. The expected-matches half of Judge B waits for Judge A's recorded setups. |
| `release_profile_unwinds_and_checks_overflow` | `crates/gd-core/tests/profile_policy.rs` | The workspace `[profile.release]`, parsed as TOML, has `panic` absent or `"unwind"` and `overflow-checks = true`. |
| `the_policy_check_cannot_be_dodged_by_toml_spelling` | same | The check rejects abort written with tabs, quoted keys, quoted headers, dotted keys, inline tables and a comment trick, and rejects missing or false overflow checks. |
| `sensor_panic_is_contained` | same (only when panics unwind) | A panicking closure run under `catch_unwind` returns `Err` and the caller carries on: the containment primitive the daemon will use per sensor. |

### Property-test seed

The property tests use a fixed seed by default, so the same commit gives the same result every run; the seed in use is printed to stderr (`cargo test -- --nocapture` shows it). `GD_PROPTEST_SEED=<number> cargo test --locked -p gd-core` explores a different seed. A failing case is saved under `crates/gd-core/proptest-regressions/` and replayed on every later run; commit that folder when it appears.

## License and supply-chain guard

| Check | Where | What it proves |
|---|---|---|
| `cargo deny --locked check` | `deny.toml` | Every crate, including test-only ones and our own, has a permissive license (GPL, LGPL, AGPL, non-commercial and unknown licenses fail), comes from crates.io, has no known vulnerability, isn't unmaintained, unsound or yanked, and isn't OpenSSL. |

## The regtest lab

`lab/up.sh` starts five real services on an isolated regtest network (`lab/README.md`). These tests check the lab's compose file without starting Docker, so they run in every `cargo test`. The live lab runs nightly.

| Test | Where | What it proves |
|---|---|---|
| `lab_compose_passes_every_check` | `crates/gd-core/tests/lab_compose.rs` | `lab/compose.yml` runs exactly the five reviewed images, each pinned by digest with its expected version; every container is read-only, drops all capabilities, has `no-new-privileges`, a non-root user, and memory, swap, CPU and process limits (under 4 GiB in total); no ports, volumes, host mounts or Docker socket; one internal network; every node on regtest; bitcoind RPC open only to the lab subnet; the mint on FakeWallet; every credential a `${GD_LAB_*}` reference, never a value. |
| `every_unsafe_change_is_caught` | same | 21 unsafe edits are each refused with their own reason: an unpinned image, a published port, privileged mode, an added capability, the Docker socket, host networking, a non-internal network, mainnet on each of the three nodes, a missing or over-budget memory limit, a literal secret, a root user, a writable root, kept capabilities, missing `no-new-privileges`, an extra service, a real Lightning backend for the mint, RPC open to the world, a named volume. |
| `lab_readme_lists_every_pinned_image` | same | `lab/README.md` names every pinned image and version, so the docs and the compose file can't drift apart. |
| `lab_scripts_stay_on_the_lab_project_and_regtest` | same | `up.sh` and `down.sh` only touch the `gd-lab` project, `up.sh` checks all three chains, `down.sh` removes volumes and `lab/.data`, and neither mentions another chain, `prune`, `sudo`, `eval`, the Docker socket or `docker run`. |
| `no_generated_secret_is_committed` | same | No generated lab credential (`gdlabcanary-…`) is in any committed lab file, and `lab/.data/` is gitignored. |

**Live check (`lab/up.sh`, nightly and by hand):** cold start to a funded LND→Core Lightning channel; every node says `regtest` or the lab removes itself (exit 3); the least-privileged logins (bitcoind `gdwatch`, LND `info:read`, the CLN `getinfo` rune) each read the version and are each refused a wider call; every service's own version matches its image label; the whole start finishes in 5 minutes or it fails (exit 4). Measured 2026-11-16 on the Mac (arm64): cold start with all five images pulled fresh 86 s, warm (images cached) 68 s, peak 449 MiB for all five containers. Design run: 69–72 s, 422–447 MiB.

## Judges

The judges measure outcomes from outside the code. They arrive next, each with a recorded baseline:

- **Judge A, recorded real setups:** does Guard Dog find every service and its version?
- **Judge B, historical advisories:** does it report every advisory that applies, and nothing that doesn't? (The schema-checked corpus is in the table above; the matcher half arrives in Phase 2.)
- **Judge C, egress capture:** does anything leave the box that shouldn't, including planted canary secrets?
- **Judge D, injection corpus:** can hostile text in any channel make Guard Dog do or show anything? Running since Phase 0.7 (see below).

**Judge D** (`crates/gd-core/tests/judge_d_injection.rs`, corpus in `fixtures/injection/`, index and generator there): baseline 2026-11-16: 48 payloads (12 per family, 10 channels), 48 of 48 pass all seven checks (terminal and HTML output free of control characters and line breaks, no HTML-special characters, no invisible character from the Unicode 16 table and no leading combining mark, both round-trip). Not yet applicable, counted and not passed: family a, no action proposed 12 and no untrusted bytes in a privileged prompt 12; family d, display-width truncation 3 and bidi isolation 2. Teeth: against a naive renderer (text returned unchanged) 36 of 48 fail (a 4, b 12, c 11, d 9). Family a fails only incidentally, on its newlines and markup. Family c's Markdown `javascript:` link has no HTML-special character, so it passes naive too. Family d's 100 KB text, Hebrew-beside-versions and padding payloads still pass naive; they need the later renderers. Four tests:

| Test | What it proves |
|---|---|
| `judge_d_injection_corpus` | Every payload passes all seven checks, and the corpus is whole: exactly the ten channel folders, each family numbered 01 to 12 with all four in every channel, no empty file, and `generate.py` plain ASCII. |
| `a_naive_renderer_fails_the_judge` | Returning the text unchanged fails every payload except the twelve listed in `NAIVE_PASSES`, and at least one in every family. |
| `the_checks_catch_subtle_mistakes` | A leading mark outside the main combining blocks, and an emoji selector left raw after an escape, are both caught even though they round-trip. |
| `every_leading_mark_is_escaped` | Each of Unicode 16's 2,033 nonspacing and enclosing marks is escaped when it starts the text, in both renderers. |
