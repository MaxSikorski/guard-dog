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
| `every_advisory_is_valid_osv_json` and 8 more checks | `crates/gd-core/tests/advisory_corpus.rs` (Judge B, corpus part) | The 23 advisories in `advisories/corpus/*.json`, read in sorted order with no network, are exactly the reviewed list in the test (deleting or adding a file fails), are valid against the vendored OSV schema (`advisories/schema/`) with date and web-address formats checked, are named after their `id`, have an `https` primary-source reference, a 2 to 4 step plain-English playbook, a real `source_checked` date and well-formed ranges, and say "unknown" on every unknown range start. Two mutation tests show the schema and these rules reject broken records. The expected matches are in `expected_matches.rs`, below. |
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

`lab/up.sh` starts five real services on an isolated regtest network (`lab/README.md`). These tests check the lab's compose file without starting Docker, so they run in every `cargo test`. The live lab is run by hand with `lab/up.sh`; the nightly CI runs it too.

| Test | Where | What it proves |
|---|---|---|
| `lab_compose_passes_every_check` | `crates/gd-core/tests/lab_compose.rs` | `lab/compose.yml` runs exactly the five reviewed images, each pinned by digest with its expected version; every container is read-only, drops all capabilities, has `no-new-privileges`, a non-root user, and memory, swap, CPU and process limits (under 4 GiB in total); no ports, volumes, host mounts or Docker socket; one internal network; every node on regtest; bitcoind RPC open only to the lab subnet; the mint on FakeWallet; every credential a `${GD_LAB_*}` reference, never a value. |
| `every_unsafe_change_is_caught` | same | 54 unsafe edits are each refused with their own reason: an unpinned image, a published port, privileged mode, an added capability, the Docker socket, host networking, a non-internal network, mainnet on each of the three nodes, a missing or over-budget memory limit, a literal secret, a root user, a writable root, kept capabilities, missing `no-new-privileges`, an extra service, a real Lightning backend for the mint, RPC open to the world, a named volume, a changed entrypoint, a second or differently spelled chain option, a zero memory limit, a missing tmpfs, an extra security option, a loosened network, a password hidden in the next command item, a YAML tag, a stray control character. |
| `lab_readme_lists_every_pinned_image` | same | `lab/README.md` names every pinned image and version, so the docs and the compose file can't drift apart. |
| `lab_scripts_stay_on_the_lab_project_and_regtest` | same | `up.sh` and `down.sh` only touch the `gd-lab` project, `up.sh` checks all three chains, `down.sh` removes volumes and `lab/.data`, and neither mentions another chain, `prune`, `sudo`, `eval`, the Docker socket or `docker run`. |
| `no_generated_secret_is_committed` | same | No generated lab credential (`gdlabcanary-…`) is in any committed lab file, and `lab/.data/` is gitignored. |

**Live check (`lab/up.sh`, by hand; the nightly CI runs it too):** cold start to a funded LND→Core Lightning channel; every node says `regtest` or the lab removes itself (exit 3); the least-privileged logins (bitcoind `gdwatch`, LND `info:read`, the CLN `getinfo` rune) each read the version and are each refused a wider call; every service's own version matches its image label; the whole start finishes in 5 minutes or it fails (exit 4). Measured 2026-11-16 on the Mac (arm64): cold start with all five images pulled fresh 86 s, warm (images cached) 68 s, peak 449 MiB for all five containers. Design run: 69–72 s, 422–447 MiB.

## Two back ends, views must agree

After Super Testnet's `hedgehog_v3`, which runs one test both offline and on regtest and compares what each side thinks. A judge sees a setup through a back end; the same judge on two back ends that describe the same setup must see the same facts, or the test fails and prints every fact that differs. Three back ends describe the lab: `fixture` (the `lab-regtest` setup in `fixtures/expected-matches.toml`), `lab-recorded` (`fixtures/lab-recorded/manifest.toml`, written by a real `lab/up.sh` run) and `lab-live` (`lab/.data/manifest.toml`, the last manifest `lab/up.sh` wrote; `lab/down.sh` deletes it).

Each back end says which kinds of fact it records, and each judge says which it reads. Judge B reads the chain, platform, arch, block storage, exposure, service versions and the packages inside them. The lab manifest records only the chain, platform, source and service versions, so arch, block storage, exposure and packages are **not compared** for the lab: the test lists them by name and pins that list, so the gap can't grow or shrink unnoticed. Judge A and Judge C plug in as a row in `JUDGES` naming what they read; each back end then records those facts (for the lab, a new key in `up.sh`'s manifest) or the pinned list grows. Judge D reads its corpus, not a setup.

In `crates/gd-core/tests/two_backends.rs`:

| Test | What it proves |
|---|---|
| `the_recorded_lab_agrees_with_the_fixtures` | On every `cargo test`: Judge B sees the same 8 facts (chain, platform, source and five service versions) through the fixture and the recorded lab, with exactly the four known gaps. The recording's `# image` lines equal the images `lab/compose.yml` pins, so a changed image fails until the lab is re-recorded. |
| `the_live_lab_agrees_with_the_fixtures` | With `GD_LAB=1`: the same against the live lab's manifest, failing if it is missing. Without it, it prints `SKIPPED` (shown even in a plain `cargo test`) and passes. Any value other than unset, `0` or `1` fails. |
| `disagreements_are_named_field_by_field` | A changed version, a missing service, an extra service, another chain, a package only one side has, and two differences at once (in sorted order) each give exactly the expected message; a kind of fact one back end doesn't record is listed as not compared. |
| `a_good_manifest_is_read_exactly` | A manifest in `up.sh`'s shape reads back as exactly its facts and image lines. |
| `an_oversized_or_odd_file_is_never_read_whole` | A 64 KiB file is read only to 16 KiB plus one byte and refused; a missing file is "no lab"; a folder (or a symlink) is an error, never a skip. |
| `every_broken_manifest_is_refused` | 27 broken manifests are each refused for their own reason: not TOML, unknown keys (one with a terminal escape, never printed), wrong format or recorder, a missing or odd chain, an odd source or one that isn't the lab, a description with a control character or a bidi override or over 200 characters, no services, too many, a missing or non-text version, ids outside `[a-z0-9-]`, versions outside `up.sh`'s `plain()` characters or over 64 long (space, escape, newline), duplicates and unsorted ids. |
| `up_sh_still_writes_this_format` | `lab/up.sh` still writes the manifest lines this test reads, checks the chain and all five reported versions with `plain()`, and `lab/.data/` is still gitignored. |

**Live check, 2026-11-16 (Mac, arm64):** with `lab/up.sh` up (cold start to funded channel in 68 s), `GD_LAB=1 cargo test --locked -p gd-core --test two_backends` passes: the fixture and the live lab agree on 8 of 8 facts, 4 kinds not compared. Changing one recorded version (Core Lightning 26.06.9 to 26.06.8) fails with that one fact named; changing one recorded image digest fails with "re-record it". With no lab, `GD_LAB=1` fails.

## Judges

The judges measure outcomes from outside the code. They arrive next, each with a recorded baseline:

- **Judge A, recorded real setups:** does Guard Dog find every service and its version?
- **Judge B, historical advisories:** does it report every advisory that applies, and nothing that doesn't? (The schema-checked corpus is in the table above; expected matches and the baseline are below; the matcher arrives in Phase 2.)
- **Judge C, egress capture:** does anything leave the box that shouldn't, including planted canary secrets?
- **Judge D, injection corpus:** can hostile text in any channel make Guard Dog do or show anything? Running since Phase 0.7 (see below).

**Judge D** (`crates/gd-core/tests/judge_d_injection.rs`, corpus in `fixtures/injection/`, index and generator there): baseline 2026-11-16: 48 payloads (12 per family, 10 channels), 48 of 48 pass all seven checks (terminal and HTML output free of control characters and line breaks, no HTML-special characters, no invisible character from the Unicode 16 table and no leading combining mark, both round-trip). Not yet applicable, counted and not passed: family a, no action proposed 12 and no untrusted bytes in a privileged prompt 12; family d, display-width truncation 3 and bidi isolation 2. Teeth: against a naive renderer (text returned unchanged) 36 of 48 fail (a 4, b 12, c 11, d 9). Family a fails only incidentally, on its newlines and markup. Family c's Markdown `javascript:` link has no HTML-special character, so it passes naive too. Family d's 100 KB text, Hebrew-beside-versions and padding payloads still pass naive; they need the later renderers. Four tests:

| Test | What it proves |
|---|---|
| `judge_d_injection_corpus` | Every payload passes all seven checks, and the corpus is whole: exactly the ten channel folders, each family numbered 01 to 12 with all four in every channel, no empty file, and `generate.py` plain ASCII. |
| `a_naive_renderer_fails_the_judge` | Returning the text unchanged fails every payload except the twelve listed in `NAIVE_PASSES`, and at least one in every family. |
| `the_checks_catch_subtle_mistakes` | A leading mark outside the main combining blocks, and an emoji selector left raw after an escape, are both caught even though they round-trip. |
| `every_leading_mark_is_escaped` | Each of Unicode 16's 2,033 nonspacing and enclosing marks is escaped when it starts the text, in both renderers. |

**Judge B, expected matches** (`crates/gd-core/tests/expected_matches.rs`; the file is `fixtures/expected-matches.toml`, its format is in `fixtures/README.md`). The expectations were written by hand before any matcher exists. Two setups, each against all 23 advisories:

| Setup | Affected | Not affected | Possibly affected |
|---|---|---|---|
| `lab-regtest` (the lab's five pinned services) | 0 | 23 | 0 |
| `lab-old-synthetic` (labelled synthetic: the lab's configuration with Core 28.1, LND 0.18.4-beta, CLN 25.09 and Nutshell 0.17.0) | 7 | 14 | 2 |

Three pairs are marked for Max's review. The lab's xz result comes from the versions read inside each pinned image. An alert scores only if its result is exactly the expected one. The matcher sees only the setup and advisory ids.

**Baseline 2026-11-16: no matcher yet.** Reported 0, precision n/a (nothing reported), recall 0% (0 of 9).

Five tests:

| Test | What it proves |
|---|---|
| `expected_matches_cover_every_setup_and_advisory` | The file passes every check, and at least one pair is affected. The checks: every setup has exactly one sorted entry per corpus advisory; ids and products exist; each result follows from its separate version and condition calls; every in-range or out-of-range call has an affected package (platform-scoped entries only where they apply) that maps to a product in the setup, and `not-applicable` is used only when none does; every condition `service` in the corpus is a product id or alias; possibly-affected has a question; reasons are one printable line; `lab-regtest`'s services and versions equal the id and expected-version labels in `lab/compose.yml`; a synthetic setup says so. |
| `every_platform_scope_is_understood` | Every per-entry `database_specific.platform` in the corpus has a rule saying which setups it applies to. A new platform text fails. |
| `judge_b_matcher_baseline` | Scores the stub matcher, which says nothing, and pins the baseline above. Update both when the matcher lands. |
| `the_scoring_has_teeth` | The expectations themselves score 100% precision and recall. Flagging everything "affected", or hedging everything "possibly", gets exactly the matching pairs right (counted from the file) and loses precision on the rest. |
| `every_broken_file_is_refused` | 23 broken edits are each refused for their own reason. Among them: a result the two calls don't give, a doubled or missing pair, a missing question, a wrong lab version or service, a version call with no matching package, `not-applicable` for a product that is present, a condition service with no product, an unlabelled synthetic setup, and package versions without their evidence. |
