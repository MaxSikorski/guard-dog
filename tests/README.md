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
| `a_failing_openssl_stops_up_sh_before_anything_starts` | same | If `openssl` fails, prints nothing or prints too little, `up.sh` exits 1 before any credential is written or anything starts, and leaves no `lab/.data` or lock behind. |
| `an_existing_lock_is_refused_until_unlock` | same | An existing lock is never taken over: `up.sh` and `down.sh` refuse it whether its owner is running or not, `--unlock` removes only the lock directory, and a symlink or file at that path is refused and left alone. |
| `index_paths_under_lab_data_are_refused` | same | The git-index check refuses any path under `lab/.data`, however it is spelled (including `lab/.DATA` and `lab/.lock`), and accepts `lab/up.sh`. |
| `no_generated_secret_is_committed` | same | No generated lab credential (`gdlabcanary-…`) is in any committed lab file, and `lab/.data/` is gitignored. |

**Live check (`lab/up.sh`, by hand; the nightly CI runs it too):** cold start to a funded LND→Core Lightning channel; every node says `regtest` or the lab removes itself (exit 3); the least-privileged logins (bitcoind `gdwatch`, LND `info:read`, the CLN `getinfo` rune) each read the version and are each refused a wider call; every service's own version matches its image label; the whole start finishes in 5 minutes or it fails (exit 4). Measured 2026-11-16 on the Mac (arm64): cold start with all five images pulled fresh 86 s, warm (images cached) 68 s, peak 449 MiB for all five containers. Design run: 69–72 s, 422–447 MiB.

## Two back ends, views must agree

After Super Testnet's `hedgehog_v3`, which runs one test both offline and on regtest and compares what each side thinks. A judge sees a setup through a back end; the same judge on two back ends that describe the same setup must see the same facts, or the test fails and prints every fact that differs. Three back ends describe the lab: `fixture` (the `lab-regtest` setup in `fixtures/expected-matches.toml`), `lab-recorded` (`fixtures/lab-recorded/manifest.toml`, written by a real `lab/up.sh` run) and `lab-live` (`lab/.data/manifest.toml`, the last manifest `lab/up.sh` wrote; `lab/down.sh` deletes it).

Each back end says which kinds of fact it records, and each judge says which it reads. Judge B reads the chain, platform, arch, block storage, exposure, service versions and the packages inside them. The lab manifest records the chain, platform, source, arch, block storage and exposure (both read from `docker inspect` of the running containers) and service versions, so only the packages are **not compared** for the lab: the test lists them by name and pins that list, so the gap can't grow or shrink unnoticed. Judge A and Judge C plug in as a row in `JUDGES` naming what they read; each back end then records those facts (for the lab, a new key in `up.sh`'s manifest) or the pinned list grows. Judge D reads its corpus, not a setup.

In `crates/gd-core/tests/two_backends.rs`:

| Test | What it proves |
|---|---|
| `the_recorded_lab_agrees_with_the_fixtures` | On every `cargo test`: Judge B sees the same 10 facts (chain, platform, arch, block storage, exposure and five service versions; the count is of facts actually compared) through the fixture and the recorded lab, with exactly the one known gap (packages). The recording's `# image` lines equal the images `lab/compose.yml` pins, one per service, so a changed image fails until the lab is re-recorded. Each service's `# ... reported` text and its version must agree (`/Satoshi:32.1.0/` is 32.1, `v26.06.9` is 26.06.9, `Nutshell/0.21.0` is 0.21.0). The parser also requires `source = "lab"`. |
| `the_live_lab_agrees_with_the_fixtures` | With `GD_LAB=1`: the same against the live lab's manifest (image lines included), failing if it is missing. The nightly runs it with `GD_LAB=1` right after `lab/up.sh` (amd64). Without it, it prints `SKIPPED` (shown even in a plain `cargo test`) and passes. Any value other than unset, empty, `0` or `1` fails, including one that isn't UTF-8. |
| `disagreements_are_named_field_by_field` | A changed version, a missing service, an extra service, another chain, a package only one side has, and two differences at once (in sorted order) each give exactly the expected message; a kind of fact one back end doesn't record is listed as not compared. |
| `a_good_manifest_is_read_exactly` | A manifest in `up.sh`'s shape reads back as exactly its facts and image lines. A second image line, a missing one, and an id line with a hidden bidi comment are each refused by line number, without echoing the line. |
| `an_oversized_or_odd_file_is_never_read_whole` | A 64 KiB file is read only to 16 KiB plus one byte and refused; a missing file is "no lab"; a folder (or a symlink) is an error, never a skip. |
| `a_pipe_a_symlink_and_a_swapped_file_are_refused` | A FIFO at the path is refused at once (the reader doesn't hang), a symlink to a good file is refused, and the file identity (device and inode) of the opened file must equal the looked-at path's, so a swap between the look and the open is refused. |
| `every_broken_manifest_is_refused` | 31 broken manifests are each refused for their own reason: not TOML, unknown keys (one with a terminal escape, never printed), wrong format or recorder, a missing or odd chain, an odd source or one that isn't the lab, a description with a control character or a bidi override or over 200 characters, no services, too many, a missing or non-text version, ids outside `[a-z0-9-]`, versions outside `up.sh`'s `plain()` characters or over 64 long (space, escape, newline), duplicates and unsorted ids. |
| `up_sh_writes_the_container_facts` | Text check only: `lab/up.sh` still writes the `arch`, `block_storage` and `exposure` lines and still has the `docker inspect` checks in it (arch: image architecture, and the pulled manifest's when Docker shows it, `mixed` if they differ; block storage: `tmpfs` only with a read-only root, at least one tmpfs and no other mount, else `disk`; exposure: `published` for published-all, any host port binding, host networking or a shared network namespace). It does not run them: the nightly's `GD_LAB=1` run is the real check. |
| `reported_text_and_version_must_agree` | A reported text that means another version than the manifest's (`/Satoshi:32.2.0/` against 32.1), one that isn't in its service's usual shape, a missing one, a bare Nutshell version (accepted, as `lab/up.sh` does), a reported line whose service name doesn't belong to the id under it, and a malformed or doubled reported line are each refused with the service named; the rules match `lab/up.sh` step 9. |
| `a_dangling_last_line_is_refused` | A `# image` or `# reported` line with no service after it (a stray last line) is refused by line number. |
| `random_well_formed_manifests_round_trip` | Property test, fixed seed, 300 random well-formed manifests in `up.sh`'s shape: each reads back as exactly its facts, image lines and reported texts, and reported text and version agree. |
| `random_malformed_manifests_are_refused_by_name_and_never_panic` | Property test, fixed seed, 300 random breakages (a required line deleted, an unknown key, a bad word, a bad version, a service twice, a junk line): each is refused with its own named error, plain ASCII. |
| `random_bytes_and_cut_manifests_never_panic` | Property test, fixed seed, 500 rounds of random noise (always refused, with a plain error) and a good manifest cut at a random place (accepted or refused plainly, never a panic). |
| `up_sh_still_writes_this_format` | `lab/up.sh` still writes the manifest lines this test reads, checks the chain and all five reported versions with `plain()`, and `lab/.data/` is still gitignored. |

**Live check, 2026-11-16 (Mac, arm64):** with `lab/up.sh` up (cold start to funded channel in 68 s), `GD_LAB=1 cargo test --locked -p gd-core --test two_backends` passes: the fixture and the live lab agree on 7 of 7 compared facts, 4 kinds not compared (before arch, block storage and exposure were recorded; the next live run reports 10 of 10 with packages the one kind not compared). Changing one recorded version (Core Lightning 26.06.9 to 26.06.8) fails with that one fact named; changing one recorded image digest fails with "re-record it". With no lab, `GD_LAB=1` fails.

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

Two pairs are marked for Max's review. The lab's xz result comes from the versions read inside each pinned image. An alert scores only if its result is exactly the expected one. The matcher sees only the setup and advisory ids.

**Baseline 2026-11-16: no matcher yet.** Reported 0, precision n/a (nothing reported), recall 0% (0 of 9).

Five tests:

| Test | What it proves |
|---|---|
| `expected_matches_cover_every_setup_and_advisory` | The file passes every check, and at least one pair is affected. The checks: every setup has exactly one sorted entry per corpus advisory; ids and products exist; each result follows from its separate version and condition calls; every in-range or out-of-range call has an affected package (platform-scoped entries only where they apply) that maps to a product in the setup, and `not-applicable` is used only when none does; every condition `service` in the corpus is a product id or alias; possibly-affected has a question; reasons are one printable line; `lab-regtest`'s services and versions equal the id and expected-version labels in `lab/compose.yml`; a synthetic setup says so. |
| `every_platform_scope_is_understood` | Every per-entry `database_specific.platform` in the corpus has a rule saying which setups it applies to. A new platform text fails. |
| `judge_b_matcher_baseline` | Scores the stub matcher, which says nothing, and pins the baseline above. Update both when the matcher lands. |
| `the_scoring_has_teeth` | The expectations themselves score 100% precision and recall. Flagging everything "affected", or hedging everything "possibly", gets exactly the matching pairs right (counted from the file) and loses precision on the rest. |
| `every_broken_file_is_refused` | 23 broken edits are each refused for their own reason. Among them: a result the two calls don't give, a doubled or missing pair, a missing question, a wrong lab version or service, a version call with no matching package, `not-applicable` for a product that is present, a condition service with no product, an unlabelled synthetic setup, and package versions without their evidence. |

**Judge C** (`crates/gd-egress`, expected reports in `tests/egress/`, which has its own README): baseline 2026-11-16 (revision 1, after the Opus and Codex reviews), on synthetic captures only: 61 of 61 scenarios give their expected report. The live run arrives with the lab harness. What it proves: for one commit and one workload, every flow went to an allowlisted destination, the capture is complete from a proven start to a proven end, and no planted canary appears under the decoding set (see `tests/egress/README.md`). What it does not: a build that deliberately encrypts or obfuscates, or end-to-end encrypted payloads to allowed hosts; other layers cover those. Compressed request bodies fail the judge until the decoders arrive in PR 1b. Teeth: each of S02 to S08 and S10 to S61 fails on purpose (S09 is the passing allowlisted control) with exactly the report written for it, and switching off token decoding, JSON decoding, the TLS-name check or the post control fails named scenarios (checked in the pull request). Seven test files, run by `cargo test --locked -p gd-egress`:

| Test | Where | What it proves |
|---|---|---|
| `prng_matches_the_reference_splitmix64` | `crates/gd-egress/tests/encoders.rs` | The generator gives the five outputs the reference C program printed for seed 1234567, and bytes are the values in little-endian order. |
| `bech32_matches_the_nip19_example`, `base58check_matches_bip32_test_vector_1`, `onion_checksum_accepts_a_real_v3_address`, `bip39_matches_the_trezor_vectors`, `bip39_wordlist_is_the_published_one`, `ipv6_text_follows_rfc_5952` | same | Each encoder matches a published test vector: NIP-19's nsec, BIP32's first xpub, a real v3 onion address, Trezor's BIP39 phrases and the wordlist's SHA-256, RFC 5952 text. |
| `own_encoders_agree_with_data_encoding` | same (property test) | Our hex, base64, base64url and base32 (and their decoders) agree with the independent `data-encoding` crate on random bytes. |
| `canaries_are_stable_for_a_seed` | `crates/gd-egress/tests/canaries.rs` | The canaries for seed 1 equal `tests/egress/golden/canaries-seed-1.json` byte for byte, and read back from it. |
| `canaries_differ_between_seeds` | same | Over seeds 1 to 1000, no class repeats a value (IPv4, with 254 values, gives at least 200). |
| `every_canary_has_its_shape` | same | Each canary matches the regex for its kind, written in the test; the seed phrase is 24 real BIP39 words. |
| `setup_root_holds_exactly_the_placements` | same | The planted tree holds exactly the ten reviewed files, every canary is in at least one, and nothing else is written. |
| `the_answer_key_is_never_inside_the_root` | same | No planted file holds the control token, and `canaries.json` sits outside the tree Guard Dog can read. |
| `needles_find_every_encoding` | `crates/gd-egress/tests/needles.rs` (property test) | Any canary, IPv4 and IPv6 included, is found raw, upper-case, hex, base64 or base64url or base32 at any 0 to 8 byte offset, percent-encoded, JSON-escaped and quoted, inside random junk. |
| `wrapped_and_separated_forms_are_found` | same (property test) | Base64 wrapped with spaces or line breaks, and plain text split by space, newline, `-`, `:` or `.` every 1 to 16 characters, is still found. |
| `redaction_never_prints_canary_derived_text` | same (property test) | Whatever form a canary takes inside a printed string, the printed form holds no 8-character piece of its text or of the hex of its bytes. |
| `ip_values_parse_every_supported_form`, `ip_near_misses_are_not_found` | same | IPv4 as dotted, integer or `0x` text and IPv6 in every `Ipv6Addr` form (including a dotted tail) or as raw bytes are matched by value; a neighbouring address, each with its positive twin, is not. |
| `needles_ignore_unrelated_traffic` | same (property test) | 256 random printable strings of up to 4 KiB give no hit, and the same strings with a canary appended do. |
| `seed_phrase_is_found_with_any_separator` | same | Any three consecutive seed words are found whether joined by space, comma, quotes, `%20`, `+`, newline or `-`; two words are not. |
| `ipv4_needle_respects_digit_boundaries` | same | `198.51.100.7` is not found inside `198.51.100.71` or `2198.51.100.7`, and is found once the touching digit is separated off. |
| `redaction_never_prints_a_canary` | same | A canary in printed text becomes `<canary:CLASS>`, even cut short, and no 16-character piece of it survives. |
| `an_empty_allowlist_parses`, `allowlist_rejects_each_bad_entry`, `allowlist_matches_exact_host_and_port` | `crates/gd-egress/tests/allowlist.rs` | `allowlist.toml` format 1: 18 bad shapes (wildcard, IP literals, upper case, trailing dot, single label, long label, port mistakes, duplicates, unknown keys, missing keys, wrong format) each fail with their own named error, and matching is exact host and port. |
| `pcap_reads_sll2_both_byte_orders_and_nanoseconds`, `pcap_rejects_truncated_files`, `pcap_rejects_a_wrong_link_type_and_a_bad_header`, `pcap_parser_never_panics` | `crates/gd-egress/tests/parsers.rs` | The packet reader handles both byte orders and both time stamps, skips incoming packets, calls every cut-off file `truncated` (except a cut exactly between two records, which is a well-formed shorter file), and never panics on random bytes. |
| `lo_reads_host_records_and_sink_reads_outgoing`, `tcp_gaps_and_conflicts_are_reported`, `dns_queries_with_extra_sections_are_rejected`, `every_dns_question_is_read` | `crates/gd-egress/tests/parsers.rs` | Loopback is read from host-type records and the black hole from outgoing ones (the other copies are counted, not read); TCP gaps and conflicting retransmissions are named and nothing is filled in; a DNS query with an answer, authority or non-OPT additional record, a short header or a cut frame fails closed; every question of a message is read. |
| `dns_log_decodes_escapes_and_rejects_stray_lines`, `mitm_jsonl_rejects_unknown_events_and_keys`, `rules_normalisation_ignores_comments_and_counters` | same | The resolver log decodes `\DDD` escapes and rejects stray lines; the recorder log rejects bad headers, unknown events, unknown keys and bad lines, and takes lines in any order; rule dumps compare without comments and counters. |
| `every_synthetic_scenario_gives_its_expected_report` | `crates/gd-egress/tests/scenarios.rs` | All 61 synthetic scenarios (S01 to S61) give their expected report byte for byte. |
| `capture_statistics_are_required_and_must_be_clean` | `crates/gd-egress/tests/scenarios.rs` | A missing `pcap/tcpdump.log`, a missing count, any kernel drop, or a packet count that differs from the pcap gives F5. |
| `report_is_independent_of_seed`, `report_is_independent_of_event_order` | same | S03, S04, S05, S08, S22, S25, S30, S31, S44 and S49 give identical bytes for seeds 1, 2 and 3; S03 and S06 give identical bytes when log lines are reversed and rotated, and S49 when whole connections are. |
| `canaries_command_writes_root_judge_teeth_and_control`, `canaries_command_refuses_an_existing_output`, `check_exits_0_on_pass_1_on_fail_2_on_bad_input` | `crates/gd-egress/tests/cli.rs` | The command line writes the five outputs and refuses to overwrite; `check` exits 0 on a pass, 1 on a leak, 2 on a bad file, fails closed on an empty capture, and never prints a canary. |
