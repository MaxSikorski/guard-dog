# Tests

Every test and judge, one line each. Run them all from the repository root with `cargo test --locked`; the full local gate is:

```bash
cargo fmt --all --check && cargo clippy --locked --all-targets -- -D warnings && cargo build --locked && cargo test --locked && cargo deny check
```

## Unit and integration tests

| Test | Where | What it proves |
|---|---|---|
| `terminal_escaping_neutralises_attacks` | `crates/gd-core/src/untrusted.rs` | Colour codes, cursor moves, OSC 8 hyperlinks, title changes, the C1 escape starter, newlines, NUL, bidirectional overrides, zero-width and tag characters all come out as visible text. |
| `terminal_escaping_leaves_ordinary_text_alone` | same | Accents, emoji, quotes and arrows pass through unchanged. |
| `html_escaping_neutralises_markup` | same | Script tags, event-handler attributes and quote breakouts are escaped, exactly once. |
| `debug_never_shows_the_content` | same | `{:?}` on untrusted text prints `Untrusted(<hidden>)`, never the text. |
| `expose_untrusted_returns_the_raw_value` | same | The one explicit way out returns the value unchanged. |
| `terminal_output_never_contains_a_control_or_invisible_character` | same (property test, 256 random hostile strings per run) | No control or invisible character survives terminal escaping. |
| `html_output_never_contains_markup_or_a_stray_ampersand` | same (property test) | No `<`, `>`, `"`, `'`, control or invisible character survives HTML escaping, and every `&` starts one of our own references. |
| `ordinary_text_passes_through_unchanged` | same (property test) | Escaping never mangles ordinary text. |
| `untrusted_text_cannot_escape_without_saying_so` | `crates/gd-core/tests/compile_fail.rs` with `tests/ui/*.rs` | Code that prints, formats, `to_string()`s, dereferences, `AsRef`s, converts or reads the field of `Untrusted<T>` does not compile. The expected compiler errors are in `tests/ui/*.stderr` and depend on the pinned Rust version. |
| `version_names_the_release_and_the_current_commit` | `crates/guard-dog/tests/version.rs` | `guard-dog --version` prints `guard-dog <version> (commit <hash>)`, with the hash git reports for the checkout right now. |

## License and supply-chain guard

| Check | Where | What it proves |
|---|---|---|
| `cargo deny check` | `deny.toml` | Every dependency has a permissive license (GPL, LGPL, AGPL, non-commercial and unknown licenses fail), comes from crates.io, has no known vulnerability, isn't unmaintained, unsound or yanked, and isn't OpenSSL. |

## Judges

The judges measure outcomes from outside the code. They arrive next, each with a recorded baseline:

- **Judge A, recorded real setups:** does Guard Dog find every service and its version?
- **Judge B, historical advisories:** does it report every advisory that applies, and nothing that doesn't?
- **Judge C, egress capture:** does anything leave the box that shouldn't, including planted canary secrets?
- **Judge D, injection corpus:** can hostile text in any channel make Guard Dog do or show anything?
