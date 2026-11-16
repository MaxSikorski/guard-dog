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

## License and supply-chain guard

| Check | Where | What it proves |
|---|---|---|
| `cargo deny --locked check` | `deny.toml` | Every crate, including test-only ones and our own, has a permissive license (GPL, LGPL, AGPL, non-commercial and unknown licenses fail), comes from crates.io, has no known vulnerability, isn't unmaintained, unsound or yanked, and isn't OpenSSL. |

## Judges

The judges measure outcomes from outside the code. They arrive next, each with a recorded baseline:

- **Judge A, recorded real setups:** does Guard Dog find every service and its version?
- **Judge B, historical advisories:** does it report every advisory that applies, and nothing that doesn't?
- **Judge C, egress capture:** does anything leave the box that shouldn't, including planted canary secrets?
- **Judge D, injection corpus:** can hostile text in any channel make Guard Dog do or show anything?
