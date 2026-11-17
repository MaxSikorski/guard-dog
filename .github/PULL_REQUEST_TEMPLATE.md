<!--
Thanks for contributing to Guard Dog! Please keep each pull request to one change,
and write in plain English. Security problems never go in a pull request: see SECURITY.md.
-->

## What and why

<!-- One or two sentences: what this changes, and why it matters to someone running their own node, relay or mint. -->

For #<!-- issue number. Please write "For #n"; don't use "Fixes", "Closes" or "Resolves". An issue closes once a release contains the change. -->

## How I tested it

<!-- Paste the result of each command you ran (test counts are perfect). Every test is listed in tests/README.md. -->

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --locked --all-targets -- -D warnings`
- [ ] `cargo build --locked`
- [ ] `cargo test --locked`
- [ ] `cargo deny --locked check`
- [ ] Other (the regtest lab, a judge, the website on phone and desktop widths):

## What I didn't test

<!-- Be honest; "nothing else" is fine if true. For example: "only on macOS", "not on a real node", "no lab run". -->

## Checklist

- [ ] No real secrets anywhere in this change, its tests, logs or description: no seeds, passphrases, nsecs, xpubs, macaroons, passwords, tokens, IP addresses or onion addresses. Test data is made-up regtest values.
- [ ] Text from outside (changelogs, advisories, relay descriptions, banners, web pages) stays data. It never reaches a shell, SQL, a file path or an AI prompt that can take actions.
- [ ] Any new Rust dependency has a permissive licence and passes `cargo deny --locked check`. No GPL, AGPL or non-commercial code.
- [ ] Guard Dog still never holds keys, moves funds, changes a system without the user's approval, or scans machines the user doesn't own.
- [ ] Docs and `tests/README.md` are updated if behaviour or tests changed.
- [ ] This touches a sensitive path (`.github/`, `deny.toml`, `rust-toolchain.toml`, a `build.rs`, release, signing or install privileges) and I've said so above.

## AI assistance

<!-- AI-assisted work is welcome. Say which tools helped, if any. -->

- [ ] No AI tools were used.
- [ ] AI tools helped (which: ______). I've read every line, I understand it, I tested it, and I stand behind it.
