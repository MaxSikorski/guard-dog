# Contributing to Guard Dog

Thanks for being here. I'm building Guard Dog so that anyone running their own Bitcoin and Nostr stack gets warned fast, privately and correctly when something they depend on turns dangerous. I know I'm missing things, and if you run your own node, relay or mint, you probably know some of them.

Guard Dog is **pre-alpha**. There's no code to install yet, which makes this the best time to shape it.

The [roadmap](ROADMAP.md) shows what's coming next and lists open questions where I'd love help. A good answer to one of those is a great first contribution.

## Ways to help

- **Test it on your setup.** Umbrel, StartOS, RaspiBlitz, myNode, nix-bitcoin, plain Docker or bare Linux. Once there's something to run, I'll need people to try it and tell me what it found, what it missed and what confused them.
- **Teach it a service.** Every service Guard Dog recognizes (Bitcoin Core, LND, Core Lightning, Alby Hub, BTCPay, Fulcrum, mempool, Cashu and Fedimint mints, Nostr relays, Blossom, bunkers…) is a small data file. If you run something it doesn't know, or you know how to read a version better, that's a great first contribution. See [Add my project](#add-my-project).
- **Curate advisories.** Turn a project's security notice into a clear advisory: which versions it affects, when it matters (for example "only if it's reachable from the internet"), and plain-English steps to fix it.
- **Break it, white hat.** Guard Dog itself is a juicy target. Try prompt injection through changelogs or relay descriptions, privilege escalation, or tricking the alerts. Please report anything you find **privately** (see [SECURITY.md](SECURITY.md)), and you'll get credit.
- **Write code.** The core is Rust. The interface is plain HTML, CSS and JavaScript with no frameworks.
- **Design, docs and translations.** Make it clearer for the next person who runs their own stack for the first time.

## Before you start

1. **Open an issue first** and say what you'd like to do. That way we don't build the same thing twice, and I can point you at the right place.
2. Keep each pull request to one change, and explain it in plain English: what changed, why, and how you checked it.

## Ground rules

- **Never post real secrets.** No seed phrases, nsecs, xpubs, macaroons, passwords, IP addresses or onion addresses in issues, pull requests, logs or test files. Redact first. Test data should be made-up regtest values.
- **Security problems go private.** Never in a public issue. See [SECURITY.md](SECURITY.md).
- **Only test what you own.** Guard Dog only scans your own machines and your own network. Contributions must keep it that way.
- **AI-assisted work is welcome,** but you have to understand it, test it and stand behind it.
- **Be kind.** We're all here because we care about people keeping their own keys and their own voice.

## Add my project

If you maintain a node, a Lightning implementation, a relay, a mint, a wallet, a platform or a miner, I'd love to have it in Guard Dog's catalog. An entry is one small file, `catalog/<id>.toml`. It is data, not code: it says what your software looks like when it runs, how to read its version, which ports should stay private and where its security advisories are published. The format is in [catalog/README.md](catalog/README.md), and the files in `catalog/` are worked examples.

Guard Dog is still pre-alpha. Right now the only thing that reads the catalog is a test that checks every entry; the parts that use it to recognize your software and match advisories come later. Adding your entry now means it is ready when they arrive.

### What I look for

- **An open-source licence.** GPL and other copyleft projects are welcome. An entry is information about your product. Guard Dog never ships, links or embeds your code. It only reads from your software: over its own network interface, from its container labels, or with a read-only command run as the service's own user.
- **A version we can read without changing anything.** For example a NIP-11 reply, an HTTP endpoint, an RPC or gRPC method, a label on your container image, or a command run as the service's own user. Never as root, and never with a credential that can write.
- **A public place your advisories go.** GitHub Security Advisories, OSV records, an Atom or RSS feed, or advisories kept as Markdown in a repo. If you only publish release notes, or nothing a machine can read, the entry says so in plain words (`blind_spot`). That way Guard Dog can say what it couldn't see about your project, rather than a bare "no known issues found".
- **A way to reach you privately,** if you have one. Point `[upstream] security_policy` at your security page. If you don't have one, the entry says so in its `todo` list.

### How to add it

1. **Open an issue first** and tell me which project it is, so we don't build the same thing twice.
2. Add one file, `catalog/<id>.toml`, and add your id to the `NOT_YET_IN_JUDGE_B` list in `crates/gd-core/tests/catalog.rs` (the test tells you if you forget). Then open a pull request. Copy the checklist below into the description and say in plain English what you checked. I review every catalog pull request myself before it merges.
3. Give a real version reply in `[[version.examples]]` and where it came from: a file in this repo, or a URL under your own project. The pattern that reads the version is tested against that real reply, not against what a version is supposed to look like. Redact the reply first. No seeds, macaroons, passwords, IP addresses or onion addresses, ever.
4. Run `cargo test --locked`. It checks your entry offline and tells you what to fix.

I add services to the regtest lab myself, in batches, so you don't need to write a lab recipe.

### Checklist

- [ ] One entry, `catalog/<id>.toml`, plus your id in `NOT_YET_IN_JUDGE_B`. The file name is the `id`: lower-case letters, digits and `-`, at most 40 characters. An entry is a product, not a repo.
- [ ] `licence` is one plain line. Use the SPDX id if you know it. If you don't, say `unknown` and add a `todo`.
- [ ] `money = true` if the software holds funds or keys.
- [ ] `[upstream] repo` is the canonical repository.
- [ ] `[version]` reads the version with a call that only reads, as the service user, never as root. `credential` names the least powerful credential it needs, in words (`none` if none).
- [ ] The version pattern starts with `^`, ends with `$`, has a group named `version`, and gives the right version for every reply in `[[version.examples]]`, and doesn't match any other entry's recorded replies (the test checks).
- [ ] `[advisories]` says how you publish (`ghsa`, `osv_packages`, `feeds`), or has a `blind_spot` in words.
- [ ] `[signing] level` is honest. `unsigned` and `unknown` are fine answers.
- [ ] Default ports are listed with an `exposure` (`never-public`, `lan` or `public-ok`).
- [ ] `binaries` and `units` are filled in, or each gap has a `binaries:` or `units:` line in `[review].todo`.
- [ ] Every fact has a source in `[review].sources`. Every question you couldn't answer is a line in `[review].todo`, not a guess.
- [ ] No secrets, keys, tokens, IP addresses or onion addresses anywhere in the file.
- [ ] `cargo test --locked` passes.

### What an entry can never do

An entry can only name read-only calls, and the test pins the exact list, so a call can't become a shell command, a write, or a request to an address of someone's choosing. Every call goes to the matching service on the user's own machine or home network. Guard Dog only scans your own machines and your own network, never holds keys or moves funds, and sends nothing about a setup anywhere you didn't choose, because there is no telemetry. Active tests run on regtest or signet, never mainnet.

## License

Guard Dog is licensed under [Apache-2.0](LICENSE). By contributing, you agree your contribution is licensed the same way.

## Other ways to support it

[Sponsoring on GitHub](https://github.com/sponsors/MaxSikorski) and sharing it on Nostr or X help too. See the **Support** section on the [Guard Dog website](https://maxsikorski.github.io/guard-dog/#support).

Thank you!
