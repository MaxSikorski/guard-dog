# Contributing to Guard Dog

Thanks for being here. I'm building Guard Dog so that anyone running their own Bitcoin and Nostr stack gets warned fast, privately and correctly when something they depend on turns dangerous. I know I'm missing things, and if you run your own node, relay or mint, you probably know some of them.

Guard Dog is **pre-alpha**. There's no code to install yet, which makes this the best time to shape it.

## Ways to help

- **Test it on your setup.** Umbrel, StartOS, RaspiBlitz, myNode, nix-bitcoin, plain Docker or bare Linux. Once there's something to run, I'll need people to try it and tell me what it found, what it missed and what confused them.
- **Teach it a service.** Every service Guard Dog recognizes (Bitcoin Core, LND, Core Lightning, Alby Hub, BTCPay, Fulcrum, mempool, Cashu and Fedimint mints, Nostr relays, Blossom, bunkers…) is a small data file. If you run something it doesn't know, or you know how to read a version better, that's a great first contribution.
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

## License

Guard Dog is licensed under [Apache-2.0](LICENSE). By contributing, you agree your contribution is licensed the same way.

## Other ways to support it

[Sponsoring on GitHub](https://github.com/sponsors/MaxSikorski) and sharing it on Nostr or X help too. See the **Support** section on the [Guard Dog website](https://maxsikorski.github.io/guard-dog/#support).

Thank you!
