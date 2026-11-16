# Guard Dog

**A self-hosted, local-first security watchdog for people whose money and identity run on Bitcoin and Nostr.**

> **Status: pre-alpha.** There's nothing to install yet. Watch this repo for the first release.

## Why I'm building this

In July 2026, the Coldcard hack drained about $116M from hardware wallets. Their firmware had quietly been making weak seeds since 2021. The people who got hit had done pretty much everything right, and updating wasn't even enough: they needed brand-new seeds. A couple of months later, Alby Hub had a wallet-takeover flaw that hit people running old versions with the Hub open to the internet, even though a fix had been out for about a year.

If your money and identity live on your own infrastructure, you're your own security team. I want Guard Dog to be the member of that team that never sleeps. It knows everything your setup depends on, notices the moment any of it becomes dangerous, and tells you in plain English exactly what to do.

## What it will do

- **Know what you run.** It finds your services on Umbrel, StartOS, RaspiBlitz, myNode, nix-bitcoin, Docker or plain Linux:
  - Bitcoin Core / Knots
  - LND, Core Lightning, Alby Hub / LDK
  - BTCPay Server, Fulcrum, electrs, mempool
  - Cashu and Fedimint mints
  - Nostr relays, Blossom servers, NIP-46 bunkers
  - the base layer underneath

  You can also register the hardware wallets and apps it can't see, and paste in any git repo you want it to watch.
- **Tell you when something becomes dangerous.** It matches what you run against security advisories, including conditions like "only if this port is open to the internet". Alerts come by Nostr DM, ntfy, Signal/Telegram or email, with step-by-step fixes.
- **See what an attacker sees.**
  - Exposure checks for ports, router mappings, Tor, tunnels and proxies.
  - An outside-in probe from a buddy's Guard Dog.
  - **Scout:** our own network discovery. It recognizes Bitcoin and Nostr services anywhere on your home network and spots attacks such as ARP spoofing.
- **Recommend the safest version, not just the latest.** Signed, matching the published hashes, past a cooling-off period, with no known advisories.
- **Watch for signs of a break-in.** Watch-only alerts for your wallets, npub and Lightning node, plus canary tripwires.
- **Optional local AI.** It works with any OpenAI-compatible endpoint and prefers models on your own hardware. Everything important works with no AI at all.

## What it will never do

- Hold your keys or move your funds.
- Send your setup's details anywhere you didn't choose. There's no telemetry.
- Change anything without your one-tap approval.
- Tell you you're "secure". It says **"no known issues found"**, along with when it checked and what it *couldn't* see.
- Scan anybody else's machines.

## Help build it

I know I'm missing things. If you run your own node, relay or mint, you already know something Guard Dog needs to know. There's room for testers, people who know a service inside out, advisory curators, white-hat breakers, Rust and web developers, and writers. Start with [CONTRIBUTING.md](CONTRIBUTING.md).

## Support

Guard Dog is free and open source, with no subscriptions and no ads. If it helps you:

- **[Sponsor it on GitHub](https://github.com/sponsors/MaxSikorski)**, one-time or monthly.
- **Follow along on Nostr:** `npub18rxdd7k5ayly50965a9rv8r7qrqmxn3tjsdp348xg205msrwyc9sacjx70`
- **Share it** on Nostr or X. There's a ready-made note on the [website](https://maxsikorski.github.io/guard-dog/#support).

## Security

Found a vulnerability in Guard Dog? Please report it privately. See [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE).

*No known issues is not the same as secure. Guard Dog helps you keep watch; it doesn't replace your own judgment.*
