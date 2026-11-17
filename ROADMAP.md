# Guard Dog roadmap

This is where Guard Dog is going, in plain words, and where I could really use your help. I'm a builder, not a professional security engineer. If you run your own node, relay or mint, you probably know things about your setup that I don't, and I'd love for you to shape this.

## Where things stand

Guard Dog is **pre-alpha**. There's nothing to install yet. Right now we're laying the foundations: a Rust workspace that builds and tests the same way every time, and the "judges", automatic tests that decide whether Guard Dog actually works, so it's never just me or an AI saying so. You can see every test and judge, and what each one proves, in [tests/README.md](tests/README.md).

## How to read this

- **Now** is what we're working on.
- **Next** is the first useful version: it knows what you run, tells you when it becomes dangerous, and shows you what an attacker sees. I'm aiming to reach it within about 90 days of publishing this roadmap. That's an aim, not a promise, and nothing after Next has a date.
- **Later** is everything after that, in rough order.
- **Will** means we've decided to build it. **Could** means it's an idea we're still weighing, and your input can change it.

The order can change as we learn.

## Now: foundations and the judges

What you get from this phase is nothing to run yet, but a way to trust what comes next. Here's where each piece is today:

- **Done:** one command builds and tests everything, from a pinned Rust toolchain, with only permissively licensed dependencies.
- **Running today: Judge D.** It feeds a corpus of injection attacks (fake changelogs, relay descriptions, banners) through Guard Dog on every pull request, and fails if any of them makes Guard Dog take an action or step outside its fixed set of answers. It's a tripwire, not proof.
- **In progress: Judge B.** It will check advisory matching against real historical advisories, with the expected answers written down in advance. The corpus of past advisories is in, but it can't be run until Judge A's recorded setups exist.
- **Not started: Judge A.** It will check Guard Dog against snapshots of real setups, with every identifier replaced by made-up values.
- **Not started: Judge C.** It will record outbound network activity in CI and fail on any connection that isn't on the expected list, or that carries one of the planted test secrets.
- **Not started: the lab.** A regtest lab (a throwaway Bitcoin network that can never touch real money) with the first few services.

## Next: the first useful version

**It knows what you run.** Guard Dog will find your services and their exact versions. It will cover the platforms and services in the [README](README.md#what-it-will-do), except where an open question below says otherwise, plus home miners like Bitaxe. You'll be able to register the things it can't see (hardware wallets, phone wallets, Nostr clients) and paste in any git repo you want it to watch. It will tell you what it *couldn't* see, too.

- On Umbrel and StartOS, it will cover what it can see without admin rights. Until open questions 1 and 2 are answered, the fallback is "you run, it reads": Guard Dog shows you one command to run yourself, and reads the output you hand it. It will never take the StartOS admin key.
- Guard Dog will run with as few permissions as possible, under its own user, from day one.

**It tells you when something becomes dangerous.** It will match what you run against security advisories, including conditions like "only if this port is open to the internet". Alerts will come by Nostr DM, ntfy or email: critical ones right away, everything else in a weekly digest, each with plain-English steps to fix it. There will be a read-only local status page. Within 10 minutes of starting the install, you should get a plain-English report: what it found, which versions you run, what it couldn't see, and a real finding if one applies.

- For projects that don't publish structured advisories, every service will at least get a "you're behind the latest release" check.

**It sees what an attacker sees.** Open ports and your firewall, router port mappings (UPnP, NAT-PMP), tunnels, Tor and reverse proxies, and an outside-in probe from a paired Guard Dog. **Scout**, our own network discovery, will recognize Bitcoin and Nostr services anywhere on your home network. Only a tiny Scout helper will hold the one network permission it needs, never the main program.

## Later

- **Will: trust.** Guard Dog will check that the software you run matches the signed releases, and will recommend the *safest* version, not just the latest: signed, matching the published hashes, past a cooling-off period, with no known advisories. It will show how well each service's releases can be verified, and say plainly when there's no signature to check. Guard Dog will check itself, and its own releases will be reproducible and signed by more than one person.
- **Will: Scout spots network attacks.** Detecting things like ARP spoofing, rogue DHCP and changed DNS on your home network.
- **Could: the pack.** Trusted friends' Guard Dogs could watch each other's back: heartbeats, probing each other from the outside, and sharing hints that every member re-checks.
- **Will: a signed advisory feed over Nostr.** Advisories will be published as signed Nostr events in the open OSV format (a standard way to publish vulnerability data), and you choose whose signatures to trust. If the feed ever goes quiet, Guard Dog still checks each service's own release notes and advisories directly, as far as those sources allow, and tells you when it can't. A Nostr NIP draft for the format will be posted publicly.
- **Will: optional AI.** Plain-English explanations, spotting silent security fixes in changelogs, and answering "am I safe?" about your own setup. Everything important will keep working with no AI at all. Every AI feature must work with a small model on your own hardware, with no network at all. It can also use any OpenAI-compatible endpoint you choose, but that's never required. The part that reads outside text can only pick from fixed answers; it can never take an action.
- **Will: watch-only and tripwires.** Alerts on spends from your xpubs you didn't plan, changes to your npub you didn't make, and unexpected Lightning channel closes. Decoy wallets and keys that tell you if someone's been in. A check that warns you when key material looks like it's stored or backed up in plain text: it points at the file without copying, logging or sending what it finds, and you can turn it off.
- **Will: one-tap fixes and a full web UI.** Fixes come from a fixed, hand-written menu, each with a dry run, and nothing happens without your explicit approval, which no script can fake. **Could:** Signal and Telegram alerts, and themes.
- **Will: the lab and white-hat pentests.** Clone your setup into an isolated regtest lab and test it there, never against mainnet, never against anyone else's machine.
- **Will:** a third-party audit before 1.0. **Could:** Umbrel and StartOS store apps (once the platforms offer a read-only way to see other apps), a desktop app, phone apps for alerts and approvals (never a remote control for your node), and a ready-to-flash image for a small home box.

## What won't change

Whatever the roadmap turns into, Guard Dog will never hold your keys or move your funds, never send your setup's details anywhere you didn't choose, never change anything without your approval, never scan anybody else's machines, and never tell you you're "secure". It says "no known issues found", with when it checked and what it couldn't see.

## Open questions where I'd love help

These are real questions I don't have good answers to yet. If you know something, please open an issue with the question as the title. Even "here's how I do it on my box" helps a lot.

1. **Umbrel: reading installed apps without admin.** What's the least-privileged way to list which apps and versions are installed on umbrelOS? Does a service installed on the host (outside the app store) survive umbrelOS updates?
2. **StartOS: a read-only listing.** On StartOS 0.4, is there any way to list installed packages and versions without the admin key? If you're a StartOS user, would the "run this one command and paste the output" flow work for you?
3. **Which services should be "understood" first?** Recognizing a service and its version is the baseline. Which services' *configuration* mistakes worry you most (open admin panels, weak authentication, dangerous defaults), and how would you check for them?
4. **Where do security fixes actually get announced?** For the services you run, how do you normally hear about a security fix: GitHub advisories, release notes, a mailing list, a Nostr account, nowhere? Please describe the pattern, not a named project's unpublished problem. Anything sensitive goes to that project's security contact first (see [SECURITY.md](SECURITY.md)).
5. **What does "verified release" mean for each service?** Who signs the releases, with which keys, how many signatures should we expect, and where are the hashes published? If you maintain or package one of these services, I'd love your take.
6. **How long should the cooling-off period be?** Before a new release counts as "safest", how long should Guard Dog wait? 7 days is my starting point. Should it differ for money-holding services, or for an actively exploited bug?
7. **The on-device changelog reader.** A small local model will label changelog lines as "possible security fix, unconfirmed". How many false alarms would you put up with before you'd turn it off? Do you know real examples of silent security fixes we could use to test it?
8. **The advisory feed's Nostr format.** If you run a relay or build a Nostr client, what would you want from a signed-advisory event kind? What would make it easy for other tools (node platforms, wallets) to use the same feed?

## How to suggest a change

- **Open an issue.** Say what you'd add, cut or move, and why it matters to someone running their own node, relay or mint. [CONTRIBUTING.md](CONTRIBUTING.md) has the ground rules: no real secrets in issues, one change per pull request, and open an issue before a big piece of work.
- **Security problems never go in a public issue.** If your suggestion involves a vulnerability, in Guard Dog or in something it watches, follow [SECURITY.md](SECURITY.md).

This roadmap changes as we learn. When we finish something or change our minds, I'll update it here.
