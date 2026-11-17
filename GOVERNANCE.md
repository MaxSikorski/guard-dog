# How Guard Dog is run

Guard Dog is pre-alpha, so this is short and honest about where things stand. It will grow as the project does.

## Who decides today

Guard Dog has one maintainer: me, Max Sikorski ([@MaxSikorski](https://github.com/MaxSikorski)). I set the direction, review and merge pull requests, and sign releases. That's a single point of failure, and I know it. The sections below say how I plan to change that.

I build Guard Dog with AI coding agents under a strict review process. Agents draft, test and open pull requests; I decide what merges into the sensitive parts, and every release is signed by my own hand and key.

## How decisions are made

- **In the open.** Direction lives in the [roadmap](ROADMAP.md). Proposals start as an issue or in [Discussions](https://github.com/MaxSikorski/guard-dog/discussions), and the reasons for a decision are written down there.
- **By evidence.** Where a change can be measured, the judges decide, not opinions: a change that makes a judge's score go down doesn't merge until we understand why. See [How we know it works](README.md#how-we-know-it-works).
- **Within fixed lines.** Some things are not up for a vote: Guard Dog never holds keys or moves funds, never sends a setup's details anywhere the user didn't choose, never changes a system without the user's approval, never scans machines the user doesn't own, and never tells anyone they're "secure".
- **Rough consensus, then the maintainer.** I'd rather persuade than overrule. When we can't agree, I make the call and say why.

## How changes are reviewed

Every pull request needs the full test gate in CI (the `merge-gate` check) to pass before it can merge, and merges keep a merge commit so history shows what was reviewed.

**Sensitive paths** are the parts that could weaken the gate itself or the safety of people's machines:

- CI and repository configuration (`.github/`)
- the dependency policy (`deny.toml`) and the pinned toolchain (`rust-toolchain.toml`)
- build scripts (`build.rs`)
- release, build and signing scripts
- privilege and install setup

A pull request touching any of these is labelled `security-sensitive-path`, never merges automatically, and waits for my explicit review. A pull request runs its own edited CI, so a change to the gate could otherwise grade itself.

## How to become a reviewer

There are no other reviewers yet, and I'd love to change that. The path I have in mind:

1. Contribute a few pull requests that merge, and review others' pull requests in the open. A good review says what you checked and how, the way Bitcoin Core reviewers write "ACK" with what they tested.
2. Once your reviews are consistently careful, I'll ask you to become a **reviewer**: your approval counts toward merging in the areas you know.
3. Later, trusted reviewers can become **maintainers** for an area, and a second release signer, so Guard Dog's releases can be signed by more than one person.

Reviewers and maintainers will be listed in this file, with the areas they cover. Anyone can step back at any time.

## Changing this document

Changes to this file go through a normal pull request, open for at least a week so people can comment.
