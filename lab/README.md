# The regtest lab

A throwaway copy of a small Bitcoin and Nostr setup, for testing Guard Dog against real software without touching anyone's real node or money. It runs on **regtest only**: a private test chain where coins are made on demand and are worth nothing.

```bash
lab/up.sh     # start from cold, fund and open a Lightning channel, print a summary
lab/down.sh   # remove everything: containers, network, volumes, lab/.data
```

You need Docker with Compose v2, `jq` and `openssl`. Run one lab at a time; `up.sh` refuses to start a second one.

## What `up.sh` does

1. Makes fresh throwaway regtest passwords in `lab/.data/lab.env` (readable only by you, never committed, never printed). Each one starts with `gdlabcanary-`, so a leak is easy to search for.
2. Starts the five services below and waits until each one's health check passes.
3. Asks bitcoind, LND and Core Lightning which chain they're on. If any of them says anything but `regtest`, it removes the lab and stops (exit 3).
4. Mines 101 blocks, sends 1 BTC each to LND and Core Lightning, and opens a 1,000,000 sat channel from LND to Core Lightning. It waits until both sides say the channel is active.
5. Proves the least-privileged logins Guard Dog will use, and saves them in `lab/.data/creds/`. Each must read the version, and each must be refused a wider call:
   - bitcoind: user `gdwatch`, limited to `getnetworkinfo` and `getblockchaininfo`
   - LND: a macaroon baked with only `info:read`
   - Core Lightning: a rune limited to `getinfo`
6. Reads each service's version from the service itself and checks it against the version its pinned image is labelled with.
7. Writes `lab/.data/manifest.toml` in Judge A's format: the services and versions that are really there.
8. Prints a summary. If the whole start takes over 5 minutes, that counts as a failure (exit 4). If any other step fails, the lab is left running so you can look; `lab/down.sh` cleans up.

## The services

Every image is pinned by its multi-arch digest, which covers linux/amd64 for CI and linux/arm64 for Apple Silicon. Each one was the newest release at least 14 days old on 2026-11-16.

| Service | Software | Version | Image | Publisher | License |
|---|---|---|---|---|---|
| `bitcoind` | Bitcoin Core | 32.1 | `bitcoin/bitcoin@sha256:d2454aaf2ff4ce1ebbc49f4aa05ed044c907b849a80a3f4c0ad23e488e50bbe0` | Built by [willcl-ark/bitcoin-core-docker](https://github.com/willcl-ark/bitcoin-core-docker). Unofficial and meant for testing; Bitcoin Core publishes no image | MIT |
| `lnd` | LND | 0.21.6-beta | `lightninglabs/lnd@sha256:54b3c87ad0bc3fea3fab8af23ace6421147ea97e6b56bf3911592d7853c185b8` | Lightning Labs (official) | MIT |
| `cln` | Core Lightning | 26.06.9 | `elementsproject/lightningd@sha256:de74289ddcccb68cd60543b08b2b8594002d819125d200492e17a95166d56577` | ElementsProject / Blockstream (official) | BSD-MIT |
| `strfry` | strfry (Nostr relay) | 1.1.2-148-g4cd3cf6 | `ghcr.io/hoytech/strfry@sha256:36f1886d185a88ca57c66ebe52e6e9e8428dac2486eea0a5d50ff934f18b60c3` | Doug Hoyte (official) | GPL-3.0 |
| `nutshell` | Cashu Nutshell (ecash mint) | 0.21.0 | `cashubtc/nutshell@sha256:beed25e291357368e35e1698bf2e4645d97ed435232a8f8ff6501c77d67c0b90` | cashubtc (official) | MIT |

strfry is GPL-3.0. The lab only runs strfry's own upstream image as a separate test container, the same way Guard Dog's users run it. Guard Dog never ships, links or redistributes it. Guard Dog's own code stays permissive (`cargo deny`).

The mint uses Nutshell's `FakeWallet` backend: it has no real Lightning connection, so it can't pay or be paid.

## How it's locked down

- **Isolated:** one internal Docker network (`172.29.208.0/24`) with no route out, not even to the internet. No port is published on your machine; `up.sh` works through `docker compose exec`.
- **Nothing on disk:** no host folders, no Docker socket, no volumes. All data lives in memory (tmpfs) and is gone when a container stops.
- **Every container:** a read-only root filesystem, all Linux capabilities dropped, `no-new-privileges`, a non-root user, and limits on memory, swap, CPU and processes.
- **Memory:** limits add up to 1,920 MiB, under the 4 GiB budget for running the lab next to a Rust build. In practice the lab peaks at about 450 MiB.

`crates/gd-core/tests/lab_compose.rs` checks all of this in every `cargo test`, and proves its checks catch 21 kinds of unsafe change.

## Changing an image

1. Pick the newest release that's at least 14 days old.
2. Read its index digest with `docker buildx imagetools inspect <image>:<tag>`. Make sure it lists both linux/amd64 and linux/arm64.
3. Update the digest and the `org.guard-dog.lab.expected-version` label in `compose.yml`, the table above, and the expected list in `crates/gd-core/tests/lab_compose.rs`.
4. Run `cargo test --locked`, then `lab/up.sh` and `lab/down.sh`.

## Growing the lab later

Each new service in the catalog adds itself here in Phase 1.4. Two existing projects are candidates to borrow from. They're for ideas only until someone checks the licenses of the images they pull:

| Project | What it is | License | Latest release seen |
|---|---|---|---|
| [Polar](https://github.com/jamaljsr/polar) | A desktop app that builds regtest Lightning networks (LND, Core Lightning, Eclair, Taproot Assets, litd) with a GUI | MIT | v4.0.0 (2026-01-06) |
| [Nigiri](https://github.com/vulpemventures/nigiri) | A command-line tool that runs bitcoind, electrs, Esplora and Liquid on regtest, with an optional LND and Core Lightning | MIT | v0.5.17 (2026-05-13) |

Polar suits trying many Lightning node types by hand. Nigiri suits adding an Electrum server and a block explorer. Neither replaces this lab: both publish ports on your machine, and how they pin their images would need checking first.
