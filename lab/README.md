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
5. Proves the least-privileged logins Guard Dog will use, and saves them (the LND macaroon and the Core Lightning rune go in `lab/.data/creds/`; the bitcoind `gdwatch` login stays in `lab/.data/lab.env`). Each must read the version, and each must be refused a wider call:
   - bitcoind: user `gdwatch`, limited to `getnetworkinfo` and `getblockchaininfo`
   - LND: a macaroon baked with only `info:read`
   - Core Lightning: a rune limited to `getinfo`
6. Proves each service can be told apart over the lab network, and records what it says (the REST ports and the probe are explained below). Each of these is a hard failure with a plain message if it goes wrong:
   - bitcoind, with no login: an unauthenticated JSON-RPC call must get `401` with `WWW-Authenticate: Basic realm="jsonrpc"`.
   - LND and Core Lightning's `clnrest` certificates are copied (certificates only, never keys; mode 0600) into `lab/.data/creds/`. The probe pins each server by the public key of its certificate, and a wrong pin must be refused.
   - LND with no macaroon: `GET /v1/state` returns a state.
   - LND with the `info:read` macaroon: `GET /v2/versioner/version` returns the manifest's version, and `GET /v1/balance/blockchain` is refused with a permission error.
   - `clnrest` with the rune: `POST /v1/getinfo` returns the manifest's version, and `POST /v1/listfunds` is refused.
   - The raw replies to the version calls (bitcoind `getnetworkinfo` and `getblockchaininfo`, LND `/v1/state` and `/v2/versioner/version`, `clnrest` `getinfo`, Nutshell `GET /v1/info`, strfry's NIP-11 page) are saved unchanged in `lab/.data/replies/<service>/<call>.json`. If one holds a credential or a `gdlabcanary-` value, the run fails instead of saving it. `fixtures/lab-recorded/replies/` holds a recorded copy (`fixtures/README.md`).
7. Reads each service's version from the service itself and checks it against the version its pinned image is labelled with.
8. Writes `lab/.data/manifest.toml` in Judge A's format: the services and versions that are really there, plus the containers' arch, block storage and exposure, read-only from `docker inspect`.
9. Prints a summary. If the whole start takes over 5 minutes, that counts as a failure (exit 4). If a step fails before all three chain checks pass, or you press Ctrl-C before all three chain checks pass, the lab removes itself. A later failure leaves the lab running so you can look; `lab/down.sh` cleans up. `lab/up.sh` and `lab/down.sh` share a lock (`lab/.lock`, which names the process holding it), so two can never run at once. A lock is never taken over automatically, even one left by a crash: once you have checked that no lab script is running, `lab/down.sh --unlock` removes it. Both scripts share `lab/lib.sh` for the lock and the teardown.

## The services

Every image is pinned by its multi-arch digest, which covers linux/amd64 for CI and linux/arm64 for Apple Silicon. Each one was the newest release at least 14 days old on 2026-11-16.

| Service | Software | Version | Image | Publisher | License |
|---|---|---|---|---|---|
| `bitcoind` | Bitcoin Core | 32.1 | `bitcoin/bitcoin@sha256:d2454aaf2ff4ce1ebbc49f4aa05ed044c907b849a80a3f4c0ad23e488e50bbe0` | Built by [willcl-ark/bitcoin-core-docker](https://github.com/willcl-ark/bitcoin-core-docker). Unofficial and meant for testing; Bitcoin Core publishes no image | MIT |
| `lnd` | LND | 0.21.6-beta | `lightninglabs/lnd@sha256:54b3c87ad0bc3fea3fab8af23ace6421147ea97e6b56bf3911592d7853c185b8` | Lightning Labs (official) | MIT |
| `cln` | Core Lightning | 26.06.9 | `elementsproject/lightningd@sha256:de74289ddcccb68cd60543b08b2b8594002d819125d200492e17a95166d56577` | ElementsProject / Blockstream (official) | BSD-MIT |
| `strfry` | strfry (Nostr relay) | 1.1.2-148-g4cd3cf6 | `ghcr.io/hoytech/strfry@sha256:36f1886d185a88ca57c66ebe52e6e9e8428dac2486eea0a5d50ff934f18b60c3` | Doug Hoyte (official) | GPL-3.0 |
| `nutshell` | Cashu Nutshell (ecash mint) | 0.21.0 | `cashubtc/nutshell@sha256:beed25e291357368e35e1698bf2e4645d97ed435232a8f8ff6501c77d67c0b90` | cashubtc (official) | MIT |

Two more services are tools, not part of the lab. `up.sh` never starts them on its own; each sits behind a compose profile and follows every rule below:

| Service | What | Profile | Image |
|---|---|---|---|
| `probe` | curl, for talking to the services over the lab network. Image: `curlimages/curl` 8.23.0, released 2026-10-28 (curl project, official; curl licence, MIT-like) | `probe` | `curlimages/curl@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93` |
| `scanner` | Guard Dog itself, built from `lab/scanner/Dockerfile`, with an in-memory 1 MiB `/state` | `scan` | built locally, tagged `gd-lab-scanner:local` |

The probe never gets a credential on its command line: `up.sh` pipes headers to curl on stdin (`curl -H @-`), so nothing shows in `ps` or `docker logs`.

LND's REST port (8080) and Core Lightning's `clnrest` (3010) are open on the lab network only. Both use their own self-signed certificates. No port is published.

strfry is GPL-3.0. The lab only runs strfry's own upstream image as a separate test container, the same way Guard Dog's users run it. Guard Dog never ships, links or redistributes it. Guard Dog's own code stays permissive (`cargo deny`).

The mint uses Nutshell's `FakeWallet` backend: it has no real Lightning connection, so it can't pay or be paid.

## How it's locked down

- **Isolated:** one internal Docker network (`172.29.208.0/24`) with no route out, not even to the internet, and in `isolated` bridge mode so the lab has no address on your machine to reach. No port is published on your machine; `up.sh` works through `docker compose exec`.
- **Nothing on disk:** no host folders, no Docker socket, no volumes. All data lives in memory (tmpfs) and is gone when a container stops.
- **Every container:** a read-only root filesystem, all Linux capabilities dropped, `no-new-privileges`, a non-root user, and limits on memory, swap, CPU and processes.
- **Memory:** limits add up to 1,920 MiB for the five services and 192 MiB more for the two tools (2,112 MiB in all), under the 4 GiB budget for running the lab next to a Rust build. In practice the lab peaks at about 450 MiB.

`crates/gd-core/tests/lab_compose.rs` checks all of this in every `cargo test`, and proves its checks catch 60 kinds of unsafe change.

## The scanner image

The scanner is built from whatever `guard-dog` is in your checkout. The Dockerfile has two stages, both pinned by digest: the official `rust` image at the version in `rust-toolchain.toml` builds it with `cargo build --locked --release -p guard-dog`, and a `distroless` runtime image (no shell) receives only the binary. `.dockerignore` keeps `target/`, `lab/.data/`, `.claude/`, `.git/` and `fixtures/private-setups/` out of the build. It is built once and kept under the tag `gd-lab-scanner:local`; running it does not rebuild it.

```bash
# build, or rebuild after you change the Rust code (takes a few minutes)
# (from the repository root)
docker build -f lab/scanner/Dockerfile -t gd-lab-scanner:local .
# run it inside the lab network (the lab must be up)
docker compose -p gd-lab -f lab/compose.yml --env-file lab/.data/lab.env --profile scan run --rm scanner --version
```

## Changing an image

1. Pick the newest release that's at least 14 days old.
2. Read its index digest with `docker buildx imagetools inspect <image>:<tag>`. Make sure it lists both linux/amd64 and linux/arm64.
3. Update the digest and the `org.guard-dog.lab.expected-version` label in `compose.yml`, the table above, and the expected list in `crates/gd-core/tests/lab_compose.rs`. (The probe has no version label; its digest sits in `TOOLS` there. The two build-stage and runtime digests in `lab/scanner/Dockerfile` are changed the same way, checked by the same test.)
4. Run `cargo test --locked -p gd-core --test lab_compose` before starting anything, so the isolation checks pass first.
5. Run `lab/up.sh`, copy `lab/.data/manifest.toml` over `fixtures/lab-recorded/manifest.toml` as it is (versions and image references only, no credentials) and `lab/.data/replies/` over `fixtures/lab-recorded/replies/` (after searching it for `gdlabcanary-`, the macaroon, the rune and home paths), and update the `lab-regtest` versions in `fixtures/expected-matches.toml`. Run `GD_LAB=1 cargo test --locked` while the lab is up, so the recorded and the live manifest are both compared, then `lab/down.sh`.

## Growing the lab later

Each new service in the catalog adds itself here in Phase 1.4. Two existing projects are candidates to borrow from. They're for ideas only until someone checks the licenses of the images they pull:

| Project | What it is | License | Latest release seen |
|---|---|---|---|
| [Polar](https://github.com/jamaljsr/polar) | A desktop app that builds regtest Lightning networks (LND, Core Lightning, Eclair, Taproot Assets, litd) with a GUI | MIT | v4.0.0 (2026-01-06) |
| [Nigiri](https://github.com/vulpemventures/nigiri) | A command-line tool that runs bitcoind, electrs, Esplora and Liquid on regtest, with an optional LND and Core Lightning | MIT | v0.5.17 (2026-05-13) |

Polar suits trying many Lightning node types by hand. Nigiri suits adding an Electrum server and a block explorer. Neither replaces this lab: both publish ports on your machine, and how they pin their images would need checking first.
