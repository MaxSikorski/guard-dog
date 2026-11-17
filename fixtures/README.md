# Fixtures

Test material the judges read. Nothing here is live: no network, no Docker.

## Expected advisory matches (Judge B)

`expected-matches.toml` says what a correct matcher must report for every setup listed in it and every advisory in `advisories/corpus/`. It was written by hand from each advisory's OSV ranges and its `database_specific.guard_dog.conditions`, before any matcher exists.

- **`[[product]]`**: one per catalog id, with its other names (`aliases`, for example `cashu-nutshell-mint` for `nutshell`) and its OSV packages as `<ecosystem> <name>`. Every `service` named in an advisory's conditions must be a product id or alias.
- **`[[setup]]`**: one per judged setup, with its platform, chain, exposure, `arch` and `block_storage`.
  - `lab-regtest` (`source = "lab"`): its services and versions must equal the pinned image labels in `lab/compose.yml`, which `lab/up.sh` checks the running services against. Its `[[setup.package]]` entries record the xz and liblzma versions read from each pinned image (`packages_from` says how).
  - `lab-old-synthetic` (`source = "synthetic"`): **not a recording.** It's the lab's configuration with older, affected versions, so that affected results are tested before an old setup has been recorded.
- **`[[expect]]`**: one per setup and advisory, sorted by setup then advisory. Each entry makes two separate calls, and the result follows from them:
  - `version`: `in-range`, `out-of-range`, `unknown`, or `not-applicable` (no product in the setup has any of the advisory's packages). Only `affected[]` entries that apply count: an entry with `database_specific.platform` applies only on that platform. For example, Bitcoin Core's unfixed 32-bit-or-FAT32 entry doesn't apply to a 64-bit setup with its blocks on tmpfs.
  - `condition`: are the advisory's required conditions `met`, `not-met` or `unknown`? Conditions marked `required = false` are exposure factors and never decide the result.
  - `result`:
    - `not-affected` if the version is out of range or a required condition is not met;
    - `affected` if the version is in range and every required condition is met;
    - otherwise `possibly-affected`, with a `question` that would settle it.
  - `reason`: one line citing the range or condition that decides it.
  - `review = "max"`: the call wasn't clear-cut, so Max or a tester should check it.

`crates/gd-core/tests/expected_matches.rs` refuses a file that has any of these problems:

- a missing or doubled pair, or an unknown advisory, setup or product;
- a result that doesn't follow from its two calls;
- a version call with no matching package, or `not-applicable` for a product that is present;
- a possibly-affected pair without a question;
- a lab version that differs from `lab/compose.yml`;
- an unlabelled synthetic setup.

The test also scores a matcher against the file; see `tests/README.md`. The matcher sees only the setup and advisory ids, never the expected result.

Never loosen an expected result to make the matcher pass without a written reason in the PR and in this file's history. A new setup gets one `[[setup]]` and one `[[expect]]` per advisory, and its id goes into `SETUPS` in the test.

## The lab as recorded (two back ends)

`lab-recorded/manifest.toml` is the manifest a real `lab/up.sh` run wrote on 2026-11-16 (Mac, arm64), committed exactly as it came out: the chain, each service's id and the version the running service reported, plus comments naming the reply and the pinned image. No credentials. `crates/gd-core/tests/two_backends.rs` checks that Judge B sees the same facts through it as through the `lab-regtest` setup above, and that its `# image` lines are the images `lab/compose.yml` pins. Re-record it whenever a lab image changes (`lab/README.md`, "Changing an image").

## Recorded and curated data

Recorded and curated data the judges read.

- `injection/`: hostile text for Judge D. See its own README.
- `setups/`: recordings of real setups for Judge A. One folder per setup.

Synthetic data lives in `tests/synthetic/`, never here.

## The recording format (format 2)

One folder per setup, `fixtures/setups/<name>/`, where `<name>` is lower-case words joined by dashes. Only these files may be in it, hidden files included. The judge rejects anything else, so an unexpected, possibly unredacted file can't slip in.

A recording is a **field extract**, not a copy. The recorder keeps only named fields that pass a type check, and drops everything else (the log says how many were dropped, never what). That set of fields is the contract Guard Dog's sensors read: a sensor may use only what the recorder keeps.

| Path | Where it comes from | Platforms |
|---|---|---|
| `manifest.toml` | Written by hand: the truth about the setup. Never made from the recorded files. | all |
| `record-log.txt` | Written by `tools/record-setup.sh` | all |
| `systemctl-list-units.txt` | `systemctl list-units --type=service --all --no-pager --plain --no-legend` | RaspiBlitz, myNode, plain systemd, nix-bitcoin |
| `dpkg-query.txt` | `dpkg-query -W` with package, version and status | Debian family |
| `ss-tlnp.txt`, `ss-ulnp.txt` | `ss -tlnp` and `ss -ulnp` | Linux |
| `torrc` | `/etc/tor/torrc` | where present |
| `binaries-version.txt` | `--version` of a fixed list of root-owned programs | RaspiBlitz, plain systemd |
| `raspiblitz-version.txt` | the `codeVersion` and `codeRelease` lines of `_version.info` | RaspiBlitz |
| `raspiblitz-conf.txt` | only the on/off switches and three named keys of `raspiblitz.conf` | RaspiBlitz |
| `raspiblitz-info.txt` | six named keys of `raspiblitz.info` | RaspiBlitz |
| `docker-version.json`, `docker-ps.json`, `docker-images.json` | the Docker engine's three list endpoints | Docker, Umbrel, lab |
| `apps/<app-id>/umbrel-app.yml` | the Umbrel app manifest | Umbrel |
| `apps/<app-id>/<file>.json` | myNode's app JSON files | myNode |
| `replies/<service>/<call>.json` | replies you captured yourself; `<call>` is one of `getnetworkinfo`, `getinfo`, `getversion`, `nip11`, `nut06`, `server-version` | all |

A file that is absent was not collected (the log says why). A file that is empty was collected and held nothing. Files are the exact bytes the machine gave, after redaction only.

### What each file keeps

| File | Kept | Never kept |
|---|---|---|
| `docker-ps.json` | container names, image, image id, state, status, ports (address, port numbers, type), a short list of label keys (Compose project and service, image version, revision, source, title) | commands, environments, mounts, every other label, networks |
| `docker-images.json` | id, tags, digests, the same label keys | everything else |
| `docker-version.json` | version, API version, OS, architecture, kernel, git commit, component names and versions | everything else |
| `systemctl-list-units.txt` | unit name (an `@instance` that isn't a plain word becomes `instance`), load, active, sub state | the description |
| `dpkg-query.txt` | package, version, status | |
| `ss-tlnp.txt`, `ss-ulnp.txt` | state, queues, addresses and ports, process name, pid, fd | |
| `torrc` | port, bridge-use and cookie-switch directives; for `HiddenServiceDir` only the last folder name | `HashedControlPassword`, `Bridge` lines, data and log folders |
| `binaries-version.txt` | the program path and at most three version lines | |
| `replies/*/getnetworkinfo.json` | version, protocol, sub-version, networks | the node's own addresses |
| `replies/*/getinfo.json` (LND, Core Lightning) | version, commit, chains, network, sync state | alias, colour, node key, addresses, block hash, features |
| `replies/*/nip11.json` | software (only a reviewed public source such as `github.com/hoytech/strfry`; any other value becomes `software-N`), version, supported NIPs | name, description, contact, owner key, icons, links |
| `replies/*/nut06.json` | version | name, keys, description, message of the day, contact, URLs |
| `apps/*/umbrel-app.yml` | `manifestVersion`, `id`, `name`, `version`, `category`, `port`, dependency names | passwords, descriptions, release notes, anything else |

Private identifiers are replaced by field: image registries and repositories, container names, compose and label values, unit instance names, package and process names and a service or app folder name all become `image-N`, `container-N`, `label-N`, `instance-N`, `package-N`, `process-N` and `service-N` unless they are on the recorder's reviewed list of public software. A tag of a public repository stays only when it is version-shaped (`v0.19.2-beta`, `latest`), a unit name that is not on the public list is replaced whole (a key in it too), myNode's `name` and `short_name` stay only when they are public product names, an Umbrel app's `id` gets the same `app-N` as its folder, and its `name:` stays only for a public app (otherwise `name-N`). A run of 12 or more words of 3 to 8 letters, joined by white space, commas or 1 to 3 other characters (`-`, `_`, `:`, `.`, `/`, `|`, any mix) or numbered (`1. word 2) word`), is a seed phrase and is replaced whole, also when it is split across values of one JSON file. A tag, an OCI `version`/`revision` label, an Umbrel `version:` and a dpkg version stay only as far as they are version-shaped (text after a version that is not build metadata is cut off), Umbrel's `category:` is one of its own categories or `category-other`, its `dependencies:` get the same `app-N` as a folder of that name, and an `ss` interface name that the platform did not give becomes `iface-N`. Every removed password, token, bearer token or user-info URL counts as a secret (exit 3). Input that is dropped as a whole (a reply of the wrong shape, a systemd description, the folders above a Tor hidden-service folder) is still searched for key shapes: if one is found the run exits 3 and the log says `secret-shape-in-dropped-input <file>`, never the value. Placeholders never look like keys (`REDACTED-NSEC-1`). The output folder must be yours with mode 0700.

Layer two then replaces what is left that could identify you: addresses (kept in documentation ranges, with wildcard and loopback kept), container names, private image registries and any domain that isn't on a short list of well-known ones, host and user names.

`manifest.toml` is the truth the judge scores against:

```toml
format = 1
platform = "raspiblitz"          # umbrel | startos | raspiblitz | mynode | nix-bitcoin | docker | systemd
source = "maintainer"            # lab | maintainer | tester | synthetic
recorded = "2026-11-20"          # YYYY-MM-DD, a real date
recorder = "record-setup.sh format 2"
reviewed_by = "Max"              # who read every file before it was shared
description = "A RaspiBlitz 1.12 with bitcoind and LND, Tor only."

[[service]]
id = "bitcoin-core"              # lower-case words joined by dashes, unique in the setup
version = "29.1"                 # the upstream release, no leading "v", or "unknown"
evidence = ["binaries-version.txt", "replies/bitcoin-core/getnetworkinfo.json"]
```

Only these keys are allowed. `unknown` counts for finding the service, not for getting its version right.

## How to record (RaspiBlitz first)

1. Log in as `admin`. Don't use root.
2. Run `perl -v`. It must print a version. Every Debian and Raspberry Pi OS has Perl.
3. Copy `tools/record-setup.sh` to the box. The script restarts itself in a clean environment, but bash reads `BASH_ENV` before the script's first line, so run it as `env -i PATH=/usr/bin:/bin bash record-setup.sh ...`.
4. Capture replies with your own commands:
   - `bitcoin-cli getnetworkinfo > ~/gni.json`
   - `lncli version > ~/lnd-version.json` (or `lncli getinfo`)
   - `lightning-cli getinfo > ~/cln-getinfo.json`
5. Run it:
   ```bash
   env -i PATH=/usr/bin:/bin bash record-setup.sh --out ~/gd-recording \
     --reply bitcoin-core/getnetworkinfo=$HOME/gni.json \
     --reply lnd/getversion=$HOME/lnd-version.json
   ```
6. Read every file in `~/gd-recording`. Then delete the reply files.

A reply file must be the command's JSON output, exactly as it printed it. The script refuses anything that isn't JSON, and keeps only the fields in the table above.

Umbrel and plain Docker work the same way. The script asks the Docker socket (`/var/run/docker.sock`, or `--docker-socket PATH`) three list questions. For a relay, capture `curl -H 'Accept: application/nostr+json' http://127.0.0.1:7777/ > nip11.json`. For a Cashu mint, capture `curl http://127.0.0.1:3338/v1/info > nut06.json`. Pass them with `--reply strfry/nip11=nip11.json` and `--reply nutshell/nut06=nut06.json`.

`record-setup.sh --check-path PATH` says whether the script would read a path: `ok`, or `refused:` and the reason (a symlink in the path, a folder others can write to, a secret-looking name).

Add `--redact-term WORD` for any other word that identifies you (your node's alias, say). The script already redacts your host name and user name.

Exit codes:

- `0` done.
- `1` a problem with how you ran it (including a reply that isn't JSON) (a bad argument, an output folder that isn't empty, running as root, no Perl). Fix it and run again.
- `2` it refused a file that looks secret. Nothing was written.
- `3` done, but it found and removed a secret-shaped value (a key, seed words, a macaroon). Read the files with extra care, and find out why that value was in the input.
- `4` its own self-check failed, so it deleted the output. Run it again; if it keeps failing, report it privately (see `SECURITY.md`).

## What it never reads and never calls

- It never reads files named like seeds, mnemonics, macaroons, `nsec`, wallets, `.env` files, secrets, private keys, cookies, passwords, `rpcauth`, credentials, tokens, certificates and key stores, databases, backups, SSH keys, shadow files, onion service keys or `raspiblitz.setup`. It never follows symlinks and never reads a file over 1 MiB.
- It never runs `docker inspect`, `systemctl show` or `systemctl cat`, which can print secrets from environments and unit files. It never uses `sudo` and never changes anything.
- It reads `raspiblitz.conf` only through a filter that keeps the on/off switches and the `network`, `chain` and `lightning` lines. The file also holds mail and Dropbox passwords.

## Before a recording goes in the repository

1. Read every file.
2. Check the `kept-domain` lines in `record-log.txt`.
3. Search for your host name, IP addresses, onion address, node alias and public key.
4. Max approves it.

If the script prints `TEST MODE: tools from a test folder; this is not a valid recording`, that is the tests' own run and the output is not a recording; the judge rejects it. A recording from Max's own node is private: it stays in `fixtures/private-setups/`, which git ignores. Judge A scores it on his machine and never in CI.

## Platforms

| Platform | Recordings | Notes |
|---|---|---|
| RaspiBlitz | no recording yet | Max's node is the first (step 4) |
| Umbrel | no recording yet | Docker plus `umbrel-app.yml` |
| StartOS | no recording yet | needs an admin-equivalent key; not supported by the recorder yet |
| myNode | no recording yet | systemd plus app JSON |
| nix-bitcoin | no recording yet | archived since 2026-08-13 |
| Plain Docker or Compose | no recording yet | the lab (step 3) |
| Plain Linux with systemd | no recording yet | the lab (step 3) |

### Raw replies (`lab-recorded/replies/`)

The unchanged answers the services gave in a real `lab/up.sh` run, recorded on 2026-11-17 (Mac, arm64) from the images `lab/compose.yml` pins (the digests are in `lab-recorded/manifest.toml`). Each file is one reply body, saved as received; the run fails instead of saving a reply that holds a credential or a `gdlabcanary-` value. The names and addresses in them are the lab's own throwaway regtest values.

| File | Call that made it | Image |
|---|---|---|
| `bitcoind/getnetworkinfo.json` | JSON-RPC `getnetworkinfo` as the `gdwatch` login | `bitcoin/bitcoin@sha256:d2454aaf2ff4ce1ebbc49f4aa05ed044c907b849a80a3f4c0ad23e488e50bbe0` (Bitcoin Core 32.1) |
| `bitcoind/getblockchaininfo.json` | JSON-RPC `getblockchaininfo` as the `gdwatch` login | same |
| `lnd/state.json` | `GET https://lnd:8080/v1/state`, no macaroon | `lightninglabs/lnd@sha256:54b3c87ad0bc3fea3fab8af23ace6421147ea97e6b56bf3911592d7853c185b8` (LND 0.21.6-beta) |
| `lnd/versioner-version.json` | `GET https://lnd:8080/v2/versioner/version` with the `info:read` macaroon | same |
| `cln/getinfo.json` | `POST https://cln:3010/v1/getinfo` with the `getinfo` rune (clnrest answers `201`) | `elementsproject/lightningd@sha256:de74289ddcccb68cd60543b08b2b8594002d819125d200492e17a95166d56577` (Core Lightning 26.06.9) |
| `nutshell/info.json` | `GET http://nutshell:3338/v1/info` | `cashubtc/nutshell@sha256:beed25e291357368e35e1698bf2e4645d97ed435232a8f8ff6501c77d67c0b90` (Nutshell 0.21.0) |
| `strfry/nip11.json` | `GET http://strfry:7777/` with `Accept: application/nostr+json` | `ghcr.io/hoytech/strfry@sha256:36f1886d185a88ca57c66ebe52e6e9e8428dac2486eea0a5d50ff934f18b60c3` (strfry 1.1.2-148-g4cd3cf6) |

Re-record them with the manifest whenever a lab image changes (`lab/README.md`, "Changing an image").
