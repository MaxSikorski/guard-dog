# Judge C: egress capture

Judge C asks one question: does anything leave the box that shouldn't, including planted canary secrets? It reads three independent records of everything Guard Dog tried to send (the resolver log, the recorder's decrypted flows and the raw packet capture), and fails the run on any of these:

- a destination that isn't in `allowlist.toml` (F1)
- a planted canary or a secret-shaped value in any form: raw, hex, base64, base32, percent-encoded, split across packets, inside a DNS name (F2)
- a packet that fell into the black hole, meaning it tried to leave without being redirected (F3)
- a missing control: a judge that sees nothing must never pass (F4)
- a capture that can't be read, or sources that disagree with each other (F5)

The checker is `crates/gd-egress` (`gd-egress check`). Today it runs on **synthetic** captures only; the live lab that makes real captures arrives in the next piece.

## What is in this folder

| Path | What |
|---|---|
| `synthetic/` | 18 expected reports, one per scenario. **Synthetic: built by `crates/gd-egress/tests/support/mod.rs`, never a real capture.** Written before the checker existed. |
| `golden/canaries-seed-1.json` | The canaries made from seed 1, byte for byte. Pins the generator. |
| `expected-rules.txt` | The firewall and route dump the sealed box must have. **Provisional** until the lab arrives; the lab piece replaces it with the real, reviewed dump. |

Reports contain no counts, no times and never a canary (those print as `<canary:CLASS>`), so an expected file is the same for every seed.

## The 18 scenarios

| # | Scenario | What it proves |
|---|---|---|
| S01 | clean-baseline | Control only: PASS, no destinations |
| S02 | blind-mitm | The recorder's control request is missing: F4 |
| S03 | https-body-leak | An nsec in an HTTPS body to an unlisted host: F1 twice, F2 |
| S04 | dns-name-leak | A macaroon inside a DNS name: found in the log and on the wire, and the name prints redacted |
| S05 | raw-udp-leak | A seed phrase (comma-separated) in a UDP packet to the black hole: F2 and F3 |
| S06 | raw-tcp-split | An xpub split over three TCP segments, out of order, one resent: found after reassembly |
| S07 | ipv6-literal | A TCP SYN to an IPv6 address: F3 |
| S08 | base64-header | A macaroon in base64url inside a header, at a 2-byte offset: found |
| S09 | allowlisted-clean | An allowlisted host and port: PASS, 2 allowlisted |
| S10 | allowlisted-with-canary | A percent-encoded password to an allowlisted host: still F2 |
| S11 | sources-disagree | A handshake with no connect event: F5 |
| S12 | truncated-body | The recorder cut a body short: F5 |
| S13 | upstream-attempt | A packet to the sink address that was not redirected: F3 |
| S14 | opaque-tls | A TLS flow the recorder couldn't read (pinned): F1 |
| S15 | rules-differ | The live rules lack the owner line: F5 |
| S16 | lab-cred-shape | A lab-style credential this run didn't plant: caught by shape |
| S17 | unknown-event | An event the parser doesn't know: F5, never ignored |
| S18 | wrong-link-type | A capture of the wrong kind: F5, plus F4 because the wire is blind |

## Regenerating the golden file

Only when a reviewed change to the canary generator makes it differ:

```bash
cargo run --locked -q -p gd-egress -- canaries --seed 1 --out /tmp/gd-canaries-1
cp /tmp/gd-canaries-1/judge/canaries.json tests/egress/golden/canaries-seed-1.json
```

Then read the diff: every value is generated, and none is real.
