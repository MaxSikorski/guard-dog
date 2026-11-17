# Judge C: egress capture

Judge C asks one question: does anything leave the box that shouldn't, including planted canary secrets? It reads three independent records of everything Guard Dog tried to send (the resolver log, the recorder's decrypted flows and the raw packet capture), and fails the run on any of these:

- **F1** a destination that isn't in `allowlist.toml`, judged by the network layer: the name asked for, the address reached, the port and the TLS server name must all agree with one entry
- **F2** a planted canary or a secret-shaped value in any form from the decoding set, anywhere a byte could have gone
- **F3** a packet that fell into the black hole, meaning it tried to leave without being redirected
- **F4** a missing control: a judge that sees nothing must never pass
- **F5** a capture that can't be read, is incomplete, or disagrees with itself (gaps, lost tails, kernel drops, fragments, extra or cut-off DNS records, compressed bodies, a missing end marker)

The checker is `crates/gd-egress` (`gd-egress check`). Today it runs on **synthetic** captures only; the live lab that makes real captures arrives in the next piece.

## What Judge C proves, and what it doesn't

**The claim**, for one commit and one workload:

- every flow went to an allowlisted destination
- the capture is complete from a proven start (the control before the workload) to a proven end (the control after it, and the recorder's end marker)
- no planted canary appears in any captured byte under the decoding set, up to two nested layers: raw, lowercase, percent-escaped, JSON-escaped, separator-stripped and letters-only views; base64, base64url, base32 and hex tokens decoded two layers deep; IP addresses matched by value in dotted, integer, `0x` and IPv6 forms

**Not covered**, and caught or bounded by other layers instead:

- a build that deliberately obfuscates or encrypts its output, including a leak hidden in a dependency on purpose
- covert timing and size channels
- secrets inside end-to-end-encrypted payloads to allowed destinations (NIP-44, until Phase 5 gives the judge the test key)
- encodings outside the decoding set, or nested three or more deep

Those are the job of the never-have list and least privilege (threat model section 5), runtime allowlist enforcement (Phase 4.5), the supply-chain checks (`cargo deny`, the 14-day cooldown, `cargo audit`, review of new crates), reproducible builds with signed releases, and the review tiers.

**Compressed request bodies fail the judge** (`undecoded-content-encoding`). Decompression arrives in PR 1b, and is required before `allowlist.toml` gets its first entry.

## What the lab must supply

Besides the files in the capture directory layout, the judge needs `pcap/tcpdump.log`: tcpdump's own closing summary (`N packets captured`, `N packets received by filter`, `N packets dropped by kernel`). The lab piece (PR 2; its `netns.sh` is not in the repository yet) writes tcpdump's messages to `tcpdump.log`, stops tcpdump with SIGINT, waits for it to exit and keeps that file as `pcap/tcpdump.log`. A missing file, missing lines, any drop, or a packet count that differs from the pcap is F5. The recorder's addon should write a global `seq` number on every `http` and `tcp` event so requests on different connections can be put back in order (without it the line number is used).

## What is in this folder

| Path | What |
|---|---|
| `synthetic/` | 61 expected reports, one per scenario. **Synthetic: built by `crates/gd-egress/tests/support/mod.rs`, never a real capture.** Each was written before the code that makes it pass. |
| `golden/canaries-seed-1.json` | The canaries made from seed 1 (`canaries.json` format 2, with the raw bytes of each), byte for byte. Pins the generator. |
| `expected-rules.txt` | The firewall and route dump the sealed box must have. **Provisional** until the lab arrives; the lab piece replaces it with the real, reviewed dump. |

Reports contain no counts, no times and never a canary (those print as `<canary:CLASS>`), so an expected file is the same for every seed.

## The 61 scenarios

S01 to S18 are the first set; S19 to S61 each cover one review finding (O = Opus, C = Codex, then the second Codex round).

| # | Scenario | What it proves |
|---|---|---|
| S01 | clean-baseline | Control before and after: PASS, no destinations |
| S02 | blind-mitm | The recorder's control request is missing: F4 names the phase |
| S03 | https-body-leak | An nsec in an HTTPS body to an unlisted host: F1 twice, F2 |
| S04 | dns-name-leak | A macaroon inside a DNS name: found in the log and on the wire, and the name prints redacted |
| S05 | raw-udp-leak | A seed phrase (comma-separated) in a UDP packet to the black hole: F2 and F3 |
| S06 | raw-tcp-split | An xpub split over three TCP segments, out of order, one resent: found after reassembly |
| S07 | ipv6-literal | A TCP SYN to an IPv6 address: F3 |
| S08 | base64-header | A macaroon in base64url inside a header, at a 2-byte offset: found |
| S09 | allowlisted-clean | An allowlisted host reached the right way: PASS, 2 allowlisted |
| S10 | allowlisted-with-canary | A percent-encoded password to an allowlisted host: still F2 |
| S11 | sources-disagree | A handshake with no connect event: F5 |
| S12 | truncated-body | The recorder cut a body short: F5 |
| S13 | upstream-attempt | A packet to the sink address that was not redirected: F3 |
| S14 | opaque-tls | A TLS flow the recorder couldn't read (pinned): F1 |
| S15 | rules-differ | The live rules lack the owner line: F5 |
| S16 | lab-cred-shape | A lab-style credential this run didn't plant: caught by shape |
| S17 | unknown-event | An event the parser doesn't know: F5, never ignored |
| S18 | wrong-link-type | A capture of the wrong kind: F5, plus F4 for both phases |
| S19 | nsec-raw-hex | The 32 key bytes of an nsec in hex (O) |
| S20 | seed-entropy-base64 | The seed phrase's entropy in base64 (O) |
| S21 | xpub-chain-code-hex | An xpub's chain code in hex (O) |
| S22 | nsec-spaced | An nsec with a space every 4 characters (O) |
| S23 | macaroon-base64-wrapped | A macaroon in base64 wrapped at 76 characters (O) |
| S24 | rpc-newline-split | A password with a line break every 10 characters (O) |
| S25 | sni-mismatch | The TLS name differs from the HTTP host (O, C) |
| S26 | port-mismatch | The original port differs from the authority port (O, C) |
| S27 | ip-literal | The request reached an address that isn't the fake-DNS answer (O) |
| S28 | no-dns-question | A listed host that was never asked about in DNS |
| S29 | pcap-cut-before-post | A packet capture cut before the post control: F4, F5 (O) |
| S30 | redact-seed-window | A seed-phrase window in a DNS name prints as `<canary:seed-phrase>` (O) |
| S31 | redact-percent-host | A percent-encoded password in a host prints as `<canary:rpc-password>` (O) |
| S32 | xprv-full-alphabet | An xprv shape with `i` and `o` in it (O) |
| S33 | tcp-events-split | A secret split over two TCP events (O) |
| S34 | control-conn-extra-request | A second request on the control connection is judged (O, C) |
| S35 | ipv4-fragment | An IPv4 fragment fails closed (O) |
| S36 | control-handshake-only | A control with a handshake but no payload (C) |
| S37 | unanswered-wire-question | A DNS question the resolver never logged (C) |
| S38 | nsec-as-method | A secret in the HTTP method (C) |
| S39 | nsec-json-u-escaped | An nsec written as JSON `\u00XX` escapes (C) |
| S40 | gzip-body | A compressed body fails closed until PR 1b (C) |
| S41 | dns-txt-additional | A DNS query with an extra record fails closed (C) |
| S42 | tcp-dns-short-frame | A DNS-over-TCP frame that runs past the stream (C) |
| S43 | dns-short-header | A DNS datagram shorter than a header (C) |
| S44 | ipv4-base64-offset | An IPv4 address in base64 behind one byte (C) |
| S45 | ipv4-near-miss | A neighbouring address, in base32 and base64, is not a hit (C) |
| S46 | ipv4-integer | An IPv4 address as a decimal integer (C) |
| S47 | ipv4-hex | An IPv4 address as `0x` and hex (C) |
| S48 | ipv6-embedded-ipv4 | An IPv6 address with a dotted-quad tail (C) |
| S49 | nsec-split-across-requests | An nsec in seven small bodies over two connections (C) |
| S50 | tcp-gap | A hole in the TCP sequence numbers (C) |
| S51 | tcp-overlap-conflict | A retransmission with different bytes: both are scanned (C) |
| S52 | lo-duplicate-outgoing | Outgoing copies of loopback records are ignored |
| S53 | workload-before-pre | A workload connection numbered before the pre control: F5 |
| S54 | mitm-no-end | The recorder's end marker is missing: F5 |
| S55 | control-ciphertext-lost | The control's handshake is captured but its request bytes are not, though the server acknowledged them: F4, F5 |
| S56 | kernel-drops | tcpdump says the kernel dropped a packet: F5 |
| S57 | nsec-double-percent | An nsec percent-encoded twice |
| S58 | hex-colon-pairs | An nsec's bytes in hex with a colon between pairs |
| S59 | ipv4-split-bodies | An IPv4 address split over four requests on two connections |
| S60 | dns-truncated-opt | A DNS query with a cut-off OPT record: F5 |
| S61 | dst-ip-redacted | The planted IPv4 as the original destination prints redacted |

## Regenerating the golden file

Only when a reviewed change to the canary generator makes it differ:

```bash
cargo run --locked -q -p gd-egress -- canaries --seed 1 --out /tmp/gd-canaries-1
cp /tmp/gd-canaries-1/judge/canaries.json tests/egress/golden/canaries-seed-1.json
```

Then read the diff: every value is generated, and none is real.
