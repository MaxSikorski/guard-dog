# Judge C: egress capture

Judge C asks one question: does anything leave the box that shouldn't, including planted canary secrets? It reads three independent records of everything Guard Dog tried to send (the resolver log, the recorder's decrypted flows and the raw packet capture), and fails the run on any of these:

- **F1** a destination that isn't in `allowlist.toml`, judged by the network layer: the name asked for, the address reached, the port and the TLS server name must all agree with one entry
- **F2** a planted canary or a secret-shaped value in any form from the decoding set, in anything the resolver log, the recorder or the packet capture holds
- **F3** a packet that fell into the black hole, meaning it tried to leave without being redirected
- **F4** a missing control: a judge that sees nothing must never pass
- **F5** a capture that can't be read, is incomplete, or disagrees with itself (gaps, lost tails, kernel drops, fragments, extra or cut-off DNS records, bodies that cannot be decoded, a missing end marker)

The checker is `crates/gd-egress` (`gd-egress check`). Today it runs on **synthetic** captures only; the live lab that makes real captures arrives in the next piece.

## What Judge C proves, and what it doesn't

**The claim**, for one commit and one workload:

- every flow went to an allowlisted destination
- the capture is complete from a proven start (the control before the workload) to a proven end (the control after it, and the recorder's end marker)
- no planted canary appears in the recorder's decrypted requests, the resolver log, the packet capture's loopback traffic to the recorder and resolver, or anything sent to the black hole, under the decoding set, up to two nested layers: raw, lowercase, percent-escaped, JSON-escaped, separator-stripped and letters-only views; base64, base64url, base32 and hex tokens decoded two layers deep; key bytes written as source code (`[0x8d, 0x1f]`, `[141, 31]`, `\x8d\x1f`); an xpub re-encoded under another version (zpub, ypub, tpub, ...); seed words as their first four letters and as SeedQR digits; IP addresses matched by value in dotted, integer, `0x`, IPv6, dashed host-name (`ip-198-51-100-7`), reverse-lookup (`in-addr.arpa`, `ip6.arpa`) and IPv4-mapped forms
- request bodies are decoded first: gzip, zlib, raw deflate and brotli, named by `Content-Encoding`, `Transfer-Encoding` (anything but `chunked` and `identity`), `grpc-encoding` (message by message), a gzip content type, or by the first bytes of the body and of every decoded layer (gzip is also looked for at every `1f 8b 08` inside a body, such as a file part of a multipart upload, and inside any base64, hex or base32 token that starts like gzip or zlib)
- all bodies of one capture together decode to at most 64 MiB in at most 4096 layers, then F5 `decode-bound`; nothing more is decoded once the scanner's own budget is spent
- byte lists written as numbers: decimal (also signed, as Java prints them), hex with or without `0x` and without zero padding (Rust `{:x?}`, Python `hex()`), in brackets or rows, Python `b'...'` literals, and raw bytes written as JSON `\u00XX`

**Not covered**, and caught or bounded by other layers instead:

- a build that deliberately obfuscates or encrypts its output, including a leak hidden in a dependency on purpose
- covert timing and size channels
- secrets inside end-to-end-encrypted payloads to allowed destinations (NIP-44, until Phase 5 gives the judge the test key)
- encodings outside the decoding set, or nested three or more deep
- raw deflate or brotli that no header names, alone or inside a decoded layer: they have no first bytes to recognise
- WebSocket messages compressed with permessage-deflate, unless the recorder undoes it (see below)
- gzip inside a decoded token when the token is itself inside a decoded layer (the token step runs on the views of the first two layers)
- a value deliberately split across successive request paths or headers (a body split across requests is joined; paths and headers are scanned one by one, and joined only in the destination's whole stream)
- loopback traffic to ports other than the recorder's 8080 and the resolver's 5353 is counted but not scanned: it cannot leave the box
- whether the recorder logged every client byte the kernel acknowledged (a pipelined request after a `503` with `Connection: close`): the per-connection byte count arrives with the recorder in PR 2

Those are the job of the never-have list and least privilege (threat model section 5), runtime allowlist enforcement (Phase 4.5), the supply-chain checks (`cargo deny`, the 14-day cooldown, `cargo audit`, review of new crates), reproducible builds with signed releases, and the review tiers.

**Decoding is bounded, and failing closed.** Decoding stops at 16 MiB of output per body, at 1000 times the size of what is being decoded, and after three layers; any of these is F5 `decode-bound`. A stream that will not decode, bytes left over after it, a coding we do not decode (`zstd`, `compress`, an unknown name) and a body that starts like zstd, xz, bzip2, zip or 7z are F5 `undecoded-content-encoding`. Nothing in either case is a pass. What decoded before a corrupt stream went bad is still scanned; the output a bound cut off is dropped, because the run has failed and scanning a bomb's output is the work it is after. `chunked` is message framing that the recorder has already removed, so it is not a compression. This is required before `allowlist.toml` gets its first entry, and it is now in place.

## What the lab must supply

Besides the files in the capture directory layout, the judge needs `pcap/tcpdump.log`: tcpdump's own closing summary (`N packets captured`, `N packets received by filter`, `N packets dropped by kernel`). The lab piece (PR 2; its `netns.sh` is not in the repository yet) writes tcpdump's messages to `tcpdump.log`, stops tcpdump with SIGINT, waits for it to exit and keeps that file as `pcap/tcpdump.log`. A missing file, a missing or repeated count line, any drop, or a packet count that differs from the pcap is F5. The recorder's addon should write a global `seq` number on every `http` and `tcp` event so requests on different connections can be put back in order (without it the line number is used). A request logged after a control request on the control's own connection (keep-alive) must have a larger `seq`, or it is F5 `order`.

**What the recorder must log, for the judge to work (PR 2):**
- Every HTTP request body is the raw, still-encoded body with the original headers (mitmproxy's `raw_content`). If the addon logs a body it has already decoded while the `Content-Encoding` header stays, every compressed request reads as corrupt and the judge is red on every run (it fails closed, so it is never a false pass).
- WebSocket messages (all Nostr relay traffic) are logged after `permessage-deflate` is undone. If a connection negotiated `permessage-deflate` and the addon cannot undo it, the run must be F5: per-message raw deflate has no first bytes and passes a scan.

**Running out of budget is F5 and says so.** `F5 capture-unreadable scan: scan-budget` means a busy or odd capture used up the scanner's token budget (4096 tokens per scan) or its 256 MiB byte budget, or a stream was over 64 MiB. It is not a leak and not a pass; read the capture or raise the budget on purpose.

## What is in this folder

| Path | What |
|---|---|
| `synthetic/` | 88 expected reports, one per scenario. **Synthetic: built by `crates/gd-egress/tests/support/mod.rs`, never a real capture.** Each was written before the code that makes it pass. |
| `golden/canaries-seed-1.json` | The canaries made from seed 1 (`canaries.json` format 2, with the raw bytes of each), byte for byte. Pins the generator. |
| `expected-rules.txt` | The firewall and route dump the sealed box must have. **Provisional** until the lab arrives; the lab piece replaces it with the real, reviewed dump. |

Reports contain no counts, no times and never a canary (those print as `<canary:CLASS>`), so an expected file is the same for every seed.

## The 88 scenarios

S01 to S18 are the first set; S19 to S61 each cover one review finding (O = Opus, C = Codex, then the second Codex round); S62 to S81 cover the third review (Opus) and the decoders; S82 to S88 the review of the decoders.

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
| S40 | gzip-body | An nsec inside a gzip body: found after decoding (C; was F5 until PR 1b) |
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
| S62 | deflate-zlib-leak | An nsec inside a zlib (`deflate`) body |
| S63 | brotli-leak | A gzip stream carrying an nsec inside a brotli body: both layers are decoded |
| S64 | gzip-clean | A harmless gzip body: PASS, nothing flagged just for being compressed |
| S65 | gzip-ratio-bomb | 8 MiB of zeros packed under 8 KiB: F5 `decode-bound` |
| S66 | gzip-three-deep | An nsec under three gzip layers: found |
| S67 | gzip-four-deep | The same under four: F5 `decode-bound`, never a pass |
| S68 | gzip-truncated | A gzip body cut in half: F5 `undecoded-content-encoding` |
| S69 | grpc-gzip-leak | An nsec in a gzip message inside a gRPC frame (`grpc-encoding: gzip`) |
| S70 | grpc-zstd | `grpc-encoding: zstd`: F5 |
| S71 | transfer-encoding-gzip | An nsec in a body with `Transfer-Encoding: gzip, chunked` |
| S72 | content-type-gzip | A gzip body named only by `Content-Type: application/gzip` |
| S73 | gzip-magic-no-header | A gzip body with no header saying so: found by its first bytes |
| S74 | zstd-magic | A body that starts like zstd: F5 |
| S75 | ptr-name-leak | The planted IPv4 as a `in-addr.arpa` PTR lookup: found, and the name prints redacted |
| S76 | nsec-key-as-byte-list | The nsec's 32 key bytes as a Rust `{:?}` list `[141, 31, ...]` |
| S77 | zpub-leak | The planted xpub re-encoded as a zpub |
| S78 | dns-opt-owner-not-root | A DNS query whose OPT record has a name instead of the root: F5 |
| S79 | dns-client-response | A message with the response bit set sent to the resolver: F5, and its question is still judged |
| S80 | tcp-no-syn | Data to the recorder with no handshake before it: F5 `tcp-gap` |
| S81 | keep-alive-before-post-control | A request on the post control's connection logged before it: F5 `order` |
| S82 | multipart-gzip-part | A multipart upload whose `.gz` file part holds an nsec |
| S83 | base64-gzip-in-json | `{"blob": "<base64 of gzip>"}` with an nsec inside |
| S84 | grpc-compressed-no-encoding | A gRPC frame flagged compressed, no `grpc-encoding`: F5 |
| S85 | zlib-trailing-bytes | `Content-Encoding: deflate`, a zlib stream and a tail: the secret is found, and the tail is F5 |
| S86 | python-bytes-repr | The nsec's key bytes as Python `repr(bytes)` |
| S87 | json-u-escapes-of-key-bytes | The key bytes as JSON `\u00XX` escapes |
| S88 | zpub-with-a-character-in-front | A zpub with one extra base58 character in front |

## Regenerating the golden file

Only when a reviewed change to the canary generator makes it differ:

```bash
cargo run --locked -q -p gd-egress -- canaries --seed 1 --out /tmp/gd-canaries-1
cp /tmp/gd-canaries-1/judge/canaries.json tests/egress/golden/canaries-seed-1.json
```

Then read the diff: every value is generated, and none is real.
