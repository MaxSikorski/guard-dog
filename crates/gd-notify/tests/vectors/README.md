# NIP-44 test vectors

`nip44.vectors.json` is the official NIP-44 v2 test-vector file. It is data only: the tests read it as JSON and never run anything from it.

| | |
|---|---|
| Source | https://github.com/paulmillr/nip44 (`nip44.vectors.json`) |
| Commit | `1f8dba1707d065b39329b75012a13a6d1d8124f5` (last commit that touched the file, 2023-12-19) |
| Raw URL | https://raw.githubusercontent.com/paulmillr/nip44/1f8dba1707d065b39329b75012a13a6d1d8124f5/nip44.vectors.json |
| SHA-256 | `269ed0f69e4c192512cc779e78c555090cebc7c785b609e338a62afc3ce25040` |

Check it with `shasum -a 256 nip44.vectors.json`.

Licence: the repository's NIP-44 specification text and code are described as MIT by the NIP-44 project. The repository has no LICENSE file that GitHub detects, so this is recorded here rather than assumed. The file holds only numbers (keys, nonces, payloads), and it is used only in tests, so nothing from it ships in a release. `THIRD-PARTY-NOTICES.md` lists the website files that ship, so it has no entry for this.

Used by `crates/gd-notify/tests/nip44_vectors.rs`.

## Gift wrap examples from the specifications

`nip59_nip17_examples.json` holds two gift wraps printed in the specifications, made by other people's code, with their recipient's secret key (public test keys from the specs). It was extracted from the two documents below by a script that only reads the JSON blocks; the recipient's `nsec` in the NIP-17 text was decoded to hex.

| | |
|---|---|
| Source | https://github.com/nostr-protocol/nips, `59.md` ("An Example") and `17.md` ("Examples", the wrap to the receiver) |
| Commit | `bec0fc89e75645e77a06d145598246efca844457` |
| `59.md` SHA-256 | `b46b078ff5b219fd4ab33a53b479b49d4cbd604b88be46d6b978d53d8f8b43a0` |
| `17.md` SHA-256 | `7aa9c3a9c0458a9552c4be2f3bf17f7ec60a4afe88bce7977f03500a7873a64c` |
| JSON SHA-256 | `db99dbf8445426b2d3c974c9e01a116a6e2d01dc00b226c60667a83175fe4f8c` |

Used by `crates/gd-notify/tests/interop.rs`. The NIP-59 example holds a kind-1 rumor, so it is opened with `unwrap_any`; the NIP-17 one is a kind-14 direct message and opens with `unwrap_dm`. Both must verify every layer and read the plain text.
