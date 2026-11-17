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
