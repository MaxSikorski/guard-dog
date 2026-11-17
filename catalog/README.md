# The service catalog

One TOML file per product Guard Dog knows about: `catalog/<id>.toml`. It is data, not code. The scanner reads it through the loader (`gd_core::catalog`); entries are compiled in from `crates/gd-core/src/catalog_files.rs`, which a test keeps equal to this folder (add a line there with each new entry). Today it holds the five services in the regtest lab (`lab/compose.yml`) and eight more products; more arrive in later pull requests. Catalog pull requests are reviewed by the maintainer before they merge.

Every fact in an entry has a source, and anything not confirmed is listed in `[review].todo` instead of being guessed. The test `crates/gd-core/tests/catalog.rs` checks every entry, offline, on every `cargo test --locked`. Entries hold no secrets: no keys, seeds, tokens, private addresses or onion addresses.

GPL and other copyleft services (strfry is GPL-3.0) may be catalogued: an entry is data about a product, and it never means Guard Dog ships, links or embeds that code. Guard Dog only talks to such a service over its own network interface.

## Rules

- The file name is the `id`. An id never changes; an old name moves to `aliases`.
- An entry is a product, not a repo (two products can share one repo).
- The schema is closed: an unknown key anywhere fails the test.
- An `id` and its `aliases` and `osv_packages` equal the product of the same id in `fixtures/expected-matches.toml` (Judge B). The test pins two exact lists: Judge B products with no entry yet (`UNCATALOGUED`) and entries that are not Judge B products yet (`NOT_YET_IN_JUDGE_B`). A list shrinks only by editing it in the same pull request.
- A call (a version call or a probe) is structured, never a shell string, and only reads. A command-line call is an `argv` list of plain words (the first a bare program name from `recognize.binaries`, never a shell or interpreter such as `sh`, `env` or `python`) plus `run_as` (`service-user-in-container` or `service-user-on-host`, never root). A network call is a method and a local path only (`GET` and `/v1/info`, or an RPC method name with its package, like `verrpc.Versioner/GetVersion`); it always goes to the matched service's own endpoint, so an entry never holds a scheme, host or address. The test lists every allowed call exactly (`READ_ONLY_CALLS`); a call not on that list is refused, and adding one is a reviewed edit. `field` is a plain dotted name. Calls and `credential` must not name a scheme, host, user info, `..`, link-local or metadata address, or onion address.
- A network version source (`rpc`, `grpc`, `http`, `nip11`) gives `endpoint_port`, one of the entry's `recognize.ports`. If the port is not confirmed, the entry says so in a `[review].todo` item that starts with `ports:`.
- A `grpc` source also gives `[version.tls]` (`cert_source`, and a `server_name` that is `localhost` or the entry's own id, never a public name). There is no key to skip certificate checks, and an unknown key fails.
- Every version regex (and probe `match`) starts with `^`, ends with `$`, is at most 200 characters and uses no inline flags (`(?m)`, `(?s)`, `(?x)` and so on). The test compiles it as `\A(?:pattern)\z`, so an alternation can never match part of a reply. A version regex has a group named `version`. Guard Dog runs them only on replies of up to 256 bytes; longer replies are never matched. A version regex must give the version for each reply in `[[version.examples]]` (each with a `source`: a file in the repo, or a URL under the entry's own upstream), for the reply the lab recorded in `fixtures/lab-recorded/manifest.toml`, and it, like every probe `match`, must not match any other catalogued service's recorded reply. A version regex must not read plain versions of more than one major number (the loader tries 2-, 3- and 4-part plain versions across majors 0 to 40, 100 and 2024 to 2027, with minors and patches 0 to 12, and refuses a regex that reads more than one major; `PLAIN_VERSION_OK` lists the one reviewed exception, strfry), because that would claim any product's reply; where a reply has a product prefix or suffix (`Nutshell/`, `-beta`, `-alpha`), the regex carries it. An example that no product ever sent, because its version form comes from an advisory's affected or fixed value, is marked `source_kind = "advisory"`: its `source` is that advisory file under `advisories/corpus/`, and the test reads it: the version must be an introduced, fixed or last-affected value (or a `database_specific.fixed_in` item) of one of the entry's own `osv_packages`, `raw` equals `version`, and the entry carries a `recorded-reply:` item in `[review].todo` until a real reply is recorded. Until then it has no images, probes or ports either (nothing recorded to recognise it by); they arrive with the recorded example. It proves the regex reads that form and is left out of the cross-entry check, which runs on recorded replies only.
- Image names are written in normalised form (`docker.io/namespace/repo`, with `library/` for Docker Hub single names), no tag or digest, `*` only as the very last character and only directly after a whole repo name and one of `-`, `_`, `.` (`docker.io/lightninglabs/lnd-*`), never in the namespace and never under `library/` (a registry may carry a port). No two entries share an image, and a port is shared only if the test lists it with a reason (`SHARED_PORTS`: the Lightning peer port 9735). `binaries` and `units` may be empty only with a `binaries:` or `units:` item in `[review].todo`.
- `blind_spot` in `[advisories]` is required when the project has no GitHub advisories and no feed a machine can read (an Atom or RSS feed, or advisories kept as markdown in a repo). `signed-multi` needs `min_signatures` or a `signing.min_signatures` todo.
- URLs are `https`, with no credentials, query or fragment. `release_feed`, `security_policy`, `keys_url` and advisory feeds sit under `upstream.repo` (same owner and repo), under a repo listed in `upstream.related_repos` (same code host and same owner as `upstream.repo`, for example a project's signature repo; the loader lists the one reviewed exception, `RELATED_OTHER_OWNER`: Bitcoin Core's `bitcoin-core` organisation), or under a prefix the test lists for that entry and field. `release_feed`, `security_policy` and a source may also sit under `upstream.website`; `keys_url` and advisory feeds never do. A `website` is refused on github.com (and any subdomain, gist and raw content included), githubusercontent.com, gitlab.com, bitbucket.org and readthedocs.io; on codeberg.org it must be exactly `upstream.repo`; on a shared pages host (github.io, gitlab.io, codeberg.page, pages.dev, netlify.app, vercel.app) it must be the owner's own subdomain (`<owner>.github.io`) and then vouches for nothing. A host with a `0x` label, a last label that starts with a digit, or a punycode (`xn--`) label is refused. Errors name the field and never quote a URL, a reply example or a pattern. No URL may name an internal host, a `.local` or `.internal` name, a name that resolves to loopback by design (localtest.me, nip.io, sslip.io and the like) or an IP address. A port or example `source` is a file in the repo (the lab file, for lab ports) or a URL under the same upstream.
- `fork_of` and `bundles` name other entries, never themselves, and never form a cycle. A bundle emits one fact per bundled id: a product that ships another (Lightning Terminal bundles LND) shows up as both.
- The loader hardens what a URL, image or call may say: no `%` encoding in any URL, no host with a trailing dot or an empty label, a wildcard image only after a full `registry/namespace/repo` prefix, no (port, proto) twice in one entry, TOML nested at most 32 levels deep, and `cert_source` is `node-tls-cert` or `pinned-in-config` (never the system's web roots). A version read from a reply is a token of 1 to 64 characters from `[0-9A-Za-z.+~-]` starting with a letter or digit, and only ASCII replies are matched. A match gives `Read(token)`, `NoMatch` or `Unreadable(reason)`; an unreadable reply (too long, non-ASCII, a bad token) is version unknown, never not affected. Display text (`name`, `summary`, notes, todo) has no control, format or bidi characters; `name` is ASCII and unique across the catalog without regard to case. `advisories.osv_packages` items start with an OSV ecosystem name (Go, PyPI, npm, crates.io, GIT, Maven, NuGet, RubyGems, Packagist, Hex, Pub, SwiftURL, Debian, Alpine, Ubuntu); a GIT package is `upstream.repo` or a related repo; an empty list needs a `blind_spot`.
- Signing key fingerprints (`[[signing.keys]]`) are not filled in yet. Package URLs and CPEs arrive with the SBOM phase.

## Fields

| Field | Meaning |
|---|---|
| `format` | Schema version, `1`. |
| `id`, `name`, `kind` | Slug (`a-z`, `0-9`, `-`, at most 40), display name, and one of `service`, `platform`, `device`, `app`, `miner`, `package`. |
| `aliases` | Other names advisories use for it. |
| `summary` | One line, plain English. |
| `money` | `true` if it holds funds or keys, or hosts software that does. |
| `licence` | Upstream licence. It never implies Guard Dog ships it. |
| `fork_of`, `bundles` | Optional; other catalog ids. |
| `[upstream]` | `repo` (`https://host/owner/repo`, required), and optional `website`, `security_policy`, `release_feed`, `related_repos`. |
| `[recognize]` | `images`, `binaries`, `units`; optional `[[recognize.ports]]` (`port`, `proto`, `what`, `exposure` = `never-public`, `lan` or `public-ok`, and an optional `source`) and `[[recognize.probes]]` (`kind` = `nip11`, `http`, `rpc` or `grpc`, the call keys below, an optional `port` that must be in `recognize.ports` (default: `version.endpoint_port`), and `field` with an anchored `match`: a probe with no pattern is refused). |
| `[version]` | `source` (`rpc`, `grpc`, `http`, `nip11`, `cli`, `image-label`, `platform-manifest`), `credential` (the least-privileged one, in words), `regex`, `scheme` (`semver`, `semver-beta`, `bitcoin-core` (0.x.y before 22, major.minor from 22), `major-minor`, `git-describe`, `calver`, `opaque`), `endpoint_port`, `[version.tls]` (grpc), `[version.call]` and at least one `[[version.examples]]` (`raw`, `version`, `source`, and optionally `source_kind = "advisory"`). |
| `[version.call]` | `field` (the reply field read), plus: for `cli`, `argv` and `run_as` (an enum); for `http` and `nip11`, `method` (`GET` only), `path` and optionally `accept`; for `rpc` and `grpc`, `method`. |
| `[[platform_map]]` | Optional: `platform`, `app_id`, `version_rule` (`same`, `image-tag`, `differs`), `note`. |
| `[advisories]` | `osv_packages` (`"<ECOSYSTEM> <name>"`), `ghsa`, `feeds` (`kind` and `url`), and an optional `blind_spot` in words when the project's advisories are known to be incomplete. |
| `[signing]` | `level` (`signed-multi`, `signed-single`, `tag-only`, `unsigned`, `unknown`); optional `method`, `keys_url`, `min_signatures`, `reproducible` (`yes`, `no`, `unverified`), `images_signed`, `[[keys]]`. |
| `[review]` | `last_reviewed` (a date), `sources` (https links), `todo` (open questions, never guessed values). |

## Example

```toml
format = 1
id = "strfry"
name = "strfry"
kind = "service"
aliases = []
summary = "A Nostr relay."
money = false
licence = "GPL-3.0"

[upstream]
repo = "https://github.com/hoytech/strfry"

[recognize]
images = ["ghcr.io/hoytech/strfry"]
binaries = ["strfry"]
units = []

[[recognize.ports]]
port = 7777
proto = "tcp"
what = "relay websocket"
exposure = "public-ok"

[version]
source = "nip11"
endpoint_port = 7777
credential = "none"
regex = '^(?P<version>\d+\.\d+\.\d+(?:-\d+-g[0-9a-f]{7,})?)$'
scheme = "git-describe"

[version.call]
method = "GET"
path = "/"
accept = "application/nostr+json"
field = "version"

[[version.examples]]
raw = "1.1.2-148-g4cd3cf6"
version = "1.1.2-148-g4cd3cf6"
source = "fixtures/lab-recorded/manifest.toml"

[advisories]
osv_packages = ["GIT https://github.com/hoytech/strfry"]
ghsa = false
feeds = []
blind_spot = "No SECURITY.md, no advisories, not in OSV (spike d, 2026-11-16)."

[signing]
level = "unsigned"

[review]
last_reviewed = 2026-11-17
sources = ["https://github.com/hoytech/strfry"]
todo = [
  "licence: confirm -only or -or-later upstream",
  "units: systemd unit names",
]
```

See the files here for complete entries.
