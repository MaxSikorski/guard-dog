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
- A network version source (`rpc`, `grpc`, `http`, `nip11`) gives `endpoint_port`, one of the entry's `recognize.ports`. If the port is not confirmed, the entry says so in a `[review].todo` item that starts with `ports:`. A network source also has at least one `[[recognize.probes]]` item on that port, which identifies the endpoint before its version is read.
- A `grpc` source also gives `[version.tls]` (`cert_source`, and a `server_name` that is `localhost` or the entry's own id, never a public name). There is no key to skip certificate checks, and an unknown key fails.
- Every version regex (and probe `match`) starts with `^`, ends with `$`, is at most 200 characters and uses no inline flags (`(?m)`, `(?s)`, `(?x)` and so on). The test compiles it as `\A(?:pattern)\z`, so an alternation can never match part of a reply. A version regex has a group named `version`. Guard Dog runs them only on replies of up to 256 bytes; longer replies are never matched. A version regex must give the version for each reply in `[[version.examples]]` (each with a `source`: a file in the repo, or a URL under the entry's own upstream), for the reply the lab recorded in `fixtures/lab-recorded/manifest.toml`, and it, like every probe `match`, must not match any other catalogued service's recorded reply. A probe `match` recognises the product by its own marker (`/Satoshi:` then a version-like start, `Nutshell/` then a token) and leaves the version form to the version regex, so an odd build such as `/Satoshi:28.1.0(mynode)/` is the product with its version unknown, not "not this product". A version regex must not read plain versions of more than one major number (the loader tries 2-, 3- and 4-part plain versions for every major 0 to 99, with minors and patches 0 to 12 and the samples 13, 18, 25, 50, 99, 100 and 123, and three forms for every major 100 to 999 and 2000 to 2099 and a few larger ones, and refuses a regex that reads more than one; a regex that reads plain versions of one major must spell it out as `^(?P<version>0\.` with no group, alternation or leading `?`, `*`, `+` or `{` after it, and every plain version it reads must have a major the entry permits (the majors the sweep sees plus those of its bare plain examples), checked on each read as well as at load; every loaded entry outside `PLAIN_VERSION_OK` has an explicit set of permitted majors, possibly empty, and a bare reply (one where the `version` group is the whole reply) with a major outside the set is `Unreadable(NotAVersion)`, so an empty set refuses every bare plain reply and leaves a prefixed one (`v26.06.9`, `/Satoshi:...`) to the entry's own regex; `PLAIN_VERSION_OK` lists the one reviewed exception, strfry; a regex that reads only minors, patches or majors outside the sweep, behind a prefix such as `Nutshell/`, is caught by review, not by the loader, and the identity rule means such a regex still reads nothing without its product's probe or image), because that would claim any product's reply; where a reply has a product prefix or suffix (`Nutshell/`, `-beta`, `-alpha`), the regex carries it. A build marker such as `-modded` stays inside the `version` group; the scheme refuses it (version unknown), so a modified build is never read as the upstream release. An example that no product ever sent, because its version form comes from an advisory's affected or fixed value, is marked `source_kind = "advisory"`: its `source` is that advisory file under `advisories/corpus/`, and the test reads it: the version must be an introduced, fixed or last-affected value (or a `database_specific.fixed_in` item) of one of the entry's own `osv_packages`, `raw` equals `version`, and the entry carries a `recorded-reply:` item in `[review].todo` until a real reply is recorded. Until then it has no images, probes or ports either (nothing recorded to recognise it by); they arrive with the recorded example. It proves the regex reads that form and is left out of the cross-entry check, which runs on recorded replies only.
- Image names are written in normalised form (`docker.io/namespace/repo`, with `library/` for Docker Hub single names), no tag or digest, `*` only as the very last character and only directly after a whole repo name and one of `-`, `_`, `.` (`docker.io/lightninglabs/lnd-*`), never in the namespace and never under `library/` (a registry may carry a port). The image reference a container runtime reports follows one strict grammar, Docker's distribution grammar narrowed: `[domain/]path[:tag][@digest]` of at most 256 bytes; the first segment is a domain only when there is more than one segment and it holds `.` or `:` or is `localhost`; a domain is dot-separated labels of `[A-Za-z0-9-]` (not starting or ending with `-`) and an optional port of 1 to 5 digits; a path component is lower-case `[a-z0-9]+` joined by `.`, `_`, `__` or runs of `-`; a tag is `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`; a digest is `sha256:` and 64 lower-case hex digits or `sha512:` and 128. Anything else is `Unreadable(BadToken)`, never a match. No two entries share an image, and a port is shared only if the test lists it with a reason (`SHARED_PORTS`: the Lightning peer port 9735). `binaries` and `units` may be empty only with a `binaries:` or `units:` item in `[review].todo`.
- `blind_spot` in `[advisories]` is required when the project has no GitHub advisories and no feed a machine can read (an Atom or RSS feed, or advisories kept as markdown in a repo). `signed-multi` needs `min_signatures` or a `signing.min_signatures` todo.
- URLs are `https`, with no credentials, query or fragment. `release_feed`, `security_policy`, `keys_url` and advisory feeds sit under `upstream.repo` (same owner and repo), under a repo listed in `upstream.related_repos` (same code host and same owner as `upstream.repo`, for example a project's signature repo; the loader lists the one reviewed exception, `RELATED_OTHER_OWNER`: Bitcoin Core's `bitcoin-core` organisation), or under a prefix the test lists for that entry and field. `release_feed`, `security_policy` and a source may also sit under `upstream.website`; `keys_url` and advisory feeds never do. A `website` is refused on github.com (and any subdomain, gist and raw content included), githubusercontent.com, gitlab.com, bitbucket.org and readthedocs.io; on codeberg.org it must be exactly `upstream.repo`; on a shared pages host (github.io, gitlab.io, codeberg.page, pages.dev, netlify.app, vercel.app) it must be the owner's own subdomain (`<owner>.github.io`) and then vouches for nothing. A host with a `0x` label, a last label that starts with a digit, or a punycode (`xn--`) label is refused. Errors name the field and never quote a URL, a reply example or a pattern. No URL may name an internal host, a `.local` or `.internal` name, a name that resolves to loopback by design (localtest.me, nip.io, sslip.io and the like) or an IP address. `upstream.repo` is on a reviewed code host (`FORGE_HOSTS`: github.com, codeberg.org), and a feed, key list or policy under a repo has a fixed shape (a release or tag feed, a file or folder at a ref, the security policy page); issues, pull requests, discussions and wikis, which anyone can write, are refused. A ref is a branch or tag name: an all-hex ref of 4 or more characters (an abbreviated commit, which a fork can supply), `pull`, `refs` and `HEAD` (any case) are refused. A website on a code host counts as the repo, so it never rescues a URL that fails the repo's shape. A port or example `source` is a file in the repo (the lab file, for lab ports) or a URL under the same upstream. One grammar covers every URL's path: empty, or `/`-separated segments of `[A-Za-z0-9._~-]` (never `.` or `..`, never an empty segment) with at most one trailing `/`, so no backslash, `:`, `;`, `@`, `+` or `//`. A repo URL (`upstream.repo`, a related repo) is exactly `https://host/owner/repo` with forge-style names: an owner of 1 to 39 characters of `[A-Za-z0-9_.-]` starting with a letter or digit, a repo of 1 to 100 of the same, not `.` or `..`. A ref also may not start with `.` or `-`, end with `.` or `.lock` (any case), so the refs git itself refuses are not trust roots. A website on any subdomain of a code host (`www.codeberg.org`) counts as that host.
- `fork_of` and `bundles` name other entries, never themselves, and never form a cycle. A bundle emits one fact per bundled id: a product that ships another (Lightning Terminal bundles LND) shows up as both.
- The loader hardens what a URL, image or call may say: no `%` encoding in any URL, no host with a trailing dot or an empty label, a wildcard image only after a full `registry/namespace/repo` prefix, no (port, proto) twice in one entry, TOML nested at most 32 levels deep, and `cert_source` is `node-tls-cert` or `pinned-in-config` (never the system's web roots). A version read from a reply is a token of 1 to 64 characters from `[0-9A-Za-z.+~-]` starting with a letter or digit, and only ASCII replies are matched. Identity gives `Read`, `NoMatch` or `Unreadable`; the caller builds an `EndpointKey` for each observation (host and port, or runtime and container id: `EndpointKey::new(host, port)` or `EndpointKey::for_container(runtime, id)`), the proof remembers it, and `read_version` with another observation's key is `Unreadable(MissingEvidence)`; an image proof is bound to the container instance, never to the image name, so a second container of the same image is identified on its own; a key of the wrong kind (an endpoint key for an image, a container key for probes) and an entry with no images give `Unreadable(MissingEvidence)`, never `NoMatch`; an image reference that is not well formed is `Unreadable(BadToken)`; a version read after identity gives `Read(token)` or `Unreadable(reason)`, never `NoMatch`; an unreadable reply (too long, non-ASCII, a bad token, not a version) is version unknown with the product kept, never not affected. Work is capped: an entry is at most 32 KB, a list at most 64 items, 16 images, a catalog at most 1024 entries; an image is listed once. Errors follow one redaction rule: the `Display` and `Debug` of every loader error carry only the file slug, entry ids taken from validated file names, field paths built from the known keys, item indexes, line numbers and fixed text, never a value from an entry (a test replaces every string of four entries by a marker and checks it never comes back); an unknown key shows as `an unknown key`. The secret-shape scan runs over the raw file text, comments included (an error names the line number), as well as over the decoded values (see the secret scan below). Display text (`name`, `summary`, notes, todo) has no control, format or bidi characters; `name` is ASCII, has no leading, trailing or doubled space, and is unique across the catalog without regard to case. `advisories.osv_packages` items start with an OSV ecosystem name (Go, PyPI, npm, crates.io, GIT, Maven, NuGet, RubyGems, Packagist, Hex, Pub, SwiftURL, Debian, Alpine, Ubuntu); a GIT package is `upstream.repo` or a related repo; an empty list needs a `blind_spot`.
- The secret scan has two layers. A compile-time guard (`crates/gd-core/src/catalog_scan.rs`, run on every embedded file by `catalog_files.rs`) makes `cargo build` itself fail, with a fixed message and no file text, when a file has a credential-shaped line, so a build that skips the tests cannot ship one. The loader runs the same function when an entry is loaded, with the regex scan on the raw lines and on the decoded values (a multi-line string is also scanned with its whitespace collapsed, so a seed split over lines is caught). It looks at the file as written, at a continuation view (a line ending in `\` joined to the next with the leading blanks dropped, which is how TOML joins a multi-line string, so a token split that way is whole again), at the whole text under the seed rule (newlines, `\`, quotes, brackets, braces, `:`, `,` and `;` all separate words, so a seed in a JSON array or over the lines of a string is found), and at the comment stream: everything after the first `#` on each line, all lines joined in file order, so a secret split over several comment lines (with value lines or blank lines between) is one token again. It flags control bytes (other than tab, newline and carriage return), 64 or more hex digits (40 or more in a comment), macaroons, extended keys, `nsec`, private-key headers, Cashu, GitHub, AWS and `sk-` tokens, Lightning invoices, onion addresses, high-entropy tokens (a run of 40 or more of `[A-Za-z0-9+=_-]` that mixes upper case, lower case and digits, which catches runes), and 12 or more seed-like words in a row (also in a numbered list or split over comment lines).
- Blind spots of the secret scan: the compile-time guard does not check IPv4 or IPv6 addresses (the load-time scan and the tests do). Prose of 12 or more unpunctuated words of 3 to 8 letters in a row, in a comment or a value, counts as a seed and fails the build: put a full stop or a comma-free break in it, or reword it. No scan finds a credential with no known shape: a password, a token under 40 characters or one that does not mix upper case, lower case and digits, a base64 token broken by `/` into pieces under 40 characters (unless it starts `AgE` or `AgF`), a seed phrase in another script, with capitalised or hyphen-joined words, or with fewer than 12 words, or any text deliberately scrambled. The guard is a seat belt; the rule stays: never paste a real credential into a catalog file.
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

[[recognize.probes]]
kind = "nip11"
method = "GET"
path = "/"
accept = "application/nostr+json"
port = 7777
field = "software"
match = '^git\+https://github\.com/hoytech/strfry(\.git)?$'

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
