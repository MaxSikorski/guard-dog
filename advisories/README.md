# Advisories

Real security advisories, written as OSV JSON, used as raw material for Judge B (does Guard Dog report every advisory that applies, and nothing that doesn't?). This is the plain-English guide to how the corpus is collected and checked.

## What is here

| Path | What |
|---|---|
| `corpus/<id>.json` | One advisory per file, named after its `id`. Real advisories only, each written from its primary source. |
| `schema/osv-schema-1.9.2.json` | The OSV JSON schema every file is checked against (vendored, below). |

`crates/gd-core/tests/advisory_corpus.rs` checks every file in sorted order with no network:

- the corpus is exactly the reviewed list of ids in the test (`EXPECTED_IDS`), so a deleted, renamed or unreviewed file fails;
- every record is valid against the schema, with its date and web-address formats checked too;
- the file name equals `id`, and there is an `https` primary-source reference;
- a plain-English playbook of 2 to 4 steps, and a real `source_checked` date;
- well-formed ranges, and the word "unknown" in the note on every `introduced: "0"`.

Mutation checks show the validator and these rules reject broken records, so a pass means something.

## The vendored schema

| | |
|---|---|
| Source | https://raw.githubusercontent.com/ossf/osv-schema/v1.9.2/validation/schema.json |
| Repository and tag | https://github.com/ossf/osv-schema, tag `v1.9.2` (released 2026-10-13, 34 days before it was vendored on 2026-11-16) |
| License | Apache-2.0 (verified against the repository's `LICENSE` and GitHub's license data) |
| SHA-256 | `15b10dbb4c4e31c7aae11d22cdd991a9a374758db7c8389e62b3cc37cac92653` |

The file is unchanged from the tag. To update it, vendor a tag at least 14 days old, record the new URL and hash here, re-run the test, and fix any record that no longer validates.

## How a record is written

- Standard OSV fields: `id`, `modified`, `published`, `aliases`, `summary`, `details`, `affected`, `references`. `details` is a paraphrase in plain words; text from outside is data, never copied in as instructions.
- `modified` is the day we last curated the record (2026-11-16 for the first batch). `published` is the date of the primary source (the `ADVISORY` reference); where a CVE or OSV record came later, or the date comes from somewhere else, `database_specific.published_basis` says so.
- IDs: the CVE, GHSA or PYSEC id when one exists; otherwise `x_<project>-<year>-<slug>`, which the schema allows for ids without an assigned prefix.
- Ranges: where the source gives no start version, `introduced` is `"0"` and the entry's `database_specific.range_note` says the start is unknown (with the word "unknown"; the test checks it). Each range is an `introduced` followed by one `fixed` or `last_affected`, never two in a row. Where a project fixes several release lines, each line gets its own range and the note says which `.0` starts are structural placeholders. Where a fix doesn't cover every platform, a second entry for the same package names the platforms that stay affected in `database_specific.platform`, with no fixed version. Where a project has no package registry, the package is `ecosystem: "GIT"` with the upstream repository address as the name, and ranges are release versions (the sources give no commit hashes). Version strings are as the source writes them; per-service normalisation (`v` prefixes, `-beta`, `6.6.0QX`) belongs to the matcher in Phase 2.
- `database_specific.guard_dog`: `conditions` (facts that must be true, beyond the version; **draft format, finalized in Phase 2.2**; a `chain` fact has `any_of`, the chains it applies to, each one of `main`, `testnet3`, `testnet4`, `signet`, `regtest` (the test refuses any other name), and is read from the setup's own `chain`), `playbook` (what to do, in plain English), `source_checked` (the date we last read the primary source).
- Other `database_specific` keys record how the source was read (`primary_source_kind`, `no_cve`, `vendor_severity`, `details_withheld_by_vendor`, `primary_source_retrieved`).

## Curation checklist

Before a record goes in:

1. **Primary source.** The project's own advisory page, GitHub Security Advisory or release notes, plus the OSV.dev record where one exists. A news report is allowed only when the project's announcement can't be fetched, and then the record says so (`primary_source_retrieved: false`).
2. **No guessed ranges.** Every version, date and id is in a cited source. If the source gives no range, mark it unknown in `database_specific`; never fill it in.
3. **Plain-English playbook.** 2 to 4 steps a non-expert can follow, with no instructions copied from the source.
4. **`source_checked` date.** The day the source was last read.
5. **Nothing undisclosed.** If an item looks like a vulnerability the project has not disclosed, write nothing about it and flag it to Max as a possible embargo item.
6. Add the id to `EXPECTED_IDS` in the test, then run `cargo test --locked -p gd-core --test advisory_corpus`.

## What is not here yet

Judge B step 3, the expected result for each recorded setup and advisory pair (affected, not affected, possibly affected, plus the question that would settle it), waits for Judge A's recorded setups. Step 5, the judge itself, waits for the Phase 2 matcher. Until then Judge B is the corpus and its validation test.
