# Fixtures

Test material the judges read. Nothing here is live: no network, no Docker.

## Expected advisory matches (Judge B)

`expected-matches.toml` says, for every setup and every advisory in `advisories/corpus/`, what a correct matcher must report. It was written by hand from each advisory's OSV ranges and its `database_specific.guard_dog.conditions`, before any matcher exists.

- **`[[setup]]`**: one per judged setup. Its services and versions are checked against their source of truth (`versions_from`); for `lab-regtest` that's the pinned image labels in `lab/compose.yml`, which `lab/up.sh` checks the running services against.
- **`[[expect]]`**: one per setup and advisory, sorted by setup then advisory. Each one records two separate calls and the result that follows from them:
  - `version`: `in-range`, `out-of-range`, `unknown`, or `not-applicable` (the product isn't in the setup).
  - `condition`: are the advisory's required conditions (running service, backend, option, exposure, platform) `met`, `not-met` or `unknown`?
  - `result`: `not-affected` if the version is out of range or a required condition is not met; `affected` if the version is in range and every required condition is met; otherwise `possibly-affected`, with a `question` that would settle it.
  - `reason`: one line citing the range or condition that decides it.
  - `review = "max"`: the call wasn't clear-cut; Max or a tester should check it.

`crates/gd-core/tests/expected_matches.rs` refuses a file with a missing or doubled pair, an unknown advisory or setup, a result that doesn't follow from the two calls, a possibly-affected pair without a question, or a lab version that differs from `lab/compose.yml`. It also scores a matcher against the file (see `tests/README.md`).

Never loosen an expected result to make the matcher pass without a written reason in the PR and in this file's history. A new recorded setup gets one `[[setup]]` and one `[[expect]]` per advisory, and its id is added to `SETUPS` in the test.
