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

`lab-recorded/manifest.toml` is the manifest a real `lab/up.sh` run wrote on 2026-11-16 (Mac, arm64), committed exactly as it came out: each service's id and the version the running service reported, plus comments naming the reply and the pinned image. No credentials. `crates/gd-core/tests/two_backends.rs` checks that Judge B sees the same setup through it as through the `lab-regtest` setup above. Re-record it whenever a lab image changes (`lab/README.md`, "Changing an image").
