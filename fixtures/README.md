# Fixtures

Test material the judges read. Nothing here is live: no network, no Docker.

## Expected advisory matches (Judge B)

`expected-matches.toml` says what a correct matcher must report for every setup listed in it and every advisory in `advisories/corpus/`. It was written by hand from each advisory's OSV ranges and its `database_specific.guard_dog.conditions`, before any matcher exists.

- **`[[product]]`**: one per catalog id, with its other names (`aliases`, for example `cashu-nutshell-mint` for `nutshell`) and its OSV packages as `<ecosystem> <name>`. Every `service` named in an advisory's conditions must be a product id or alias.
- **`[[setup]]`**: one per judged setup, with its platform, chain, exposure, `arch` and `block_storage`.
  - `lab-regtest` (`source = "lab"`): its services and versions must equal the pinned image labels in `lab/compose.yml`, which `lab/up.sh` checks the running services against. Its `[[setup.package]]` entries record the xz and liblzma versions read from each pinned image (`packages_from` says how).
  - `lab-old-synthetic` (`source = "synthetic"`): **not a recording.** It's the lab's configuration with older, affected versions, so that affected results are tested before an old setup has been recorded.
  - **`[[setup.fact]]`**: zero or more per setup. The facts that advisory conditions depend on and the setup's other keys don't already carry (the services, packages, chain, platform, exposure, arch and block storage are carried there). A matcher reads these rows, never the English in `description` or `reason`. Each row has exactly these keys:
    - `name`: a condition name that some advisory in `advisories/corpus/` uses (the test reads the set from the corpus, so a typo fails);
    - `service`: a service id in that setup, left out for a fact about the whole setup or about something the setup doesn't run;
    - `subject`: the argument, only for names that take one: the option for `option_enabled` and `option_disabled`, the backend for `backend_in_use`, the feature for `feature_enabled`, the package for `package_installed`;
    - `value`: `"true"`, `"false"` or `"unknown"`. Where the setup's own description, `lab/compose.yml` or an expectation's reason doesn't say, the value is `"unknown"`; nothing is guessed;
    - `evidence`: one line of plain English saying where it comes from, with no local paths.

    Every required condition of an advisory whose product the setup runs needs a row, unless the pair's `condition` is `unknown`. `service_running` is carried by the services list and `package_installed` by the setup's package entries, so those need no row.
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
- an unlabelled synthetic setup;
- a `[[setup.fact]]` with an unknown key, a name no advisory uses, a service the setup doesn't run, a `subject` where there is no argument (or none where there is), a value other than `true`, `false` or `unknown`, empty evidence or evidence that names a local path;
- a required condition with no fact row where the pair's condition isn't `unknown`.

The test also scores a matcher against the file; see `tests/README.md`. The matcher sees only the setup and advisory ids, never the expected result.

History: on 2026-11-17 the pair `lab-old-synthetic` x the LND DNS bootstrap advisory changed from not-affected to possibly-affected (version in-range, condition unknown, `review = "max"`). The advisory's required condition is `option_disabled nobootstrap`, and the lab doesn't set `--nobootstrap`, so on the facts it is met as written. "Regtest has no DNS seeds" is not something the condition says. Max decides whether the advisory should carry a chain condition. The `lab-regtest` pair stays not-affected because its LND version is out of range.

Never loosen an expected result to make the matcher pass without a written reason in the PR and in this file's history. A new setup gets one `[[setup]]` and one `[[expect]]` per advisory, and its id goes into `SETUPS` in the test.

## The lab as recorded (two back ends)

`lab-recorded/manifest.toml` is the manifest a real `lab/up.sh` run wrote on 2026-11-16 (Mac, arm64), committed exactly as it came out: the chain, each service's id and the version the running service reported, plus comments naming the reply and the pinned image. No credentials. `crates/gd-core/tests/two_backends.rs` checks that Judge B sees the same facts through it as through the `lab-regtest` setup above, and that its `# image` lines are the images `lab/compose.yml` pins. Re-record it whenever a lab image changes (`lab/README.md`, "Changing an image").
