# Where the PEP 440 vectors come from

`pep440-vectors.json` holds 139 version strings (30 that `packaging` refuses), the text `str(Version(...))` gives for each, and the order (-1, 0 or 1) of every pair of readable strings: 5,886 pairs.

- Generator: `gen_pep440.py`, using `packaging.version.Version`.
- Pin: `packaging==26.3`, released 2026-08-04 (three and a half months before the run, so well past the 14-day rule). The newer releases listed on PyPI on 2026-11-17 were checked first; 26.3 is the newest.
- Run once, on 2026-11-17: `uv run --no-project --with packaging==26.3 python -I crates/gd-advisories/tests/reference/gen_pep440.py > crates/gd-advisories/tests/reference/pep440-vectors.json`
- Specification: [PEP 440](https://peps.python.org/pep-0440/) and [version specifiers](https://packaging.python.org/en/latest/specifications/version-specifiers/).

Generation is a development step. The tests read only the committed JSON; no Python runs at test time, and no new runtime package exists. To regenerate on purpose, change the inputs or the pin in the script, run the command above, review the diff, and commit the script and the output together.

The scheme accepts a strict subset of `packaging`: Unicode whitespace around a version and Unicode letters that Python's case folding equates with ASCII ones (the long s in `post`) are refused (`unicode_whitespace_and_case_folding_tricks_are_refused`; no recorded vectors for those, since `packaging` accepts them). The Kelvin sign in a local label is refused by both and is recorded.
