# Where the PEP 440 vectors come from

`pep440-vectors.json` holds 137 version strings (28 that `packaging` refuses), the text `str(Version(...))` gives for each, and the order (-1, 0 or 1) of every pair of readable strings: 5,886 pairs.

- Generator: `gen_pep440.py`, using `packaging.version.Version`.
- Pin: `packaging==26.3`, released 2026-08-04 (three and a half months before the run, so well past the 14-day rule). The newer releases listed on PyPI on 2026-11-17 were checked first; 26.3 is the newest.
- Run once, on 2026-11-17: `uv run --no-project --with packaging==26.3 python -I crates/gd-advisories/tests/reference/gen_pep440.py > crates/gd-advisories/tests/reference/pep440-vectors.json`
- Specification: [PEP 440](https://peps.python.org/pep-0440/) and [version specifiers](https://packaging.python.org/en/latest/specifications/version-specifiers/).

Generation is a development step. The tests read only the committed JSON; no Python runs at test time, and no new runtime package exists. To regenerate on purpose, change the inputs or the pin in the script, run the command above, review the diff, and commit the script and the output together.
