"""Records PEP 440 reference vectors from the packaging library.

Development step only: the tests read the committed pep440-vectors.json and
never run Python. Regenerate on purpose with

    uv run --no-project --with packaging==26.3 python -I \
        crates/gd-advisories/tests/reference/gen_pep440.py \
        > crates/gd-advisories/tests/reference/pep440-vectors.json

The output is JSON on stdout: the generator's name and pin, the fixed list of
inputs, `str(Version(input))` for each (null where packaging refuses it), and
the ordering of every pair of readable inputs (-1, 0 or 1) as [i, j, order].
"""

import json
import sys

import packaging
from packaging.version import InvalidVersion, Version

PIN = "26.3"

# The design's examples (2.1, section 2), then edge cases for each rule:
# epoch, release zero padding, pre/post/dev spellings and separators, implicit
# post, local labels, outer whitespace, and inputs that must be refused.
INPUTS = [
    # design examples
    "1.0", "1.0.0", "1.0.dev1", "1.0a1", "1.0b1", "1.0rc1", "1.0.post1",
    "1.0.post1.dev1", "1!0.1", "9999.0", "1.0+abc", "1.0+1", "V01.0RC",
    "1.0rc0",
    # epoch
    "0!1.0", "1!1.0", "2!0.0", "0.1", "1!0.0.1",
    # release: padding and leading zeros
    "1", "1.0.0.0", "01.00", "1.2.3", "1.10", "1.9", "1.2", "10.0", "2.0",
    "00001.0",
    # leading v and case
    "v1.0", "V1.0", "1.0RC1", "1.0A1", "1.0B2", "1.0.POST1", "1.0.DEV1",
    # pre-release spellings and separators
    "1.0alpha1", "1.0-alpha-1", "1.0_a_1", "1.0.a.1", "1.0beta2", "1.0b2",
    "1.0c1", "1.0pre1", "1.0preview1", "1.0-rc.1", "1.0a", "1.0b", "1.0rc",
    "1.0a2", "1.0a10", "1.0a9", "1.0b0", "1.0rc2", "1.0rc10",
    # a separator after a label with no number is accepted by packaging
    "1.0a.", "1.0post-", "1.0.dev_", "1.0rc-", "1.0a-.dev1",
    # post-release spellings
    "1.0-1", "1.0-2", "1.0post1", "1.0-post1", "1.0_post_1", "1.0rev1",
    "1.0r1", "1.0.post", "1.0.post0", "1.0.post2", "1.0.post10",
    "1.0a1.post1", "1.0rc1.post2",
    # dev-release spellings
    "1.0dev", "1.0-dev2", "1.0_dev_3", "1.0.dev0", "1.0.dev2", "1.0.dev10",
    "1.0a1.dev1", "1.0a1.dev2", "1.0b1.dev1", "1.0rc1.dev1", "1.0.post2.dev1",
    "1.0.post1.dev2",
    # local labels
    "1.0+abc.1", "1.0+abc.2", "1.0+ABC", "1.0+a-b_c", "1.0+001", "1.0+1.0",
    "1.0+1.0.0", "1.0+abc.def", "1.0+2", "1.0+10", "1.0+0",
    "1.0.post1+local", "1.0.dev1+local",
    # real-world cashu versions
    "0.17.0", "0.18.0", "0.21.0", "0.18.0rc1", "0.18.0.dev1",
    # outer whitespace
    " 1.0 ", "\t1.0\n",
    # big numbers beyond 64 bits
    "18446744073709551616.0", "1.18446744073709551616",
    "18446744073709551616!1.0",
    # refused
    "", " ", "v", "1.", ".1", "1..0", "1.0+", "1.0+a..b", "1.0+a.", "1!",
    "!1.0", "a1", "1.0.0-", "1.0 1", "1.0xyz",
    # "1.0.1a-" is NOT refused: like "1.0a-" above, a separator after a label
    # with no number is accepted (it reads as 1.0.1a0). It sits here only so
    # the recorded vector order stays unchanged.
    "1.0.1a-",
    "vv1.0", "1.0++a",
    "1.0.post1.post2", "1.0.dev1.dev2", "1.0a1a2", "1.0-a-b", "1.0+a b",
    "1,0", "١.٠", "1.0é", "1_0", "1.0.dev1.post1", "1.0.post1a1",
]


def order(a: Version, b: Version) -> int:
    return -1 if a < b else (1 if a > b else 0)


def main() -> None:
    if packaging.__version__ != PIN:
        sys.exit(f"expected packaging {PIN}, got {packaging.__version__}")
    seen = set()
    inputs = []
    for item in INPUTS:
        if item in seen:
            sys.exit(f"duplicate input {item!r}")
        seen.add(item)
        inputs.append(item)
    parsed = []
    for item in inputs:
        try:
            parsed.append(Version(item))
        except InvalidVersion:
            parsed.append(None)
    pairs = []
    for i, a in enumerate(parsed):
        for j in range(i + 1, len(parsed)):
            b = parsed[j]
            if a is not None and b is not None:
                pairs.append([i, j, order(a, b)])
    out = {
        "generator": "packaging.version.Version",
        "packaging": PIN,
        "inputs": inputs,
        "normalized": [None if p is None else str(p) for p in parsed],
        "pairs": pairs,
    }
    lines = ["{"]
    lines.append(f'"generator": {json.dumps(out["generator"])},')
    lines.append(f'"packaging": {json.dumps(out["packaging"])},')
    lines.append('"inputs": [')
    lines.append(",\n".join(json.dumps(x, ensure_ascii=True) for x in out["inputs"]))
    lines.append("],")
    lines.append('"normalized": [')
    lines.append(",\n".join(json.dumps(x) for x in out["normalized"]))
    lines.append("],")
    lines.append('"pairs": [')
    lines.append(",\n".join(json.dumps(p) for p in out["pairs"]))
    lines.append("]")
    lines.append("}")
    sys.stdout.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
