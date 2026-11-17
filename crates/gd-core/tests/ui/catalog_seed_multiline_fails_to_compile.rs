// A catalog file with a 12-word seed phrase pasted four words per line into a
// triple-quoted value fails the build itself: the seed rule runs over the whole text,
// newlines included. The words are the public test list, never a real phrase.
const TEXT: &str = concat!(
    "format = 1\nlicence = \"\"\"\n",
    "abandon ability able about\n",
    "above absent absorb abstract\n",
    "absurd abuse access accident\"\"\"\n"
);

const _: () = assert!(
    gd_core::catalog::raw_credential_line(TEXT) == 0,
    "credential-shaped line"
);

fn main() {}
