// A catalog file with a credential-shaped line fails the build itself: the embedded
// text is checked in a `const` assertion, with no test run. The token is assembled
// from pieces, so no full token is written down here.
const TEXT: &str = concat!(
    "format = 1\n# note: ",
    "gh",
    "p_",
    "a1B2a1B2a1B2a1B2a1B2a1B2a1B2a1B2a1B2a1B2",
    "\n"
);

const _: () = assert!(
    gd_core::catalog::raw_credential_line(TEXT) == 0,
    "credential-shaped line"
);

fn main() {}
