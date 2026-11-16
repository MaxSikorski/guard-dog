// No `AsRef<str>`: it can't be passed where text is expected.
use gd_core::Untrusted;

fn run_with(_argument: impl AsRef<str>) {}

fn main() {
    let banner = Untrusted::new(String::from("service banner"));
    run_with(banner);
}
