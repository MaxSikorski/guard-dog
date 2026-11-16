// No conversion back into the plain value.
use gd_core::Untrusted;

fn main() {
    let label = Untrusted::new(String::from("container label"));
    let _plain: String = label.into();
}
