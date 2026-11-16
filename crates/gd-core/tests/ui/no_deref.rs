// No `Deref`: string methods aren't reachable through the wrapper.
use gd_core::Untrusted;

fn main() {
    let name = Untrusted::new(String::from("relay name"));
    let _length = name.len();
}
