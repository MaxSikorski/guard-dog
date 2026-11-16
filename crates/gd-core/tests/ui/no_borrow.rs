// No `Borrow<str>`: it can't be borrowed as plain text either.
use gd_core::Untrusted;
use std::borrow::Borrow;

fn main() {
    let name = Untrusted::new(String::from("relay name"));
    let _plain: &str = name.borrow();
}
