// Untrusted text has no `Display`, so it can't be printed or formatted.
use gd_core::Untrusted;

fn main() {
    let name = Untrusted::new(String::from("relay name"));
    println!("{name}");
}
