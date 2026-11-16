// The wrapped value is private, so it can't be read or matched directly.
use gd_core::Untrusted;

fn main() {
    let note = Untrusted::new(String::from("nostr note"));
    let _plain: &String = &note.0;
}
