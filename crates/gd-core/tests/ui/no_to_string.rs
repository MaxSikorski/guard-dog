// Without `Display` there is no `to_string()` either.
use gd_core::Untrusted;

fn main() {
    let name = Untrusted::new(String::from("relay name"));
    let _plain: String = name.to_string();
}
