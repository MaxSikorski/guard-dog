// No `==`: code can't branch on outside text without `expose_untrusted()`.
use gd_core::Untrusted;

fn main() {
    let label = Untrusted::new(String::from("container label"));
    if label == Untrusted::new(String::from("trusted")) {
        println!("treated as trusted");
    }
}
