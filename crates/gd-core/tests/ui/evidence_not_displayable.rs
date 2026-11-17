use gd_core::{CallId, Evidence};

fn main() {
    let call = CallId::parse("getnetworkinfo").unwrap_or_else(|_| std::process::abort());
    let evidence = Evidence::new(call, "raw reply");
    println!("{}", evidence.raw());
}
