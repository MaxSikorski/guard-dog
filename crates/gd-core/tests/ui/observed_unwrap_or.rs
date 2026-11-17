use gd_core::Observed;

fn main() {
    let seen: Observed<u8> = Observed::Seen(1);
    let _value = seen.unwrap_or(0);
}
