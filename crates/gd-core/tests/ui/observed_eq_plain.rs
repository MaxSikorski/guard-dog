use gd_core::Observed;

fn main() {
    let seen: Observed<u8> = Observed::Seen(1);
    let _same = seen == 1u8;
}
