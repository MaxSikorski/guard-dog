use gd_core::Observed;

fn main() {
    let seen: Observed<bool> = Observed::Seen(true);
    let _fine: bool = seen.into();
}
