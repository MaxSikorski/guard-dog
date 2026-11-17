use gd_core::Observed;

fn main() {
    // No default: "nothing seen" is a choice with a reason.
    let _nothing: Observed<u8> = Default::default();
}
