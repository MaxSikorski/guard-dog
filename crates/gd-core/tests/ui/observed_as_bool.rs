use gd_core::Observed;

fn main() {
    let seen: Observed<bool> = Observed::Seen(true);
    // An unknown must never read as true or false.
    if seen {
        println!("fine");
    }
}
