use gd_core::{CompleteSearch, Observed, Presence};

fn main() {
    // "Not there" needs a complete search; only `Presence::absent` makes the proof.
    let _absent: Observed<Presence> = Observed::Seen(Presence::Absent(CompleteSearch {
        coverage: gd_core::Coverage::Complete,
    }));
}
