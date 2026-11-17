use gd_core::PlainVersion;

fn main() {
    // Only `parse` makes one; a tuple-struct literal can't.
    let _version = PlainVersion("1.0; rm -rf /".to_owned());
}
