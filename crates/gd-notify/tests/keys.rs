//! Guard Dog's own key pair and the file it lives in.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use common::SeqEntropy;
use gd_notify::Keys;
use gd_notify::keyfile::{KEY_FILE_NAME, load_or_create};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Dir {
        let p = std::env::temp_dir().join(format!("gd-notify-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        Dir(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

#[test]
fn first_use_creates_a_0600_key_and_later_use_reads_it() {
    let dir = Dir::new("create");
    let first = load_or_create(dir.path(), &mut SeqEntropy(1)).unwrap();
    let file = dir.path().join(KEY_FILE_NAME);
    assert_eq!(mode(&file), 0o600);
    let text = fs::read_to_string(&file).unwrap();
    assert_eq!(text.trim().len(), 64);
    // A second call with different entropy must read, not regenerate.
    let second = load_or_create(dir.path(), &mut SeqEntropy(2)).unwrap();
    assert_eq!(first.public_hex(), second.public_hex());
}

#[test]
fn a_symlinked_key_file_is_refused() {
    let dir = Dir::new("symlink");
    let other = dir.path().join("elsewhere");
    fs::write(&other, "11".repeat(32)).unwrap();
    fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&other, dir.path().join(KEY_FILE_NAME)).unwrap();
    assert!(load_or_create(dir.path(), &mut SeqEntropy(1)).is_err());
}

#[test]
fn a_key_file_that_is_not_a_regular_file_is_refused() {
    let dir = Dir::new("notregular");
    fs::create_dir(dir.path().join(KEY_FILE_NAME)).unwrap();
    assert!(load_or_create(dir.path(), &mut SeqEntropy(1)).is_err());
}

#[test]
fn a_key_file_with_group_or_other_bits_is_refused() {
    for bad in [0o640, 0o604, 0o660, 0o606, 0o644, 0o666, 0o601, 0o602, 0o610, 0o620] {
        let dir = Dir::new(&format!("mode{bad:o}"));
        load_or_create(dir.path(), &mut SeqEntropy(1)).unwrap();
        let file = dir.path().join(KEY_FILE_NAME);
        fs::set_permissions(&file, fs::Permissions::from_mode(bad)).unwrap();
        assert!(load_or_create(dir.path(), &mut SeqEntropy(1)).is_err(), "{bad:o}");
    }
}

#[test]
fn a_key_file_with_garbage_in_it_is_refused() {
    for content in ["", "not hex", &"zz".repeat(32), &"11".repeat(31), &"00".repeat(32)] {
        let dir = Dir::new("garbage");
        let file = dir.path().join(KEY_FILE_NAME);
        fs::write(&file, content).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_or_create(dir.path(), &mut SeqEntropy(1)).is_err(), "{content:?}");
    }
}

#[test]
fn a_state_dir_that_is_not_0700_is_refused() {
    for bad in [0o755, 0o750, 0o770, 0o701, 0o777, 0o500] {
        let dir = Dir::new(&format!("dirmode{bad:o}"));
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(bad)).unwrap();
        let result = load_or_create(dir.path(), &mut SeqEntropy(1));
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_err(), "{bad:o}");
    }
}

#[test]
fn a_missing_or_symlinked_state_dir_is_refused() {
    let dir = Dir::new("missing");
    assert!(load_or_create(&dir.path().join("nope"), &mut SeqEntropy(1)).is_err());
    let real = dir.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    let link = dir.path().join("link");
    symlink(&real, &link).unwrap();
    assert!(load_or_create(&link, &mut SeqEntropy(1)).is_err());
}

#[test]
fn nothing_secret_reaches_debug_or_error_text() {
    let secret = "1f".repeat(32);
    let keys = Keys::from_secret_hex(&secret).unwrap();
    let shown = format!("{keys:?} {keys:#?}");
    assert!(shown.contains("<redacted>"));
    assert!(!shown.contains(&secret));
    assert!(!shown.contains(&keys.public_hex()));
    // Error values for a bad key never echo the text they were given.
    let err = Keys::from_secret_hex(&"zz".repeat(32)).unwrap_err();
    let text = format!("{err} {err:?}");
    assert!(!text.contains("zz"));
}

#[test]
fn zero_and_out_of_range_secrets_are_refused() {
    assert!(Keys::from_secret_hex(&"00".repeat(32)).is_err());
    assert!(Keys::from_secret_hex(&"ff".repeat(32)).is_err());
    assert!(Keys::from_secret_hex("abcd").is_err());
}
