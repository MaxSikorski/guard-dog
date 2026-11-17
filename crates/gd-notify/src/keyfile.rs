//! Where Guard Dog's own key lives: `<state_dir>/notify.key`.
//!
//! Created on first use from the OS random generator, as hex, with
//! `create_new` and mode 0600. Reading refuses a symlink, anything that is not
//! a regular file, a file another user could read or write, and a state folder
//! that is not exactly 0700.

use crate::encoding::hex32;
use crate::{Entropy, Keys, NotifyError};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::Zeroizing;

/// The key file's name inside the state folder.
pub const KEY_FILE_NAME: &str = "notify.key";

fn refuse(message: &'static str) -> NotifyError {
    NotifyError::KeyFile(message)
}

/// Returns the folder's owner.
fn check_state_dir(dir: &Path) -> Result<u32, NotifyError> {
    let meta = fs::symlink_metadata(dir).map_err(|_| refuse("the state folder does not exist"))?;
    if !meta.file_type().is_dir() {
        return Err(refuse("the state folder is not a real folder (a symlink?)"));
    }
    if meta.permissions().mode() & 0o7777 != 0o700 {
        return Err(refuse("the state folder must have mode 0700"));
    }
    Ok(meta.uid())
}

/// The key file must belong to whoever owns the state folder.
fn owners_match(file_uid: u32, dir_uid: u32) -> bool {
    file_uid == dir_uid
}

fn read_key(path: &Path, dir_uid: u32) -> Result<Keys, NotifyError> {
    let before = fs::symlink_metadata(path).map_err(|_| refuse("cannot look at the key file"))?;
    if !before.file_type().is_file() {
        return Err(refuse("the key file is a symlink or not a regular file"));
    }
    if before.permissions().mode() & 0o7177 != 0 {
        return Err(refuse(
            "the key file must be readable and writable by its owner only (0600)",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| refuse("cannot open the key file"))?;
    // The file we opened must be the one we looked at.
    let after = file
        .metadata()
        .map_err(|_| refuse("cannot look at the key file"))?;
    if after.dev() != before.dev() || after.ino() != before.ino() || !after.file_type().is_file() {
        return Err(refuse("the key file changed while it was being opened"));
    }
    if !owners_match(after.uid(), dir_uid) {
        return Err(refuse(
            "the key file does not belong to the state folder's owner",
        ));
    }
    if after.permissions().mode() & 0o7177 != 0 {
        return Err(refuse(
            "the key file must be readable and writable by its owner only (0600)",
        ));
    }
    let mut text = Zeroizing::new(String::new());
    (&mut file)
        .take(129)
        .read_to_string(&mut text)
        .map_err(|_| refuse("the key file is not text"))?;
    let trimmed = text.strip_suffix('\n').unwrap_or(&text);
    // Re-checked as hex and as a valid key; the text is never echoed.
    hex32(trimmed).map_err(|_| refuse("the key file does not hold a key"))?;
    Keys::from_secret_hex(trimmed).map_err(|_| refuse("the key file does not hold a valid key"))
}

/// Reads Guard Dog's key, creating it on first use. `state_dir` must already
/// exist with mode 0700.
pub fn load_or_create(state_dir: &Path, entropy: &mut dyn Entropy) -> Result<Keys, NotifyError> {
    let dir_uid = check_state_dir(state_dir)?;
    let path = state_dir.join(KEY_FILE_NAME);
    match fs::symlink_metadata(&path) {
        Ok(_) => return read_key(&path, dir_uid),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(_) => return Err(refuse("cannot look at the key file")),
    }
    let keys = Keys::generate(entropy)?;
    let mut line = keys.secret_hex();
    line.push('\n');
    match write_new(&path, |file| {
        file.write_all(line.as_bytes())?;
        file.sync_all()
    }) {
        Ok(()) => Ok(keys),
        // Someone else created it a moment ago: use theirs, after the same checks.
        Err(e) if e.kind() == ErrorKind::AlreadyExists => read_key(&path, dir_uid),
        Err(_) => Err(refuse("cannot create the key file")),
    }
}

/// Creates the file (never over an existing one, mode 0600) and fills it with
/// `fill`. If filling fails, the half-written file is removed, so a later run
/// does not meet a broken key.
fn write_new(
    path: &Path,
    fill: impl FnOnce(&mut std::fs::File) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    if let Err(e) = fill(&mut file) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use super::*;
    use std::io;
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("gd-notify-kf-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        p
    }

    #[test]
    fn a_failed_write_leaves_no_key_file_behind() {
        let dir = temp_dir("partial");
        let path = dir.join(KEY_FILE_NAME);
        let result = write_new(&path, |file| {
            file.write_all(b"half a ke")?;
            Err(io::Error::other("disk full"))
        });
        assert!(result.is_err());
        assert!(!path.exists(), "a partial key file was left");
        // And the next run can create one normally.
        let keys = load_or_create(&dir, &mut crate::OsEntropy).unwrap();
        assert_eq!(keys.public_hex().len(), 64);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_failed_sync_is_also_cleaned_up() {
        let dir = temp_dir("sync");
        let path = dir.join(KEY_FILE_NAME);
        assert!(write_new(&path, |_| Err(io::Error::other("sync failed"))).is_err());
        assert!(!path.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_key_file_must_belong_to_the_same_user_as_the_folder() {
        assert!(owners_match(501, 501));
        assert!(!owners_match(0, 501));
        assert!(!owners_match(501, 0));
        // The real files we make belong to the folder's owner.
        let dir = temp_dir("owner");
        load_or_create(&dir, &mut crate::OsEntropy).unwrap();
        let d = fs::metadata(&dir).unwrap().uid();
        let f = fs::metadata(dir.join(KEY_FILE_NAME)).unwrap().uid();
        assert!(owners_match(f, d));
        fs::remove_dir_all(&dir).unwrap();
    }
}
