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

/// The key file's name inside the state folder.
pub const KEY_FILE_NAME: &str = "notify.key";

fn refuse(message: &'static str) -> NotifyError {
    NotifyError::KeyFile(message)
}

fn check_state_dir(dir: &Path) -> Result<(), NotifyError> {
    let meta = fs::symlink_metadata(dir).map_err(|_| refuse("the state folder does not exist"))?;
    if !meta.file_type().is_dir() {
        return Err(refuse("the state folder is not a real folder (a symlink?)"));
    }
    if meta.permissions().mode() & 0o7777 != 0o700 {
        return Err(refuse("the state folder must have mode 0700"));
    }
    Ok(())
}

fn read_key(path: &Path) -> Result<Keys, NotifyError> {
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
    if after.permissions().mode() & 0o7177 != 0 {
        return Err(refuse(
            "the key file must be readable and writable by its owner only (0600)",
        ));
    }
    let mut text = String::new();
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
    check_state_dir(state_dir)?;
    let path = state_dir.join(KEY_FILE_NAME);
    match fs::symlink_metadata(&path) {
        Ok(_) => return read_key(&path),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(_) => return Err(refuse("cannot look at the key file")),
    }
    let keys = Keys::generate(entropy)?;
    let created = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path);
    match created {
        Ok(mut file) => {
            let mut line = keys.secret_hex();
            line.push('\n');
            file.write_all(line.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|_| refuse("cannot write the key file"))?;
            Ok(keys)
        }
        // Someone else created it a moment ago: use theirs, after the same checks.
        Err(e) if e.kind() == ErrorKind::AlreadyExists => read_key(&path),
        Err(_) => Err(refuse("cannot create the key file")),
    }
}
