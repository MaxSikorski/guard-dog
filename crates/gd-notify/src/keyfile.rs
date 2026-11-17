//! Where Guard Dog's own key lives: `<state_dir>/notify.key`.
//!
//! Created on first use from the OS random generator, as hex, with
//! `create_new` and mode 0600. Reading refuses a symlink, anything that is not
//! a regular file, a file another user could read or write, and a state folder
//! that is not exactly 0700. The folder and the file must both belong to the
//! user running Guard Dog, so a key planted by anyone else (root included) is
//! refused.

use crate::encoding::hex32_secret;
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

/// The user id this process runs as, read from a file we just made in the
/// folder (a new file belongs to the effective user), then removed. No extra
/// crate and no `unsafe`.
fn effective_uid(dir: &Path) -> Result<u32, NotifyError> {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let name = format!(
        ".notify-uid-probe-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let path = dir.join(name);
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|_| refuse("cannot write in the state folder"))?;
    let uid = file.metadata().map(|m| m.uid());
    drop(file);
    let _ = fs::remove_file(&path);
    uid.map_err(|_| refuse("cannot tell which user is running Guard Dog"))
}

/// The folder must be a real folder (not a symlink) with mode 0700. Checked
/// before anything is written in it.
fn check_state_dir_shape(dir: &Path) -> Result<fs::Metadata, NotifyError> {
    let meta = fs::symlink_metadata(dir).map_err(|_| refuse("the state folder does not exist"))?;
    if !meta.file_type().is_dir() {
        return Err(refuse("the state folder is not a real folder (a symlink?)"));
    }
    if meta.permissions().mode() & 0o7777 != 0o700 {
        return Err(refuse("the state folder must have mode 0700"));
    }
    Ok(meta)
}

/// The folder must be a real 0700 folder owned by `euid`.
fn check_state_dir(dir: &Path, euid: u32) -> Result<(), NotifyError> {
    let meta = check_state_dir_shape(dir)?;
    if meta.uid() != euid {
        return Err(refuse(
            "the state folder does not belong to the user running Guard Dog",
        ));
    }
    Ok(())
}

/// The key file must belong to the user running Guard Dog.
fn owners_match(file_uid: u32, euid: u32) -> bool {
    file_uid == euid
}

fn read_key(path: &Path, euid: u32) -> Result<Keys, NotifyError> {
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
    if !owners_match(after.uid(), euid) {
        return Err(refuse(
            "the key file does not belong to the user running Guard Dog",
        ));
    }
    if after.permissions().mode() & 0o7177 != 0 {
        return Err(refuse(
            "the key file must be readable and writable by its owner only (0600)",
        ));
    }
    // A fixed wiped buffer, never a growing string: 64 hex characters, an
    // optional newline, and one byte more to notice a file that is too long.
    let mut buf = Zeroizing::new([0u8; 66]);
    let mut len = 0usize;
    while len < buf.len() {
        let room = buf
            .get_mut(len..)
            .ok_or(refuse("the key file is not text"))?;
        match file.read(room) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(refuse("the key file is not text")),
        }
    }
    let text = buf.get(..len).ok_or(refuse("the key file is not text"))?;
    let text = text.strip_suffix(b"\n").unwrap_or(text);
    let text = std::str::from_utf8(text).map_err(|_| refuse("the key file is not text"))?;
    // Decoded once, into a wiped buffer; the text is never echoed.
    let bytes = hex32_secret(text).map_err(|_| refuse("the key file does not hold a key"))?;
    Keys::from_secret_bytes(&bytes).map_err(|_| refuse("the key file does not hold a valid key"))
}

/// Reads Guard Dog's key, creating it on first use. `state_dir` must already
/// exist with mode 0700 and belong to the user running Guard Dog.
pub fn load_or_create(state_dir: &Path, entropy: &mut dyn Entropy) -> Result<Keys, NotifyError> {
    // Nothing is written until the folder is known to be a real 0700 folder, so
    // a symlink or a loose folder is refused without touching its target.
    check_state_dir_shape(state_dir)?;
    let euid = effective_uid(state_dir)?;
    load_or_create_as(state_dir, entropy, euid)
}

/// [`load_or_create`] with the expected owner given (tests pass a wrong one).
fn load_or_create_as(
    state_dir: &Path,
    entropy: &mut dyn Entropy,
    euid: u32,
) -> Result<Keys, NotifyError> {
    check_state_dir(state_dir, euid)?;
    let path = state_dir.join(KEY_FILE_NAME);
    match fs::symlink_metadata(&path) {
        Ok(_) => return read_key(&path, euid),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(_) => return Err(refuse("cannot look at the key file")),
    }
    remove_stale_temporaries(state_dir);
    let keys = Keys::generate(entropy)?;
    let mut line = keys.secret_hex();
    line.push('\n');
    // The key is written and synced in a private temporary file first, then
    // installed under its real name with a hard link, which fails if a key is
    // already there. So `notify.key` is never seen empty or half written, and
    // two first uses at once end with one key.
    let temporary = state_dir.join(format!(
        "{TEMP_PREFIX}{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    write_new(&temporary, |file| {
        file.write_all(line.as_bytes())?;
        file.sync_all()
    })
    .map_err(|_| refuse("cannot create the key file"))?;
    let linked = fs::hard_link(&temporary, &path);
    let _ = fs::remove_file(&temporary);
    match linked {
        Ok(()) => {
            // Make the new directory entry durable too.
            fs::File::open(state_dir)
                .and_then(|d| d.sync_all())
                .map_err(|_| refuse("cannot save the key file's folder entry"))?;
            Ok(keys)
        }
        // Someone else installed a key a moment ago: use theirs, after the same checks.
        Err(e) if e.kind() == ErrorKind::AlreadyExists => read_key(&path, euid),
        Err(_) => Err(refuse("cannot create the key file")),
    }
}

const TEMP_PREFIX: &str = ".notify-key-tmp-";
static TEMP_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
/// A temporary this old is from a run that was killed; a live run needs
/// milliseconds.
const STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(60);

/// Removes temporaries left by a killed run. They are never read as the key
/// (only `notify.key` is), this just tidies the folder.
fn remove_stale_temporaries(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(TEMP_PREFIX) {
            continue;
        }
        let old = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= STALE_AFTER);
        if old {
            let _ = fs::remove_file(entry.path());
        }
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
        assert_eq!(keys.public_hex().unwrap().len(), 64);
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
    fn the_running_user_is_found_without_leaving_a_trace() {
        let dir = temp_dir("euid");
        let euid = effective_uid(&dir).unwrap();
        // A file we make ourselves belongs to the same user.
        let mine = dir.join("mine");
        fs::write(&mine, b"x").unwrap();
        assert_eq!(fs::metadata(&mine).unwrap().uid(), euid);
        fs::remove_file(&mine).unwrap();
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0, "a probe was left");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_symlinked_state_folder_is_refused_before_anything_is_written_in_its_target() {
        use std::os::unix::fs::symlink;
        let base = temp_dir("symlink");
        // A target that cannot be written: if the owner probe ran first, the
        // refusal would be "cannot write", not the symlink refusal.
        let target = base.join("target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o500)).unwrap();
        let link = base.join("link");
        symlink(&target, &link).unwrap();
        let err = load_or_create(&link, &mut crate::OsEntropy).unwrap_err();
        assert!(
            matches!(err, NotifyError::KeyFile(m) if m.contains("symlink")),
            "{err}"
        );
        assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
        // And a loose folder is refused for its mode, again before any write.
        let loose = base.join("loose");
        fs::create_dir(&loose).unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o755)).unwrap();
        let err = load_or_create(&loose, &mut crate::OsEntropy).unwrap_err();
        assert!(matches!(err, NotifyError::KeyFile(m) if m.contains("0700")));
        assert_eq!(fs::read_dir(&loose).unwrap().count(), 0);
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn two_first_uses_at_once_end_with_the_same_key_and_no_empty_file() {
        for round in 0..20 {
            let dir = temp_dir(&format!("race{round}"));
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let dir = dir.clone();
                    std::thread::spawn(move || {
                        load_or_create(&dir, &mut crate::OsEntropy)
                            .unwrap()
                            .public_hex()
                            .unwrap()
                    })
                })
                .collect();
            let seen: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            assert!(seen.iter().all(|k| k == &seen[0]), "different keys");
            let path = dir.join(KEY_FILE_NAME);
            assert_eq!(fs::metadata(&path).unwrap().len(), 65, "not a whole key");
            // The key on disk is the one every caller got, and nothing else is left.
            assert_eq!(
                read_key(&path, effective_uid(&dir).unwrap())
                    .unwrap()
                    .public_hex()
                    .unwrap(),
                seen[0]
            );
            let names: Vec<_> = fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().file_name())
                .collect();
            assert_eq!(names.len(), 1, "{names:?}");
            fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn a_stale_temporary_from_a_killed_run_is_removed_and_never_read_as_the_key() {
        let dir = temp_dir("stale");
        let stale = dir.join(format!("{TEMP_PREFIX}99999-0"));
        // A complete, valid-looking key in a temporary: it must not become the key.
        fs::write(&stale, format!("{}\n", "1f".repeat(32))).unwrap();
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o600)).unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        fs::File::options()
            .write(true)
            .open(&stale)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let keys = load_or_create(&dir, &mut crate::OsEntropy).unwrap();
        assert_ne!(
            keys.public_hex().unwrap(),
            Keys::from_secret_hex(&"1f".repeat(32))
                .unwrap()
                .public_hex()
                .unwrap()
        );
        assert!(!stale.exists(), "the stale temporary was left");
        assert!(dir.join(KEY_FILE_NAME).exists());
        // A fresh temporary (a live run's) is left alone.
        let fresh = dir.join(format!("{TEMP_PREFIX}99998-0"));
        fs::write(&fresh, b"x").unwrap();
        remove_stale_temporaries(&dir);
        assert!(fresh.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_key_file_that_is_too_long_or_not_hex_is_refused_from_the_fixed_buffer() {
        let dir = temp_dir("fixed");
        let euid = effective_uid(&dir).unwrap();
        let path = dir.join(KEY_FILE_NAME);
        for body in [
            "1f".repeat(32) + "\n\n",
            "1f".repeat(33),
            "1f".repeat(1000),
            "zz".repeat(32),
            String::new(),
        ] {
            fs::write(&path, &body).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(read_key(&path, euid).is_err());
        }
        // With and without the final newline, a good key is read.
        for body in ["1f".repeat(32), "1f".repeat(32) + "\n"] {
            fs::write(&path, &body).unwrap();
            assert!(read_key(&path, euid).is_ok());
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_key_file_or_folder_of_another_user_is_refused_on_the_read_path() {
        let dir = temp_dir("owner");
        let euid = effective_uid(&dir).unwrap();
        load_or_create(&dir, &mut crate::OsEntropy).unwrap();
        let path = dir.join(KEY_FILE_NAME);
        // Same user: read back fine, through the real read path.
        assert!(read_key(&path, euid).is_ok());
        assert!(load_or_create_as(&dir, &mut crate::OsEntropy, euid).is_ok());
        // Someone else is "the user": the existing key file is refused ...
        let other = euid.wrapping_add(1);
        assert!(matches!(
            read_key(&path, other),
            Err(NotifyError::KeyFile(m)) if m.contains("does not belong")
        ));
        // ... and so is the whole load, because the folder is not theirs either.
        assert!(matches!(
            load_or_create_as(&dir, &mut crate::OsEntropy, other),
            Err(NotifyError::KeyFile(_))
        ));
        assert!(owners_match(euid, euid) && !owners_match(0, 501));
        fs::remove_dir_all(&dir).unwrap();
    }
}
