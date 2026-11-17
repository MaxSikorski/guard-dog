//! Where Guard Dog's own key lives: `<state_dir>/notify.key`.
//!
//! Created on first use from the OS random generator, as hex, with
//! `create_new` and mode 0600. Reading refuses a symlink, anything that is not
//! a regular file, a file another user could read or write, and a state folder
//! that is not exactly 0700. The folder and the file must both belong to the
//! user running Guard Dog, so a key planted by anyone else (root included) is
//! refused.
//!
//! The folders above the state folder are walked the way OpenSSH's
//! `secure_path` does it: one name at a time from `/`, following each symlink
//! by hand (at most 40), and every folder passed through must belong to root
//! or the running user and not be open to others unless it is sticky. On
//! purpose, a state folder whose parents were made under umask 002 (mode
//! 0775, group-writable) is refused: another group member could swap it.
//!
//! Linux only. The entry points ([`load_or_create`]) refuse on every other
//! system with [`NotifyError::UnsupportedPlatform`], before touching the
//! filesystem. The reason is extended access lists. On Linux, POSIX ACL
//! entries are bounded by the group-class mask shown in the mode bits, so the
//! exact 0700 and 0600 checks leave no hidden grant, and that includes the
//! folders above the state folder, which are judged by owner and mode bits:
//! the mask covers them too. macOS and the BSDs have NFSv4-style extended ACLs
//! that the mode bits do not show (for example `everyone allow search`), and
//! Guard Dog cannot prove their absence without parsing another tool's
//! output, so those systems are refused. The helpers below (path text checks,
//! the walk, shape checks) still compile on every unix target, so their unit
//! tests run on a Mac too.
//!
//! The key store also needs a local filesystem. On a network or userspace
//! filesystem (NFS, SMB, FUSE, 9p, ZFS and the like) the server or driver
//! decides who may read a file, and the mode bits this module checks can be
//! only a local picture of that, so they prove nothing. Before anything is
//! written or read, the mount holding the state folder is found in
//! `/proc/self/mountinfo` and refused with [`NotifyError::NotLocalFilesystem`]
//! unless its type is ext2, ext3, ext4, xfs, btrfs, f2fs, tmpfs or overlay.
//! That table is read before the state path is looked at in any way, and every
//! mount on or above each path the walk will visit (links included) must be
//! local, so a network mount is never contacted. The chosen mount's
//! `major:minor` must equal the folder's `st_dev`, which refuses a mount hidden
//! by a later one and a bind-mounted key (the key file and temporary must share
//! the folder's device too). A btrfs subvolume, whose `st_dev` mountinfo does
//! not show, may be refused: fail safe.

use crate::encoding::{hex_encode, hex32_secret};
use crate::{Entropy, Keys, NotifyError};
use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// The key file's name inside the state folder.
pub const KEY_FILE_NAME: &str = "notify.key";

/// Filesystems where the kernel itself enforces the mode bits on this machine.
const LOCAL_FILESYSTEMS: [&[u8]; 8] = [
    b"ext2", b"ext3", b"ext4", b"xfs", b"btrfs", b"f2fs", b"tmpfs", b"overlay",
];

/// Undoes the octal escapes (`\040` for a space and so on) of a mountinfo field.
fn unescape_mount_field(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0;
    while let Some(&b) = field.get(i) {
        if b == b'\\'
            && let Some(digits) = field.get(i + 1..i + 4)
            && digits.iter().all(|d| (b'0'..=b'7').contains(d))
        {
            let value = digits
                .iter()
                .fold(0u32, |acc, d| acc * 8 + u32::from(d - b'0'));
            if let Ok(byte) = u8::try_from(value) {
                out.push(byte);
                i += 4;
                continue;
            }
        }
        out.push(b);
        i += 1;
    }
    out
}

/// Whether `mount` is `path` itself or a folder above it (whole names only).
fn mount_covers(mount: &[u8], path: &[u8]) -> bool {
    if mount == b"/" {
        return true;
    }
    path.starts_with(mount) && (path.len() == mount.len() || path.get(mount.len()) == Some(&b'/'))
}

/// One line of `/proc/self/mountinfo`, reduced to what is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Mount {
    /// The `major:minor` device number of the mounted filesystem.
    dev: (u32, u32),
    mount_point: Vec<u8>,
    fstype: Vec<u8>,
}

impl Mount {
    fn is_local(&self) -> bool {
        LOCAL_FILESYSTEMS.contains(&self.fstype.as_slice())
    }
}

/// Parses `major:minor` (decimal numbers).
fn parse_dev(field: &[u8]) -> Option<(u32, u32)> {
    let text = std::str::from_utf8(field).ok()?;
    let (major, minor) = text.split_once(':')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

/// Parses the text of `/proc/self/mountinfo`. Any malformed line makes the
/// whole text an error, so a damaged file is never half trusted. Pure, so it
/// is tested on every target.
fn parse_mountinfo(mountinfo: &[u8]) -> Result<Vec<Mount>, NotifyError> {
    let mut table = Vec::new();
    for line in mountinfo.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&[u8]> = line.split(|b| *b == b' ').collect();
        // id, parent, major:minor, root, mount point, options, [optional..], "-", type, source, super options
        let sep = fields
            .iter()
            .enumerate()
            .skip(6)
            .find(|(_, f)| **f == b"-")
            .map(|(i, _)| i)
            .ok_or(NotifyError::NotLocalFilesystem)?;
        let dev = fields
            .get(2)
            .and_then(|f| parse_dev(f))
            .ok_or(NotifyError::NotLocalFilesystem)?;
        let mount_field = fields.get(4).ok_or(NotifyError::NotLocalFilesystem)?;
        let fstype = fields
            .get(sep + 1)
            .filter(|t| !t.is_empty())
            .ok_or(NotifyError::NotLocalFilesystem)?;
        let mount_point = unescape_mount_field(mount_field);
        if mount_point.first() != Some(&b'/') {
            return Err(NotifyError::NotLocalFilesystem);
        }
        table.push(Mount {
            dev,
            mount_point,
            fstype: fstype.to_vec(),
        });
    }
    Ok(table)
}

/// The mount holding `path`: the one whose mount point is the longest
/// whole-name prefix of it (a later line wins a tie, as an over-mount does).
fn covering_mount<'a>(table: &'a [Mount], path: &Path) -> Option<&'a Mount> {
    let path = path.as_os_str().as_bytes();
    let mut best: Option<&Mount> = None;
    for m in table {
        if mount_covers(&m.mount_point, path)
            && best.is_none_or(|b| m.mount_point.len() >= b.mount_point.len())
        {
            best = Some(m);
        }
    }
    best
}

/// Refuses when ANY mount whose mount point equals or is a folder above `path`
/// is not a local filesystem. Pure text, no file access: the walk calls it for
/// each name before it looks at that name, so a network mount is never
/// contacted, not even by a `stat`.
fn check_not_remote(table: &[Mount], path: &Path) -> Result<(), NotifyError> {
    let bytes = path.as_os_str().as_bytes();
    if table
        .iter()
        .any(|m| mount_covers(&m.mount_point, bytes) && !m.is_local())
    {
        return Err(NotifyError::NotLocalFilesystem);
    }
    Ok(())
}

/// Splits a `st_dev` into the `(major, minor)` of Linux (glibc's
/// `gnu_dev_major` and `gnu_dev_minor`), the numbers mountinfo shows.
fn split_dev(dev: u64) -> (u32, u32) {
    let major = ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xffff_f000);
    let minor = (dev & 0xff) | ((dev >> 12) & 0xffff_ff00);
    (
        u32::try_from(major).unwrap_or(u32::MAX),
        u32::try_from(minor).unwrap_or(u32::MAX),
    )
}

/// From a mount table and a canonical path, the mount holding it, which must
/// be local and must be the very filesystem the folder is on: its `major:minor`
/// has to equal the folder's `st_dev`. A mount laid over the longer one later
/// (a hidden mount) or a bind mount makes the two differ and is refused. A
/// btrfs subvolume reports its own device number that mountinfo does not
/// show, so such a folder may be refused too; that is on purpose (fail safe).
fn check_mount_of(table: &[Mount], path: &Path, st_dev: u64) -> Result<(), NotifyError> {
    check_not_remote(table, path)?;
    let mount = covering_mount(table, path).ok_or(NotifyError::NotLocalFilesystem)?;
    if !mount.is_local() || mount.dev != split_dev(st_dev) {
        return Err(NotifyError::NotLocalFilesystem);
    }
    Ok(())
}

/// The mount table of this machine. Off Linux it is empty (the public entry
/// point refuses there before any file is touched; the helpers still run in
/// tests).
fn read_mount_table() -> Result<Vec<Mount>, NotifyError> {
    if cfg!(not(target_os = "linux")) {
        return Ok(Vec::new());
    }
    let text = fs::read("/proc/self/mountinfo").map_err(|_| NotifyError::NotLocalFilesystem)?;
    parse_mountinfo(&text)
}

/// Refuses unless the folder is on one of the local filesystems in
/// [`LOCAL_FILESYSTEMS`] and on the very filesystem mountinfo says holds it.
/// Linux only: elsewhere it refuses outright.
fn check_local_filesystem(state_dir: &Path) -> Result<(), NotifyError> {
    if cfg!(not(target_os = "linux")) {
        return Err(NotifyError::UnsupportedPlatform);
    }
    let table = read_mount_table()?;
    // The path as given, before anything is looked at.
    check_not_remote(&table, state_dir)?;
    let real = fs::canonicalize(state_dir).map_err(|_| NotifyError::NotLocalFilesystem)?;
    let st_dev = fs::metadata(&real)
        .map_err(|_| NotifyError::NotLocalFilesystem)?
        .dev();
    check_mount_of(&table, &real, st_dev)
}

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

/// The folder must be a real 0700 folder owned by `euid`. Returns its metadata,
/// so the caller can remember which folder was checked.
fn check_state_dir(dir: &Path, euid: u32) -> Result<fs::Metadata, NotifyError> {
    let meta = check_state_dir_shape(dir)?;
    if meta.uid() != euid {
        return Err(refuse(
            "the state folder does not belong to the user running Guard Dog",
        ));
    }
    Ok(meta)
}

const ABOVE_UNREADABLE: &str = "cannot look at a folder above the state folder";
const BAD_PATH: &str =
    "the state folder must be an absolute path without ., .. or a trailing slash";
/// The most symlinks followed on the way to the state folder.
const MAX_LINK_HOPS: u32 = 40;

/// The state path, as raw bytes, must be absolute, must not end in `/` (other
/// than `/` itself) and must have no `.` or `..` segment. Checked on the bytes,
/// not on `Path::components`, which quietly drops a trailing `/` and `/.`
/// and so would hide exactly the forms that make a symlink look like a folder.
fn check_path_text(dir: &Path) -> Result<(), NotifyError> {
    let bytes = dir.as_os_str().as_bytes();
    if bytes.first() != Some(&b'/') || (bytes.len() > 1 && bytes.last() == Some(&b'/')) {
        return Err(refuse(BAD_PATH));
    }
    if bytes.split(|b| *b == b'/').any(|s| s == b"." || s == b"..") {
        return Err(refuse(BAD_PATH));
    }
    Ok(())
}

/// The non-empty names in a path, in order.
fn segments(path: &OsStr) -> VecDeque<OsString> {
    path.as_bytes()
        .split(|b| *b == b'/')
        .filter(|s| !s.is_empty())
        .map(|s| OsString::from_vec(s.to_vec()))
        .collect()
}

/// A folder we pass through on the way down: it must belong to root or the
/// running user, and must not be writable by group or others unless sticky.
fn check_passed_dir(m: &fs::Metadata, euid: u32) -> Result<(), NotifyError> {
    if m.uid() != 0 && m.uid() != euid {
        return Err(refuse(
            "a folder above the state folder belongs to another user",
        ));
    }
    if m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0 {
        return Err(refuse(
            "a folder above the state folder can be changed by other users",
        ));
    }
    Ok(())
}

/// Walks to the state folder like OpenSSH's `secure_path`: from `/`, one name
/// at a time, `lstat` on each. A symlink is read and its target spliced in
/// front of the names still to come (a relative target starts at the folder
/// that holds the link, an absolute one at `/`), at most 40 times. Before each
/// name (and before `/`) is looked at, its path is checked against the mount
/// `table`: a network or userspace mount on the way is refused before it is
/// touched, so no `lstat` ever reaches it. `lstat` is passed in so a test can
/// see which paths were looked at. `on_dir` sees every folder passed through
/// and `on_link` every link.
fn walk_path(
    dir: &Path,
    table: &[Mount],
    lstat: &mut dyn FnMut(&Path) -> std::io::Result<fs::Metadata>,
    on_dir: &mut dyn FnMut(&fs::Metadata) -> Result<(), NotifyError>,
    on_link: &mut dyn FnMut(&fs::Metadata) -> Result<(), NotifyError>,
) -> Result<(), NotifyError> {
    check_path_text(dir)?;
    let mut current = PathBuf::from("/");
    check_not_remote(table, &current)?;
    let root = lstat(&current).map_err(|_| refuse(ABOVE_UNREADABLE))?;
    on_dir(&root)?;
    let mut rest = segments(dir.as_os_str());
    let mut hops = 0u32;
    while let Some(name) = rest.pop_front() {
        if name == "." {
            continue;
        }
        if name == ".." {
            // Only a link's target can hold this; `current` is already real.
            current.pop();
            continue;
        }
        let next = current.join(&name);
        // Before the path is touched; this covers a link's target too, since
        // its names are walked one by one like any others.
        check_not_remote(table, &next)?;
        let m = lstat(&next).map_err(|_| refuse(ABOVE_UNREADABLE))?;
        if m.file_type().is_symlink() {
            on_link(&m)?;
            hops += 1;
            if hops > MAX_LINK_HOPS {
                return Err(refuse("too many symlinks on the way to the state folder"));
            }
            let target = fs::read_link(&next).map_err(|_| refuse(ABOVE_UNREADABLE))?;
            if target.is_absolute() {
                current = PathBuf::from("/");
            }
            for part in segments(target.as_os_str()).into_iter().rev() {
                rest.push_front(part);
            }
        } else if m.file_type().is_dir() {
            on_dir(&m)?;
            current = next;
        } else {
            return Err(refuse(ABOVE_UNREADABLE));
        }
    }
    Ok(())
}

/// The walk without any network contact and without any owner check: every
/// path it will look at is first checked against the mount table. Run before
/// the state path is looked at in any other way.
fn check_no_remote_on_the_way(dir: &Path, table: &[Mount]) -> Result<(), NotifyError> {
    walk_path(
        dir,
        table,
        &mut |p| fs::symlink_metadata(p),
        &mut |_| Ok(()),
        &mut |_| Ok(()),
    )
}

/// The walk with its owner and writability checks. Every folder passed
/// through, including the ones reached through links and the folder holding
/// each link, must belong to root or the running user and not be writable by
/// others unless sticky; so must each link's owner. Otherwise someone else
/// could rename something in the chain and swap the state folder for another
/// one. A sticky folder such as `/tmp` is fine because only an entry's owner
/// can rename it there, and every entry below it is checked.
fn check_ancestors(dir: &Path, euid: u32) -> Result<(), NotifyError> {
    let table = read_mount_table()?;
    walk_path(
        dir,
        &table,
        &mut |p| fs::symlink_metadata(p),
        &mut |m| check_passed_dir(m, euid),
        &mut |m| {
            if m.uid() != 0 && m.uid() != euid {
                return Err(refuse(
                    "a folder above the state folder belongs to another user",
                ));
            }
            Ok(())
        },
    )
}

const DIR_CHANGED_INSTALL: &str = "the state folder changed while the key was being installed";
const DIR_CHANGED_READ: &str = "the state folder changed while the key was being read";

/// The folder at `dir` must still be the same directory (device and inode) as
/// the one that was checked.
fn same_dir(dir: &Path, dir_id: (u64, u64), message: &'static str) -> Result<(), NotifyError> {
    let m = fs::symlink_metadata(dir).map_err(|_| refuse(message))?;
    if !m.file_type().is_dir() || (m.dev(), m.ino()) != dir_id {
        return Err(refuse(message));
    }
    Ok(())
}

/// After linking: the folder we sync is the one we checked, the key name holds
/// our own temporary's file, and the folder is still the same one.
fn verify_installed(
    dir: &Path,
    dir_id: (u64, u64),
    temp_id: (u64, u64),
) -> Result<(), NotifyError> {
    let d = fs::File::open(dir).map_err(|_| refuse("cannot save the key file's folder entry"))?;
    let dm = d
        .metadata()
        .map_err(|_| refuse("cannot save the key file's folder entry"))?;
    if (dm.dev(), dm.ino()) != dir_id {
        return Err(refuse(DIR_CHANGED_INSTALL));
    }
    d.sync_all()
        .map_err(|_| refuse("cannot save the key file's folder entry"))?;
    let k =
        fs::symlink_metadata(dir.join(KEY_FILE_NAME)).map_err(|_| refuse(DIR_CHANGED_INSTALL))?;
    if !k.file_type().is_file() || (k.dev(), k.ino()) != temp_id {
        return Err(refuse(DIR_CHANGED_INSTALL));
    }
    same_dir(dir, dir_id, DIR_CHANGED_INSTALL)
}

/// The key file must belong to the user running Guard Dog.
fn owners_match(file_uid: u32, euid: u32) -> bool {
    file_uid == euid
}

fn read_key(path: &Path, euid: u32, dir_dev: u64) -> Result<Keys, NotifyError> {
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
    // A key file on another filesystem than its folder is a bind mount laid
    // over it: whoever controls that mount controls the key.
    if after.dev() != dir_dev {
        return Err(refuse(
            "the key file is on a different filesystem than the state folder",
        ));
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
/// exist with mode 0700 and belong to the user running Guard Dog, and must be
/// an absolute path whose folders above it are not open to other users.
pub fn load_or_create(state_dir: &Path, entropy: &mut dyn Entropy) -> Result<Keys, NotifyError> {
    // Linux only (see the module doc); nothing is touched before this.
    if cfg!(not(target_os = "linux")) {
        return Err(NotifyError::UnsupportedPlatform);
    }
    // The raw text first: `link/` and `link/.` would make `symlink_metadata`
    // follow a symlink and report a folder.
    check_path_text(state_dir)?;
    // Before ANY look at the path (stat, lstat or canonicalize): read the mount
    // table once and walk the path, and every link target on the way, as text
    // against it. A network or userspace mount is refused without being
    // contacted.
    let table = read_mount_table()?;
    check_no_remote_on_the_way(state_dir, &table)?;
    // Nothing is written until the folder is known to be a real 0700 folder, so
    // a symlink or a loose folder is refused without touching its target.
    check_state_dir_shape(state_dir)?;
    // A network or userspace filesystem is refused before the probe writes.
    check_local_filesystem(state_dir)?;
    // The ancestor check needs the user id, so the probe writes first: it is
    // created `create_new` with mode 0600 and removed straight away.
    let euid = effective_uid(state_dir)?;
    load_or_create_as(state_dir, entropy, euid)
}

/// [`load_or_create`] with the expected owner given (tests pass a wrong one).
fn load_or_create_as(
    state_dir: &Path,
    entropy: &mut dyn Entropy,
    euid: u32,
) -> Result<Keys, NotifyError> {
    if cfg!(not(target_os = "linux")) {
        return Err(NotifyError::UnsupportedPlatform);
    }
    let meta = check_state_dir(state_dir, euid)?;
    let dir_id = (meta.dev(), meta.ino());
    check_ancestors(state_dir, euid)?;
    // Real folder identity (after symlinks) must be the one just checked.
    let real_meta =
        fs::metadata(fs::canonicalize(state_dir).map_err(|_| refuse(ABOVE_UNREADABLE))?)
            .map_err(|_| refuse(ABOVE_UNREADABLE))?;
    if (real_meta.dev(), real_meta.ino()) != dir_id {
        return Err(refuse(
            "the state folder changed while it was being checked",
        ));
    }
    // Again after the walk, on the folder the walk ended at.
    check_local_filesystem(state_dir)?;
    let path = state_dir.join(KEY_FILE_NAME);
    let key_exists = match fs::symlink_metadata(&path) {
        Ok(_) => true,
        Err(e) if e.kind() == ErrorKind::NotFound => false,
        Err(_) => return Err(refuse("cannot look at the key file")),
    };
    remove_stale_temporaries(state_dir);
    if key_exists {
        return read_existing(&path, euid, state_dir, dir_id);
    }
    let keys = Keys::generate(entropy)?;
    // 64 hex characters and a newline, in a buffer made 65 long up front, so
    // adding the newline never reallocates (a reallocation would leave a copy
    // of the secret behind, unwiped). `Zeroizing` wipes it on drop.
    let mut line = Zeroizing::new(String::with_capacity(65));
    line.push_str(&keys.secret_hex());
    line.push('\n');
    let mut suffix = [0u8; TEMP_SUFFIX_BYTES];
    // The key is written and synced in a private temporary file first, then
    // installed under its real name with a hard link, which fails if a key is
    // already there. So `notify.key` is never seen empty or half written, and
    // two first uses at once end with one key.
    let (temporary, file) = create_temporary(
        state_dir,
        dir_id.0,
        || {
            entropy.fill(&mut suffix)?;
            Ok(format!("{TEMP_PREFIX}{}", hex_encode(&suffix)))
        },
        line.as_bytes(),
    )?;
    let temp_meta = file
        .metadata()
        .map_err(|_| refuse("cannot create the key file"))?;
    let temp_id = (temp_meta.dev(), temp_meta.ino());
    if let Err(e) = same_dir(state_dir, dir_id, DIR_CHANGED_INSTALL) {
        let _ = fs::remove_file(&temporary);
        return Err(e);
    }
    let linked = fs::hard_link(&temporary, &path);
    let _ = fs::remove_file(&temporary);
    match linked {
        // On a refusal here nothing is removed: we no longer know which
        // folder we would be removing from.
        Ok(()) => {
            verify_installed(state_dir, dir_id, temp_id)?;
            Ok(keys)
        }
        // Someone else installed a key a moment ago: use theirs, after the same checks.
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            read_existing(&path, euid, state_dir, dir_id)
        }
        Err(_) => Err(refuse("cannot create the key file")),
    }
}

/// Reads the key, then confirms the folder was not swapped meanwhile.
fn read_existing(
    path: &Path,
    euid: u32,
    state_dir: &Path,
    dir_id: (u64, u64),
) -> Result<Keys, NotifyError> {
    let keys = read_key(path, euid, dir_id.0)?;
    same_dir(state_dir, dir_id, DIR_CHANGED_READ)?;
    Ok(keys)
}

const TEMP_PREFIX: &str = ".notify-key-tmp-";
/// A temporary this old is from a run that was killed; a live run needs
/// milliseconds. The age is wall-clock time against the file's mtime. If the
/// clock jumps forward, a live temporary can look stale and be removed; that
/// run's hard link then fails with `NotFound` and returns an error, never a
/// wrong key. If the clock jumps back, cleanup just waits. Both fail safe.
const STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(60);

/// Bytes of randomness in a temporary's name (shown as twice as many hex
/// characters).
const TEMP_SUFFIX_BYTES: usize = 8;

/// True only for the exact shape Guard Dog makes: the prefix, then
/// `TEMP_SUFFIX_BYTES * 2` lowercase hex characters and nothing else. A file
/// such as `.notify-key-tmp-backup` is somebody else's and is never removed.
fn is_temp_name(name: &OsStr) -> bool {
    name.as_bytes()
        .strip_prefix(TEMP_PREFIX.as_bytes())
        .is_some_and(|s| {
            s.len() == TEMP_SUFFIX_BYTES * 2
                && s.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// Removes temporaries left by a killed run, on every run. A temporary from a
/// run killed between link and unlink is a second name for the key file, and
/// removing it removes that name. It is never read as the key (only
/// `notify.key` is).
fn remove_stale_temporaries(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !is_temp_name(&name) {
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

/// Creates a temporary (never over an existing file, mode 0600) holding
/// `contents`, trying up to 4 names; a taken name moves on to the next.
fn create_temporary(
    dir: &Path,
    dir_dev: u64,
    mut next_name: impl FnMut() -> Result<String, NotifyError>,
    contents: &[u8],
) -> Result<(PathBuf, fs::File), NotifyError> {
    for _ in 0..4 {
        let path = dir.join(next_name()?);
        match write_new(&path, dir_dev, |file| {
            file.write_all(contents)?;
            file.sync_all()
        }) {
            Ok(file) => return Ok((path, file)),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
            Err(_) => break,
        }
    }
    Err(refuse("cannot create the key file"))
}

/// Creates the file (never over an existing one, mode 0600) and fills it with
/// `fill`. If filling fails, the half-written file is removed, so a later run
/// does not meet a broken key. Returns the open file.
fn write_new(
    path: &Path,
    dir_dev: u64,
    fill: impl FnOnce(&mut std::fs::File) -> std::io::Result<()>,
) -> std::io::Result<fs::File> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    // The new file must be on the state folder's own filesystem, and its mode
    // is set to 0600 explicitly (a strict umask such as 0400 would have taken
    // bits off the mode given to `open`), both before anything is written.
    let ready = file.metadata().and_then(|m| {
        if m.dev() == dir_dev {
            file.set_permissions(fs::Permissions::from_mode(0o600))
        } else {
            Err(std::io::Error::other("different filesystem"))
        }
    });
    if let Err(e) = ready.and_then(|()| fill(&mut file)) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(e);
    }
    Ok(file)
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

    const MOUNTINFO: &str = "\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
30 22 0:27 / /srv/nfs rw,relatime shared:5 - nfs4 host:/export rw,vers=4.2
31 30 0:28 / /srv/nfs/local rw,relatime - xfs /dev/sdb1 rw
32 22 0:29 / /mnt/share rw,relatime - cifs //host/share rw
33 22 0:30 / /mnt/my\\040disk rw,relatime - btrfs /dev/sdc1 rw
";

    fn fstype(text: &str, path: &str) -> Result<String, NotifyError> {
        let table = parse_mountinfo(text.as_bytes())?;
        covering_mount(&table, Path::new(path))
            .map(|m| String::from_utf8(m.fstype.clone()).unwrap())
            .ok_or(NotifyError::NotLocalFilesystem)
    }

    /// The `st_dev` of a folder, as `read_key` and `write_new` compare it.
    fn dev_of(p: &Path) -> u64 {
        fs::metadata(p).unwrap().dev()
    }

    #[test]
    fn mountinfo_gives_the_type_of_a_plain_ext4_root() {
        assert_eq!(fstype(MOUNTINFO, "/var/state").unwrap(), "ext4");
    }

    #[test]
    fn mountinfo_gives_nfs4_and_cifs_which_are_not_allowed() {
        assert_eq!(fstype(MOUNTINFO, "/srv/nfs/state").unwrap(), "nfs4");
        assert_eq!(fstype(MOUNTINFO, "/mnt/share").unwrap(), "cifs");
        assert!(!LOCAL_FILESYSTEMS.contains(&b"nfs4".as_slice()));
        assert!(!LOCAL_FILESYSTEMS.contains(&b"cifs".as_slice()));
        assert!(!LOCAL_FILESYSTEMS.contains(&b"fuse.sshfs".as_slice()));
        assert!(LOCAL_FILESYSTEMS.contains(&b"overlay".as_slice()));
    }

    #[test]
    fn the_longest_mount_point_wins_for_nested_mounts() {
        assert_eq!(fstype(MOUNTINFO, "/srv/nfs/local/x").unwrap(), "xfs");
        assert_eq!(fstype(MOUNTINFO, "/srv/nfs/local").unwrap(), "xfs");
        // A name that only shares leading letters is not inside the mount.
        assert_eq!(fstype(MOUNTINFO, "/srv/nfs-other").unwrap(), "ext4");
    }

    #[test]
    fn an_escaped_space_in_a_mount_point_is_understood() {
        assert_eq!(fstype(MOUNTINFO, "/mnt/my disk/state").unwrap(), "btrfs");
    }

    #[test]
    fn malformed_mountinfo_is_an_error() {
        for text in [
            "",
            "garbage",
            "22 1 8:1 / / rw - ",
            "22 1 8:1 / / rw,relatime shared:1 ext4 /dev/sda1 rw",
            "22 1 8:1 / relative rw - ext4 /dev/sda1 rw",
        ] {
            assert_eq!(
                fstype(text, "/var/state"),
                Err(NotifyError::NotLocalFilesystem),
                "{text:?}"
            );
        }
        // No mount covers the path.
        assert_eq!(
            fstype("22 1 8:1 / /data rw - ext4 /dev/sda1 rw\n", "/var/state"),
            Err(NotifyError::NotLocalFilesystem)
        );
    }

    #[test]
    fn the_refusal_message_names_no_path() {
        let m = NotifyError::NotLocalFilesystem.to_string();
        assert!(m.contains("local disk") && !m.contains('/'));
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("gd-notify-kf-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        p
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_write_leaves_no_key_file_behind() {
        let dir = temp_dir("partial");
        let path = dir.join(KEY_FILE_NAME);
        let result = write_new(&path, dev_of(&dir), |file| {
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
        assert!(
            write_new(&path, dev_of(&dir), |_| Err(io::Error::other(
                "sync failed"
            )))
            .is_err()
        );
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

    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
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
                read_key(&path, effective_uid(&dir).unwrap(), dev_of(&dir))
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

    #[cfg(target_os = "linux")]
    #[test]
    fn a_stale_temporary_from_a_killed_run_is_removed_and_never_read_as_the_key() {
        let dir = temp_dir("stale");
        let stale = dir.join(format!("{TEMP_PREFIX}0123456789abcdef"));
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
        let fresh = dir.join(format!("{TEMP_PREFIX}fedcba9876543210"));
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
            assert!(read_key(&path, euid, dev_of(path.parent().unwrap())).is_err());
        }
        // With and without the final newline, a good key is read.
        for body in ["1f".repeat(32), "1f".repeat(32) + "\n"] {
            fs::write(&path, &body).unwrap();
            assert!(read_key(&path, euid, dev_of(path.parent().unwrap())).is_ok());
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_key_file_or_folder_of_another_user_is_refused_on_the_read_path() {
        let dir = temp_dir("owner");
        let euid = effective_uid(&dir).unwrap();
        load_or_create(&dir, &mut crate::OsEntropy).unwrap();
        let path = dir.join(KEY_FILE_NAME);
        // Same user: read back fine, through the real read path.
        assert!(read_key(&path, euid, dev_of(path.parent().unwrap())).is_ok());
        assert!(load_or_create_as(&dir, &mut crate::OsEntropy, euid).is_ok());
        // Someone else is "the user": the existing key file is refused ...
        let other = euid.wrapping_add(1);
        assert!(matches!(
            read_key(&path, other, dev_of(path.parent().unwrap())),
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

    fn id_of(p: &Path) -> (u64, u64) {
        let m = fs::metadata(p).unwrap();
        (m.dev(), m.ino())
    }

    /// A 0777 folder (not sticky) above the state folder, reached through a
    /// symlink, so the walk has to follow the link by hand to find it.
    fn open_folder_behind_a_link(name: &str) -> (PathBuf, PathBuf, PathBuf) {
        use std::os::unix::fs::symlink;
        let base = temp_dir(name);
        let open = base.join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        let state = open.join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let link = base.join("link");
        symlink(&open, &link).unwrap();
        (base, open, link.join("state"))
    }

    #[test]
    fn the_walk_refuses_a_folder_above_that_others_can_write_even_behind_a_link() {
        let (base, open, through) = open_folder_behind_a_link("anc0");
        let euid = effective_uid(&base).unwrap();
        let err = check_ancestors(&through, euid).unwrap_err();
        assert!(
            matches!(err, NotifyError::KeyFile(m) if m.contains("can be changed by other users")),
            "{err}"
        );
        fs::set_permissions(&open, fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(check_ancestors(&through, euid).is_ok());
        fs::set_permissions(&open, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(&base).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_folder_above_that_others_can_write_is_refused() {
        let (base, open, through) = open_folder_behind_a_link("anc");
        let state = open.join("state");
        let err = load_or_create(&through, &mut crate::OsEntropy).unwrap_err();
        assert!(
            matches!(err, NotifyError::KeyFile(m) if m.contains("can be changed by other users")),
            "{err}"
        );
        assert_eq!(fs::read_dir(&state).unwrap().count(), 0);
        fs::set_permissions(&open, fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(load_or_create(&through, &mut crate::OsEntropy).is_ok());
        fs::set_permissions(&open, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn only_guard_dogs_exact_temporary_name_is_ever_cleaned_up() {
        let dir = temp_dir("tempname");
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        let make = |name: String| {
            let p = dir.join(name);
            fs::write(&p, b"x").unwrap();
            fs::File::options()
                .write(true)
                .open(&p)
                .unwrap()
                .set_modified(old)
                .unwrap();
            p
        };
        let mine = make(format!("{TEMP_PREFIX}0123456789abcdef"));
        let others = [
            make(format!("{TEMP_PREFIX}backup")),
            make(format!("{TEMP_PREFIX}0123456789abcde")),
            make(format!("{TEMP_PREFIX}0123456789abcdef0")),
            make(format!("{TEMP_PREFIX}ABCDEF0123456789")),
            make(format!("{TEMP_PREFIX}0123456789abcdeg")),
            make(TEMP_PREFIX.to_owned()),
            make(format!("x{TEMP_PREFIX}0123456789abcdef")),
        ];
        remove_stale_temporaries(&dir);
        assert!(!mine.exists(), "Guard Dog's own old temporary was left");
        for p in &others {
            assert!(p.exists(), "removed a file that is not ours: {p:?}");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_folder_above_owned_by_another_user_is_refused() {
        let dir = temp_dir("anc2");
        let euid = effective_uid(&dir).unwrap();
        // As root every folder here is root's own, so there is no "other user".
        if euid == 0 {
            fs::remove_dir_all(&dir).unwrap();
            return;
        }
        // `dir` is the folder that "belongs to another user": the injected user
        // id is not ours, and the only folders above `inner` that are not root's
        // are `dir` and whatever holds it, so this never depends on TMPDIR
        // (a root-owned sticky /tmp passes, then `dir` is refused).
        let inner = dir.join("inner");
        fs::create_dir(&inner).unwrap();
        fs::set_permissions(&inner, fs::Permissions::from_mode(0o700)).unwrap();
        let err = check_ancestors(&inner, euid.wrapping_add(1)).unwrap_err();
        assert!(
            matches!(err, NotifyError::KeyFile(m) if m.contains("belongs to another user")),
            "{err}"
        );
        assert!(check_ancestors(&inner, euid).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_relative_or_dotted_state_path_is_refused() {
        let dir = temp_dir("anc3");
        let euid = effective_uid(&dir).unwrap();
        let shown = dir.display().to_string();
        for bad in [
            Path::new("rel/state").to_path_buf(),
            dir.join("x/../state"),
            dir.join("x/./state"),
            PathBuf::from(format!("{shown}/")),
            PathBuf::from(format!("{shown}/.")),
            PathBuf::from(format!("{shown}/..")),
            PathBuf::new(),
        ] {
            let err = check_ancestors(&bad, euid).unwrap_err();
            assert!(
                matches!(err, NotifyError::KeyFile(m) if m.contains("absolute path")),
                "{err}"
            );
        }
        assert!(check_path_text(Path::new("/")).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_symlink_that_looks_like_a_folder_by_its_spelling_is_refused() {
        use std::os::unix::fs::symlink;
        let base = temp_dir("spell");
        let real = base.join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let link = base.join("link");
        symlink(&real, &link).unwrap();
        let a = base.join("a");
        fs::create_dir(&a).unwrap();
        fs::set_permissions(&a, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&real, a.join("link")).unwrap();
        let shown = base.display().to_string();
        for bad in [
            format!("{shown}/link/"),
            format!("{shown}/link/."),
            format!("{shown}/a/./link"),
        ] {
            let err = load_or_create(Path::new(&bad), &mut crate::OsEntropy).unwrap_err();
            assert!(
                matches!(err, NotifyError::KeyFile(m) if m.contains("absolute path")),
                "{bad}: {err}"
            );
        }
        // Nothing was written in the folder behind the link.
        assert_eq!(fs::read_dir(&real).unwrap().count(), 0);
        fs::remove_dir_all(&base).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_symlink_inside_a_folder_others_can_write_is_refused() {
        use std::os::unix::fs::symlink;
        let base = temp_dir("l2");
        let real = base.join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let state = real.join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        // A 0777 folder that is not sticky holds the link: anyone could
        // replace `l2`, so the path through it is refused.
        let open = base.join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        symlink(&real, open.join("l2")).unwrap();
        let through = open.join("l2").join("state");
        let err = load_or_create(&through, &mut crate::OsEntropy).unwrap_err();
        assert!(
            matches!(err, NotifyError::KeyFile(m) if m.contains("can be changed by other users")),
            "{err}"
        );
        assert_eq!(fs::read_dir(&state).unwrap().count(), 0);
        fs::set_permissions(&open, fs::Permissions::from_mode(0o700)).unwrap();
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn forty_one_symlink_hops_are_refused_and_a_short_chain_is_followed() {
        use std::os::unix::fs::symlink;
        let base = temp_dir("hops");
        let euid = effective_uid(&base).unwrap();
        let real = base.join("real");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let state = real.join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        // l0 -> l1 -> ... -> l{n-1} -> real, each a relative link: n hops.
        let chain = |prefix: &str, n: usize| {
            for i in 0..n {
                let target = if i + 1 == n {
                    "real".to_owned()
                } else {
                    format!("{prefix}{}", i + 1)
                };
                symlink(target, base.join(format!("{prefix}{i}"))).unwrap();
            }
            base.join(format!("{prefix}0")).join("state")
        };
        let short = chain("s", 5);
        assert!(check_ancestors(&short, euid).is_ok());
        let long = chain("l", 41);
        let err = check_ancestors(&long, euid).unwrap_err();
        assert!(
            matches!(err, NotifyError::KeyFile(m) if m.contains("too many symlinks")),
            "{err}"
        );
        // Through the public entry point it is refused too, and nothing is
        // written. On Linux the kernel's own 40-link limit fails first, in the
        // shape check (`symlink_metadata` on the whole path).
        #[cfg(target_os = "linux")]
        {
            assert!(load_or_create(&long, &mut crate::OsEntropy).is_err());
            assert_eq!(fs::read_dir(&state).unwrap().count(), 0);
        }
        // A long chain under the limit is still followed (not 40: the temp
        // folder's own path may hold a link or two, as /var does on macOS).
        let thirty = chain("f", 30);
        assert!(check_ancestors(&thirty, euid).is_ok());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_swapped_folder_or_key_is_caught_after_linking() {
        let a = temp_dir("swapa");
        let b = temp_dir("swapb");
        let err = same_dir(&a, id_of(&b), DIR_CHANGED_INSTALL).unwrap_err();
        assert!(matches!(err, NotifyError::KeyFile(m) if m.contains("changed")));
        assert!(same_dir(&a, id_of(&a), DIR_CHANGED_INSTALL).is_ok());
        fs::write(a.join(KEY_FILE_NAME), b"x").unwrap();
        let key_id = id_of(&a.join(KEY_FILE_NAME));
        assert!(verify_installed(&a, id_of(&a), (0, 0)).is_err());
        assert!(verify_installed(&a, id_of(&b), key_id).is_err());
        assert!(verify_installed(&a, id_of(&a), key_id).is_ok());
        fs::remove_dir_all(&a).unwrap();
        fs::remove_dir_all(&b).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_stale_hard_link_to_an_installed_key_is_removed_on_the_read_path() {
        let dir = temp_dir("hardlink");
        let k = load_or_create(&dir, &mut crate::OsEntropy)
            .unwrap()
            .public_hex()
            .unwrap();
        let crashed = dir.join(format!("{TEMP_PREFIX}00ff00ff00ff00ff"));
        fs::hard_link(dir.join(KEY_FILE_NAME), &crashed).unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        fs::File::options()
            .write(true)
            .open(&crashed)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let again = load_or_create(&dir, &mut crate::OsEntropy)
            .unwrap()
            .public_hex()
            .unwrap();
        assert!(again == k, "a different key was returned");
        assert!(!crashed.exists(), "the stale name was left");
        let meta = fs::metadata(dir.join(KEY_FILE_NAME)).unwrap();
        assert_eq!(meta.nlink(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_taken_temporary_name_is_skipped() {
        let dir = temp_dir("taken");
        let aa = dir.join(format!("{TEMP_PREFIX}aa"));
        fs::write(&aa, "x").unwrap();
        let mut names = ["aa", "bb"].into_iter();
        let (path, _file) = create_temporary(
            &dir,
            dev_of(&dir),
            || Ok(format!("{TEMP_PREFIX}{}", names.next().unwrap())),
            b"contents",
        )
        .unwrap();
        assert!(path.ends_with(format!("{TEMP_PREFIX}bb")));
        assert_eq!(fs::read_to_string(&aa).unwrap(), "x");
        assert_eq!(fs::read_to_string(&path).unwrap(), "contents");
        // Four collisions in a row give up.
        let result = create_temporary(&dir, dev_of(&dir), || Ok(format!("{TEMP_PREFIX}aa")), b"y");
        assert!(result.is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn st_dev_is_split_into_major_and_minor_like_linux() {
        // glibc's makedev, written out, so the split is checked against it.
        fn makedev(major: u64, minor: u64) -> u64 {
            (minor & 0xff)
                | ((major & 0xfff) << 8)
                | ((minor & !0xff) << 12)
                | ((major & !0xfff) << 32)
        }
        assert_eq!(split_dev(0x0801), (8, 1));
        assert_eq!(split_dev(0), (0, 0));
        for (major, minor) in [(8, 1), (259, 3), (0, 27), (4095, 255), (0x1234, 0x5_6789)] {
            assert_eq!(
                split_dev(makedev(major, minor)),
                (major as u32, minor as u32)
            );
        }
        // 12-bit major and 20-bit minor fields reach into the high bits.
        assert_eq!(split_dev(makedev(0x12345, 0xabcde)), (0x12345, 0xabcde));
    }

    #[test]
    fn a_later_mount_hiding_the_longer_one_is_caught_by_the_device_check() {
        // The third line was mounted over `/a` after `/a/b`, so it hides
        // `/a/b`; the longest-prefix rule still picks `/a/b` (ext4, 8:2), but
        // the folder's real st_dev is that of the tmpfs on top (0:50).
        let text = "\
22 1 8:1 / / rw - ext4 /dev/sda1 rw
40 22 8:2 / /a rw - ext4 /dev/sda2 rw
41 40 8:3 / /a/b rw - ext4 /dev/sda3 rw
42 22 0:50 / /a rw - tmpfs tmpfs rw
";
        let table = parse_mountinfo(text.as_bytes()).unwrap();
        let path = Path::new("/a/b/state");
        assert_eq!(covering_mount(&table, path).unwrap().dev, (8, 3));
        // The device the folder really reports is the tmpfs's: refused.
        assert_eq!(
            check_mount_of(&table, path, 50),
            Err(NotifyError::NotLocalFilesystem)
        );
        // Were the folder really on /a/b's filesystem, it is accepted.
        assert_eq!(check_mount_of(&table, path, (8 << 8) | 3), Ok(()));
        // A mismatch alone refuses, even with a local type.
        assert_eq!(
            check_mount_of(&table, Path::new("/x"), (8 << 8) | 9),
            Err(NotifyError::NotLocalFilesystem)
        );
        // No bind-mount case is tested against a real kernel here.
    }

    #[test]
    fn any_remote_mount_on_or_above_a_path_refuses_it() {
        let table = parse_mountinfo(MOUNTINFO.as_bytes()).unwrap();
        assert!(check_not_remote(&table, Path::new("/var/state")).is_ok());
        for p in ["/srv/nfs", "/srv/nfs/state", "/mnt/share/x"] {
            assert_eq!(
                check_not_remote(&table, Path::new(p)),
                Err(NotifyError::NotLocalFilesystem),
                "{p}"
            );
        }
        // Stricter than the longest-prefix rule: an xfs mount inside the nfs one.
        assert!(check_not_remote(&table, Path::new("/srv/nfs/local/x")).is_err());
        // A folder above a network mount is not on it.
        assert!(check_not_remote(&table, Path::new("/srv")).is_ok());
    }

    #[test]
    fn the_walk_refuses_a_network_mount_before_it_is_looked_at() {
        let table = parse_mountinfo(
            "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n30 22 0:27 / /srv rw - nfs4 host:/e rw\n"
                .as_bytes(),
        )
        .unwrap();
        let mut seen: Vec<PathBuf> = Vec::new();
        let r = walk_path(
            Path::new("/srv/state"),
            &table,
            &mut |p| {
                seen.push(p.to_path_buf());
                fs::symlink_metadata("/")
            },
            &mut |_| Ok(()),
            &mut |_| Ok(()),
        );
        assert_eq!(r, Err(NotifyError::NotLocalFilesystem));
        // Only `/` was looked at; `/srv` and below never were.
        assert_eq!(seen, vec![PathBuf::from("/")]);
        // A network root is refused before even `/` is looked at.
        let table = parse_mountinfo(b"22 1 0:27 / / rw - nfs4 host:/e rw\n").unwrap();
        let mut calls = 0;
        let r = walk_path(
            Path::new("/state"),
            &table,
            &mut |_| {
                calls += 1;
                fs::symlink_metadata("/")
            },
            &mut |_| Ok(()),
            &mut |_| Ok(()),
        );
        assert_eq!(r, Err(NotifyError::NotLocalFilesystem));
        assert_eq!(calls, 0);
    }

    #[test]
    fn a_link_target_on_a_network_mount_is_refused_before_it_is_looked_at() {
        use std::os::unix::fs::symlink;
        let base = temp_dir("remote-link");
        symlink("/srv/elsewhere", base.join("l")).unwrap();
        let table = parse_mountinfo(
            "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n30 22 0:27 / /srv rw - nfs4 host:/e rw\n"
                .as_bytes(),
        )
        .unwrap();
        let mut seen: Vec<PathBuf> = Vec::new();
        let r = walk_path(
            &base.join("l").join("state"),
            &table,
            &mut |p| {
                seen.push(p.to_path_buf());
                fs::symlink_metadata(p)
            },
            &mut |_| Ok(()),
            &mut |_| Ok(()),
        );
        assert_eq!(r, Err(NotifyError::NotLocalFilesystem));
        assert!(seen.iter().all(|p| !p.starts_with("/srv")), "{seen:?}");
        assert!(seen.iter().any(|p| p.ends_with("l")));
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_new_file_is_0600_and_must_share_the_folders_device() {
        let dir = temp_dir("devmode");
        let path = dir.join("f");
        let file = write_new(&path, dev_of(&dir), |f| f.write_all(b"x")).unwrap();
        assert_eq!(
            file.metadata().unwrap().permissions().mode() & 0o7777,
            0o600
        );
        // A different device is refused before anything is written, and the
        // file is not left behind. (A strict umask such as 0400 is not tested:
        // it cannot be set without `unsafe`; the explicit fchmod covers it.)
        let other = dir.join("g");
        let mut wrote = false;
        let r = write_new(&other, dev_of(&dir).wrapping_add(1), |_| {
            wrote = true;
            Ok(())
        });
        assert!(r.is_err() && !wrote && !other.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_key_file_on_another_device_than_its_folder_is_refused() {
        let dir = temp_dir("keydev");
        let path = dir.join("k");
        let mut f = write_new(&path, dev_of(&dir), |_| Ok(())).unwrap();
        f.write_all(format!("{}\n", "11".repeat(32)).as_bytes())
            .unwrap();
        let euid = effective_uid(&dir).unwrap();
        assert!(read_key(&path, euid, dev_of(&dir)).is_ok());
        let err = read_key(&path, euid, dev_of(&dir).wrapping_add(1)).unwrap_err();
        assert!(
            matches!(err, NotifyError::KeyFile(m) if m.contains("different filesystem")),
            "{err}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
