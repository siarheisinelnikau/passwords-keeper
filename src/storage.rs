use crate::{
    error::{Result, VaultError},
    preflight::MAX_FILE,
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fingerprint {
    pub hash: [u8; 32],
    pub len: usize,
}
impl Fingerprint {
    pub fn of(data: &[u8]) -> Self {
        Self {
            hash: Sha256::digest(data).into(),
            len: data.len(),
        }
    }
}
pub fn read(path: &Path) -> Result<(Vec<u8>, Fingerprint)> {
    let file = File::open(path)?;
    if file.metadata()?.len() > MAX_FILE as u64 {
        return Err(VaultError::Limit);
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_FILE {
        return Err(VaultError::Limit);
    }
    let stamp = Fingerprint::of(&bytes);
    Ok((bytes, stamp))
}
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
}
pub fn backup_path(path: &Path) -> PathBuf {
    sibling(path, ".bak")
}
pub fn recovery_path(path: &Path) -> PathBuf {
    sibling(path, ".recovery.kdbx")
}

fn cancelled(cancel: &AtomicBool) -> Result<()> {
    if cancel.load(Ordering::SeqCst) {
        Err(VaultError::Cancelled)
    } else {
        Ok(())
    }
}
fn verify(path: &Path, expected: Option<&Fingerprint>) -> Result<()> {
    match (read(path), expected) {
        (Ok((_, now)), Some(old)) if &now == old => Ok(()),
        (Err(VaultError::Io(e)), None) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(VaultError::Conflict),
    }
}

/// Optimistic external-change detection, a durable backup, then atomic replacement.
/// Cooperating writers share a lock file. Noncooperating rename races cannot be
/// excluded across processes; the backup always retains the verified old bytes.
pub fn save(
    path: &Path,
    data: &[u8],
    expected: Option<&Fingerprint>,
    cancel: &AtomicBool,
) -> Result<Fingerprint> {
    save_observed(path, data, expected, cancel, |_| {})
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SavePhase {
    Staged,
    BackupCreated,
    BeforeCommit,
    Replacing,
}
pub fn save_observed(
    path: &Path,
    data: &[u8],
    expected: Option<&Fingerprint>,
    cancel: &AtomicBool,
    mut observer: impl FnMut(SavePhase),
) -> Result<Fingerprint> {
    if data.len() > MAX_FILE {
        return Err(VaultError::Limit);
    }
    cancelled(cancel)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(sibling(path, ".write-lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| VaultError::Busy)?;
    verify(path, expected)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(data)?;
    temp.as_file().sync_all()?;
    observer(SavePhase::Staged);
    cancelled(cancel)?;
    if expected.is_some() {
        let (old, stamp) = read(path)?;
        if Some(&stamp) != expected {
            return Err(VaultError::Conflict);
        }
        let mut backup = tempfile::NamedTempFile::new_in(parent)?;
        backup.write_all(&old)?;
        backup.as_file().sync_all()?;
        backup
            .persist(backup_path(path))
            .map_err(|e| VaultError::Io(e.error))?;
        observer(SavePhase::BackupCreated);
    }
    observer(SavePhase::BeforeCommit);
    cancelled(cancel)?;
    verify(path, expected)?;
    let temp = temp.into_temp_path();
    observer(SavePhase::Replacing);
    if expected.is_some() {
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            let dst: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            let src: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
            let displaced = path.with_file_name(format!(
                "{}.external-change-{}.kdbx",
                path.file_name().unwrap_or_default().to_string_lossy(),
                uuid::Uuid::new_v4()
            ));
            let displaced_wide: Vec<u16> =
                displaced.as_os_str().encode_wide().chain(Some(0)).collect();
            // The replacement lives on the same volume. No delete-then-rename gap.
            let success = unsafe {
                windows_sys::Win32::Storage::FileSystem::ReplaceFileW(
                    dst.as_ptr(),
                    src.as_ptr(),
                    displaced_wide.as_ptr(),
                    0,
                    std::ptr::null(),
                    std::ptr::null(),
                )
            };
            if success == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            // ReplaceFile captures the exact displaced version, closing the data-loss
            // window between the final optimistic check and a noncooperating rename.
            if read(&displaced).ok().map(|(_, stamp)| stamp).as_ref() != expected {
                return Err(VaultError::ConflictRecovered(displaced));
            }
            let _ = fs::remove_file(displaced);
        }
        #[cfg(not(windows))]
        {
            temp.persist(path).map_err(|e| VaultError::Io(e.error))?;
        }
    } else {
        temp.persist_noclobber(path)
            .map_err(|e| VaultError::Io(e.error))?;
    }
    #[cfg(unix)]
    {
        File::open(parent)?.sync_all()?;
    }
    Ok(Fingerprint::of(data))
}

pub fn save_new(path: &Path, data: &[u8]) -> Result<Fingerprint> {
    save(path, data, None, &AtomicBool::new(false))
}

pub fn absolute(path: &Path) -> std::io::Result<PathBuf> {
    if path.exists() {
        fs::canonicalize(path)
    } else {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        Ok(fs::canonicalize(parent)?.join(
            path.file_name()
                .ok_or_else(|| std::io::Error::other("Missing file name"))?,
        ))
    }
}
