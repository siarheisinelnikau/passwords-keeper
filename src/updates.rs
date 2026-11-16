use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

pub const REPOSITORY: &str = "siarheisinelnikau/passwords-keeper";
const API: &str = "https://api.github.com/repos/siarheisinelnikau/passwords-keeper/releases/latest";
const MAX_DOWNLOAD: u64 = 200 * 1024 * 1024;
#[derive(Clone, Debug)]
pub struct Update {
    pub version: String,
    pub url: String,
    pub sha256: [u8; 32],
    pub size: u64,
}
pub struct StagedUpdate {
    pub path: PathBuf,
    pub sha256: [u8; 32],
}
impl Drop for StagedUpdate {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("The release service could not be reached or has no published release.")]
    Unavailable,
    #[error("The official download has no usable digest or is incompatible.")]
    Integrity,
    #[error("Update file access failed.")]
    Io,
}
#[derive(Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    assets: Vec<Asset>,
}
#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    size: u64,
    digest: Option<String>,
}
fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(90)))
        .https_only(true)
        .build()
        .into()
}
pub fn select_release(json: &str, current: &str) -> Result<Option<Update>, UpdateError> {
    let r: Release = serde_json::from_str(json).map_err(|_| UpdateError::Unavailable)?;
    if r.draft || r.prerelease {
        return Err(UpdateError::Unavailable);
    }
    let version = semver::Version::parse(r.tag_name.trim_start_matches('v'))
        .map_err(|_| UpdateError::Unavailable)?;
    let installed = semver::Version::parse(current).map_err(|_| UpdateError::Unavailable)?;
    if !version.pre.is_empty() {
        return Err(UpdateError::Unavailable);
    }
    if version <= installed {
        return Ok(None);
    }
    let name = format!("PasswordsKeeper-v{version}.exe");
    let asset = r
        .assets
        .into_iter()
        .find(|a| a.name == name)
        .ok_or(UpdateError::Integrity)?;
    let expected = format!(
        "https://github.com/{REPOSITORY}/releases/download/{}/{}",
        r.tag_name, name
    );
    if asset.browser_download_url != expected || asset.size < 1024 || asset.size > MAX_DOWNLOAD {
        return Err(UpdateError::Integrity);
    }
    let hash = asset
        .digest
        .as_deref()
        .and_then(|s| s.strip_prefix("sha256:"))
        .and_then(parse_sha256)
        .ok_or(UpdateError::Integrity)?;
    Ok(Some(Update {
        version: version.to_string(),
        url: asset.browser_download_url,
        sha256: hash,
        size: asset.size,
    }))
}
pub fn check() -> Result<Option<Update>, UpdateError> {
    let response = agent()
        .get(API)
        .header("Accept", "application/vnd.github+json")
        .header(
            "User-Agent",
            concat!("PasswordsKeeper/", env!("CARGO_PKG_VERSION")),
        )
        .call()
        .map_err(|_| UpdateError::Unavailable)?;
    let json = response
        .into_body()
        .with_config()
        .limit(1024 * 1024)
        .read_to_string()
        .map_err(|_| UpdateError::Unavailable)?;
    select_release(&json, crate::VERSION)
}
pub fn download(
    update: &Update,
    mut progress: impl FnMut(u8),
) -> Result<StagedUpdate, UpdateError> {
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        let _ = (&update, &mut progress);
        return Err(UpdateError::Integrity);
    }
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let exe = std::env::current_exe().map_err(|_| UpdateError::Io)?;
        let parent = exe.parent().ok_or(UpdateError::Io)?;
        let mut file = tempfile::Builder::new()
            .prefix("PasswordsKeeper-update-")
            .suffix(".exe")
            .tempfile_in(parent)
            .map_err(|_| UpdateError::Io)?;
        let mut response = agent()
            .get(&update.url)
            .call()
            .map_err(|_| UpdateError::Unavailable)?;
        let mut reader = response.body_mut().as_reader();
        let mut hash = Sha256::new();
        let mut chunk = [0; 64 * 1024];
        let mut total = 0;
        let mut shown = 0;
        loop {
            let read = reader
                .read(&mut chunk)
                .map_err(|_| UpdateError::Unavailable)?;
            if read == 0 {
                break;
            }
            total += read as u64;
            if total > update.size || total > MAX_DOWNLOAD {
                return Err(UpdateError::Integrity);
            }
            hash.update(&chunk[..read]);
            file.write_all(&chunk[..read])
                .map_err(|_| UpdateError::Io)?;
            let percent = (total * 100 / update.size) as u8;
            if percent >= shown + 5 {
                progress(percent);
                shown = percent;
            }
        }
        if total != update.size || hash.finalize().as_slice() != update.sha256 {
            return Err(UpdateError::Integrity);
        }
        file.as_file().sync_all().map_err(|_| UpdateError::Io)?;
        verify_executable(file.path(), &update.sha256)?;
        let path = file.into_temp_path().keep().map_err(|_| UpdateError::Io)?;
        progress(100);
        Ok(StagedUpdate {
            path,
            sha256: update.sha256,
        })
    }
}
pub fn parse_sha256(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut value = [0; 32];
    for (i, byte) in value.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(value)
}
fn hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|v| format!("{v:02x}")).collect()
}
pub fn verify_executable(path: &Path, expected: &[u8; 32]) -> Result<(), UpdateError> {
    let mut file = fs::File::open(path).map_err(|_| UpdateError::Io)?;
    if file.metadata().map_err(|_| UpdateError::Io)?.len() > MAX_DOWNLOAD {
        return Err(UpdateError::Integrity);
    }
    let mut header = [0; 1024];
    let n = file.read(&mut header).map_err(|_| UpdateError::Io)?;
    if n < 64 || &header[..2] != b"MZ" {
        return Err(UpdateError::Integrity);
    }
    let offset = u32::from_le_bytes(
        header[60..64]
            .try_into()
            .map_err(|_| UpdateError::Integrity)?,
    ) as usize;
    if offset > n.saturating_sub(6)
        || &header[offset..offset + 4] != b"PE\0\0"
        || u16::from_le_bytes([header[offset + 4], header[offset + 5]]) != 0x8664
    {
        return Err(UpdateError::Integrity);
    }
    let mut digest = Sha256::new();
    digest.update(&header[..n]);
    let mut buffer = [0; 64 * 1024];
    loop {
        let n = file.read(&mut buffer).map_err(|_| UpdateError::Io)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    if digest.finalize().as_slice() != expected {
        return Err(UpdateError::Integrity);
    }
    Ok(())
}
pub fn start_install(update: &StagedUpdate) -> Result<(), UpdateError> {
    let exe = std::env::current_exe().map_err(|_| UpdateError::Io)?;
    let parent = exe.parent().ok_or(UpdateError::Io)?;
    verify_executable(&update.path, &update.sha256)?;
    let helper = parent.join(format!(
        "PasswordsKeeper-updater-{}.exe",
        uuid::Uuid::new_v4()
    ));
    fs::copy(&exe, &helper).map_err(|_| UpdateError::Io)?;
    let mut command = std::process::Command::new(&helper);
    command
        .arg("--apply-update")
        .arg(&exe)
        .arg(&update.path)
        .arg(hex(&update.sha256))
        .arg(std::process::id().to_string());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    command.spawn().map_err(|_| UpdateError::Io)?;
    Ok(())
}
/// The helper accepts paths and a public digest only. It never sees vault secrets.
pub fn run_helper(args: &[String]) -> Result<bool, UpdateError> {
    if args.first().map(String::as_str) != Some("--apply-update") {
        return Ok(false);
    }
    if args.len() != 5 {
        return Err(UpdateError::Integrity);
    }
    let destination = PathBuf::from(&args[1]);
    let staged = PathBuf::from(&args[2]);
    let hash = parse_sha256(&args[3]).ok_or(UpdateError::Integrity)?;
    let helper = std::env::current_exe().map_err(|_| UpdateError::Io)?;
    let parent = helper
        .parent()
        .ok_or(UpdateError::Io)?
        .canonicalize()
        .map_err(|_| UpdateError::Io)?;
    for path in [&destination, &staged] {
        if path.parent().and_then(|p| p.canonicalize().ok()).as_ref() != Some(&parent) {
            return Err(UpdateError::Integrity);
        }
    }
    if destination == helper || staged == helper || destination == staged {
        return Err(UpdateError::Integrity);
    }
    let pid = args[4].parse::<u32>().map_err(|_| UpdateError::Integrity)?;
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject},
        };
        let process = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
        if !process.is_null() {
            let result = WaitForSingleObject(process, 30_000);
            CloseHandle(process);
            if result != 0 {
                return Err(UpdateError::Io);
            }
        }
    }
    #[cfg(not(windows))]
    let _ = pid;
    verify_executable(&staged, &hash)?;
    let backup = parent.join(format!(
        "PasswordsKeeper-previous-{}.exe",
        uuid::Uuid::new_v4()
    ));
    #[cfg(windows)]
    unsafe {
        use std::os::windows::ffi::OsStrExt;
        let wide = |p: &Path| {
            p.as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<u16>>()
        };
        if windows_sys::Win32::Storage::FileSystem::ReplaceFileW(
            wide(&destination).as_ptr(),
            wide(&staged).as_ptr(),
            wide(&backup).as_ptr(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        ) == 0
        {
            return Err(UpdateError::Io);
        }
    }
    #[cfg(not(windows))]
    {
        return Err(UpdateError::Integrity);
    }
    if std::process::Command::new(&destination)
        .arg("--cleanup-helper")
        .arg(&helper)
        .spawn()
        .is_err()
    {
        let _ = fs::rename(
            &destination,
            parent.join("PasswordsKeeper-failed-update.exe"),
        );
        let _ = fs::rename(&backup, &destination);
        let _ = std::process::Command::new(&destination).spawn();
        return Err(UpdateError::Io);
    }
    Ok(true)
}
pub fn cleanup_helper(args: &[String]) {
    if args.len() != 2 || args[0] != "--cleanup-helper" {
        return;
    }
    let path = Path::new(&args[1]);
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    if path.parent().and_then(|p| p.canonicalize().ok())
        == exe.parent().and_then(|p| p.canonicalize().ok())
        && path
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|v| v.starts_with("PasswordsKeeper-updater-") && v.ends_with(".exe"))
    {
        let _ = fs::remove_file(path);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn release_versions_assets_and_unavailable_integrity() {
        let json = |version: &str, draft: bool, digest: &str| {
            format!(
                r#"{{"tag_name":"v{version}","draft":{draft},"prerelease":false,"assets":[{{"name":"PasswordsKeeper-v{version}.exe","browser_download_url":"https://github.com/{REPOSITORY}/releases/download/v{version}/PasswordsKeeper-v{version}.exe","size":2048,"digest":"{digest}"}}]}}"#
            )
        };
        assert!(
            select_release(
                &json("0.2.0", false, &format!("sha256:{}", "ab".repeat(32))),
                "0.1.0"
            )
            .unwrap()
            .is_some()
        );
        assert!(
            select_release(&json("0.1.0", false, ""), "0.1.0")
                .unwrap()
                .is_none()
        );
        assert!(select_release(&json("0.2.0", true, ""), "0.1.0").is_err());
        assert!(select_release(&json("0.2.0", false, ""), "0.1.0").is_err());
        assert!(select_release("{\"message\":\"Not Found\"}", "0.1.0").is_err());
    }
}
