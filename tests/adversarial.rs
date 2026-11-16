use passwords_keeper::{
    error::VaultError,
    preflight,
    storage::{self, SavePhase},
};
use std::{
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

fn field_range(data: &[u8], id: u8) -> std::ops::Range<usize> {
    let mut p = 12;
    loop {
        let t = data[p];
        let n = u32::from_le_bytes(data[p + 1..p + 5].try_into().unwrap()) as usize;
        if t == id {
            return p + 5..p + 5 + n;
        }
        assert_ne!(t, 0);
        p += 5 + n;
    }
}
fn kdf_range(data: &[u8], name: &[u8]) -> std::ops::Range<usize> {
    let outer = field_range(data, 11);
    let mut p = outer.start + 2;
    loop {
        let t = data[p];
        assert_ne!(t, 0);
        p += 1;
        let n = u32::from_le_bytes(data[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        let key = &data[p..p + n];
        p += n;
        let n = u32::from_le_bytes(data[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        if key == name {
            return p..p + n;
        }
        p += n;
    }
}
#[test]
fn unknown_and_excessive_kdf_are_rejected_before_derivation() {
    let base = include_bytes!("fixtures/argon2id.kdbx");
    let mut bytes = base.to_vec();
    let id = kdf_range(&bytes, b"$UUID");
    bytes[id].fill(0xff);
    assert!(matches!(
        preflight::check(&bytes),
        Err(VaultError::Unsupported)
    ));
    for key in [b"M".as_slice(), b"I", b"P"] {
        let mut bytes = base.to_vec();
        let range = kdf_range(&bytes, key);
        bytes[range].fill(0xff);
        assert!(matches!(preflight::check(&bytes), Err(VaultError::Limit)));
    }
    let mut bytes = base.to_vec();
    let range = kdf_range(&bytes, b"V");
    bytes[range].fill(0);
    assert!(matches!(
        preflight::check(&bytes),
        Err(VaultError::Unsupported)
    ));
    let mut bytes = base.to_vec();
    let range = field_range(&bytes, 11);
    bytes[range.start + 3..range.start + 7].fill(0xff);
    assert!(preflight::check(&bytes).is_err());
}
fn original(path: &Path) -> storage::Fingerprint {
    storage::save_new(path, b"original synthetic ciphertext").unwrap()
}
#[test]
fn cancel_after_temp_sync_and_after_backup_never_replaces() {
    for phase in [SavePhase::Staged, SavePhase::BeforeCommit] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.kdbx");
        let fingerprint = original(&path);
        let cancel = AtomicBool::new(false);
        let result = storage::save_observed(
            &path,
            b"new synthetic ciphertext",
            Some(&fingerprint),
            &cancel,
            |now| {
                if now == phase {
                    cancel.store(true, Ordering::SeqCst);
                }
            },
        );
        assert!(matches!(result, Err(VaultError::Cancelled)));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"original synthetic ciphertext"
        );
    }
}
#[test]
fn detects_external_change_at_commit_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.kdbx");
    let fingerprint = original(&path);
    let result = storage::save_observed(
        &path,
        b"new synthetic ciphertext",
        Some(&fingerprint),
        &AtomicBool::new(false),
        |now| {
            if now == SavePhase::BeforeCommit {
                std::fs::write(&path, b"foreign synthetic ciphertext").unwrap();
            }
        },
    );
    assert!(matches!(result, Err(VaultError::Conflict)));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"foreign synthetic ciphertext"
    );
    assert_eq!(
        std::fs::read(storage::backup_path(&path)).unwrap(),
        b"original synthetic ciphertext"
    );
}
#[test]
fn corrupt_update_digests_cannot_panic_or_verify() {
    for value in ["aü".repeat(21) + "a", "z".repeat(64), "0".repeat(63)] {
        assert!(passwords_keeper::updates::parse_sha256(&value).is_none());
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid.exe");
    std::fs::write(&path, b"synthetic non executable").unwrap();
    assert!(passwords_keeper::updates::verify_executable(&path, &[0; 32]).is_err());
}

#[cfg(windows)]
#[test]
fn a_late_racing_writer_keeps_both_versions_and_reports_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.kdbx");
    let fingerprint = original(&path);
    let result = storage::save_observed(
        &path,
        b"new synthetic ciphertext",
        Some(&fingerprint),
        &AtomicBool::new(false),
        |phase| {
            if phase == SavePhase::Replacing {
                std::fs::write(&path, b"racing external synthetic version").unwrap();
            }
        },
    );
    let backup = match result {
        Err(VaultError::ConflictRecovered(path)) => path,
        _ => panic!("late conflict was not reported"),
    };
    assert_eq!(std::fs::read(&path).unwrap(), b"new synthetic ciphertext");
    assert_eq!(
        std::fs::read(backup).unwrap(),
        b"racing external synthetic version"
    );
    assert_eq!(
        std::fs::read(storage::backup_path(&path)).unwrap(),
        b"original synthetic ciphertext"
    );
}
#[test]
fn preferences_roundtrip_and_startup_opt_out() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("preferences.json");
    let prefs = passwords_keeper::settings::Settings {
        startup_updates: false,
        language: passwords_keeper::settings::Language::Ru,
        dark: false,
        reduced_motion: true,
        idle_minutes: 12,
        ..Default::default()
    };
    prefs.save(&path).unwrap();
    let restored = passwords_keeper::settings::Settings::load(&path);
    assert!(!restored.startup_updates);
    assert_eq!(restored.language, prefs.language);
    assert!(!restored.dark);
    assert!(restored.reduced_motion);
    assert_eq!(restored.idle_minutes, 12);
}
