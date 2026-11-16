use passwords_keeper::{
    error::VaultError,
    preflight,
    security::{Clipboard, ClipboardLease, Generator, IdleGuard, LockReason},
    storage,
    vault::{EntryDraft, Vault, search},
};
use std::{path::Path, sync::atomic::AtomicBool, time::Duration};
use zeroize::Zeroizing;
const MASTER: &str = "synthetic master phrase 2026";
fn make(path: &Path) -> Vault {
    Vault::create(path.into(), Zeroizing::new(MASTER.into())).unwrap()
}
fn draft(v: &Vault) -> EntryDraft {
    EntryDraft {
        group: v.catalog().groups[0].id,
        title: "Synthetic mail".into(),
        username: "test@example.invalid".into(),
        password: "SYNTHETIC SECRET only".into(),
        url: "https://example.invalid".into(),
        notes: "line one\nline two\nПример é".into(),
        ..Default::default()
    }
}

#[test]
fn library_kdf_configuration() {
    let config = keepass::config::DatabaseConfig {
        kdf_config: keepass::config::KdfConfig::Argon2id {
            iterations: 3,
            memory: 64 * 1024 * 1024,
            parallelism: 1,
            version: argon2::Version::V0x13,
        },
        ..Default::default()
    };
    let db = keepass::Database::new(config);
    let mut bytes = Vec::new();
    db.save(
        &mut bytes,
        keepass::DatabaseKey::new().with_password(MASTER),
    )
    .unwrap();
    preflight::check(&bytes).unwrap();
}

#[test]
fn aes_kdf_and_empty_group_depth_limit_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("aes-kdf.kdbx");
    let config = keepass::config::DatabaseConfig {
        kdf_config: keepass::config::KdfConfig::Aes { rounds: 1000 },
        ..Default::default()
    };
    let db = keepass::Database::new(config);
    let mut bytes = Vec::new();
    db.save(
        &mut bytes,
        keepass::DatabaseKey::new().with_password(MASTER),
    )
    .unwrap();
    std::fs::write(&path, bytes).unwrap();
    let mut vault = Vault::open(path, Zeroizing::new(MASTER.into())).unwrap();
    let mut parent = vault.catalog().groups[0].id;
    for _ in 0..preflight::MAX_DEPTH {
        parent = vault.add_group(parent, "Synthetic child").unwrap();
    }
    assert!(matches!(
        vault.add_group(parent, "Too deep"),
        Err(VaultError::Limit)
    ));
    vault.save(&AtomicBool::new(false)).unwrap();
    drop(vault);
    assert_eq!(
        Vault::open(
            dir.path().join("aes-kdf.kdbx"),
            Zeroizing::new(MASTER.into())
        )
        .unwrap()
        .catalog()
        .groups
        .len(),
        preflight::MAX_DEPTH + 1
    );
}

#[test]
fn encrypted_round_trip_backup_and_export() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.kdbx");
    let mut v = make(&path);
    let root = v.catalog().groups[0].id;
    let group = v.add_group(root, "Accounts").unwrap();
    let nested = v.add_group(group, "Mail").unwrap();
    let mut d = draft(&v);
    d.group = nested;
    let id = v.put(&d).unwrap();
    v.save(&AtomicBool::new(false)).unwrap();
    let before = std::fs::read(&path).unwrap();
    assert!(!before.windows(9).any(|s| s == b"SYNTHETIC"));
    d.id = Some(id);
    d.password = "changed synthetic password".into();
    v.put(&d).unwrap();
    v.save(&AtomicBool::new(false)).unwrap();
    assert_eq!(std::fs::read(storage::backup_path(&path)).unwrap(), before);
    drop(v);
    let v = Vault::open(path, Zeroizing::new(MASTER.into())).unwrap();
    let reopened = v.entry(id).unwrap();
    assert_eq!(reopened.password, d.password);
    assert_eq!(reopened.notes, d.notes);
    assert_eq!(v.catalog().groups.len(), 3);
    let cat = v.catalog();
    assert_eq!(search(&cat, Some(nested), "synthetic test@").len(), 1);
    assert_eq!(search(&cat, None, "SYNTHETIC SECRET").len(), 0);
    let copy = dir.path().join("export.kdbx");
    v.export(&copy).unwrap();
    assert_eq!(
        Vault::open(copy, Zeroizing::new(MASTER.into()))
            .unwrap()
            .entry(id)
            .unwrap()
            .password,
        d.password
    );
}
#[test]
fn wrong_master_tamper_and_all_truncations_do_not_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.kdbx");
    let mut v = make(&path);
    v.put(&draft(&v)).unwrap();
    v.save(&AtomicBool::new(false)).unwrap();
    drop(v);
    let original = std::fs::read(&path).unwrap();
    assert!(matches!(
        Vault::open(path.clone(), Zeroizing::new("wrong".into())),
        Err(VaultError::Credentials)
    ));
    for end in 0..original.len() {
        assert!(
            preflight::check(&original[..end]).is_err(),
            "accepted truncation {end}"
        );
    }
    let mut altered = original.clone();
    let n = altered.len() - 50;
    altered[n] ^= 0x80;
    std::fs::write(&path, &altered).unwrap();
    assert!(Vault::open(path.clone(), Zeroizing::new(MASTER.into())).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), altered);
}
#[test]
fn cancel_and_external_conflict_preserve_both_versions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v.kdbx");
    let mut v = make(&path);
    v.save(&AtomicBool::new(false)).unwrap();
    let before = std::fs::read(&path).unwrap();
    v.put(&draft(&v)).unwrap();
    assert!(matches!(
        v.save(&AtomicBool::new(true)),
        Err(VaultError::Cancelled)
    ));
    assert!(v.dirty);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    std::fs::write(&path, b"external synthetic replacement").unwrap();
    assert!(matches!(
        v.save(&AtomicBool::new(false)),
        Err(VaultError::Conflict)
    ));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"external synthetic replacement"
    );
    let rescued = dir.path().join("rescued.kdbx");
    v.export(&rescued).unwrap();
    assert_eq!(
        Vault::open(rescued, Zeroizing::new(MASTER.into()))
            .unwrap()
            .catalog()
            .entries
            .len(),
        1
    );
}
#[test]
fn encrypted_lock_restores_unsaved_invalid_draft() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = make(&dir.path().join("v.kdbx"));
    let mut d = draft(&v);
    d.title.clear();
    let sealed = v.seal(Some(&d)).unwrap();
    drop(v);
    assert!(sealed.unlock(Zeroizing::new("wrong".into())).is_err());
    let (v, restored) = sealed.unlock(Zeroizing::new(MASTER.into())).unwrap();
    let restored = restored.unwrap();
    assert!(restored.title.is_empty());
    assert_eq!(restored.password, d.password);
    assert!(v.catalog().entries.is_empty());
    assert!(v.dirty);
}
#[test]
fn group_mutations_and_generator_constraints() {
    let dir = tempfile::tempdir().unwrap();
    let mut v = make(&dir.path().join("v.kdbx"));
    let root = v.catalog().groups[0].id;
    let group = v.add_group(root, "Work").unwrap();
    v.rename_group(group, "Personal").unwrap();
    let mut d = draft(&v);
    d.group = group;
    let id = v.put(&d).unwrap();
    assert!(v.delete_group(group).is_err());
    v.delete_entry(id).unwrap();
    v.delete_group(group).unwrap();
    assert!(v.delete_group(root).is_err());
    let cfg = Generator::default();
    let a = cfg.generate().unwrap();
    let b = cfg.generate().unwrap();
    assert_ne!(*a, *b);
    assert_eq!(a.len(), 24);
    assert!(a.bytes().any(|c| c.is_ascii_digit()));
    assert!(a.bytes().any(|c| c.is_ascii_uppercase()));
    assert!(!a.bytes().any(|c| b"0O1lI|".contains(&c)));
    assert!(
        Generator {
            length: 7,
            ..cfg.clone()
        }
        .generate()
        .is_err()
    );
    assert!(
        Generator {
            length: 129,
            ..cfg.clone()
        }
        .generate()
        .is_err()
    );
    assert!(
        Generator {
            lower: false,
            upper: false,
            digits: false,
            symbols: false,
            ..cfg
        }
        .generate()
        .is_err()
    );
}
#[derive(Default)]
struct FakeClipboard {
    sequence: u64,
    value: String,
}
impl Clipboard for FakeClipboard {
    fn write_secret(&mut self, text: &str) -> passwords_keeper::error::Result<u64> {
        self.sequence += 1;
        self.value = text.into();
        Ok(self.sequence)
    }
    fn clear_if_owned(&mut self, token: u64) -> passwords_keeper::error::Result<bool> {
        if self.sequence == token {
            self.value.clear();
            self.sequence += 1;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
#[test]
fn clipboard_never_clears_a_new_owner_or_equal_recopy() {
    let mut lease = ClipboardLease::new(FakeClipboard::default());
    lease
        .copy("synthetic", Duration::ZERO, Duration::from_secs(30))
        .unwrap();
    lease.tick(Duration::from_secs(29)).unwrap();
    assert_eq!(lease.adapter.value, "synthetic");
    lease.adapter.write_secret("foreign new contents").unwrap();
    lease.tick(Duration::from_secs(31)).unwrap();
    assert_eq!(lease.adapter.value, "foreign new contents");
    lease
        .copy("same", Duration::from_secs(40), Duration::from_secs(30))
        .unwrap();
    lease.adapter.write_secret("same").unwrap();
    lease.tick(Duration::from_secs(70)).unwrap();
    assert_eq!(lease.adapter.value, "same");
    lease
        .copy("owned", Duration::from_secs(80), Duration::from_secs(30))
        .unwrap();
    lease.tick(Duration::from_secs(110)).unwrap();
    assert!(lease.adapter.value.is_empty());
}
#[test]
fn fake_clock_idle_and_session_lock() {
    let mut guard = IdleGuard::new(Duration::ZERO, Duration::from_secs(60));
    guard.unlock(Duration::ZERO);
    assert_eq!(guard.poll(Duration::from_secs(59), false), None);
    guard.activity(Duration::from_secs(59));
    assert_eq!(guard.poll(Duration::from_secs(60), false), None);
    assert_eq!(
        guard.poll(Duration::from_secs(119), false),
        Some(LockReason::Idle)
    );
    assert_eq!(guard.poll(Duration::from_secs(150), false), None);
    guard.unlock(Duration::from_secs(200));
    assert_eq!(
        guard.poll(Duration::from_secs(201), true),
        Some(LockReason::WindowsSession)
    );
}
#[test]
fn unknown_format_and_size_limits() {
    assert!(matches!(
        preflight::check(b"not a vault"),
        Err(VaultError::Unsupported)
    ));
    assert!(matches!(
        preflight::check(&vec![0; preflight::MAX_FILE + 1]),
        Err(VaultError::Limit)
    ));
    let dir = tempfile::tempdir().unwrap();
    let v = make(&dir.path().join("v.kdbx"));
    let mut data = v.encrypted().unwrap();
    data[8] = 1;
    assert!(matches!(
        preflight::check(&data),
        Err(VaultError::Unsupported)
    ));
}
