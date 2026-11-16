//! Public synthetic fixtures from sseemayer/keepass-rs, tag v0.8.12 (MIT).
//! This establishes fixture decoding, not a fresh external KeePass application run.
use passwords_keeper::{error::VaultError, vault::Vault};
use zeroize::Zeroizing;
#[test]
fn upstream_argon2_and_chacha_fixtures() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["argon2", "argon2id", "chacha"] {
        let bytes = std::fs::read(format!("tests/fixtures/{name}.kdbx")).unwrap();
        let path = dir.path().join(format!("{name}.kdbx"));
        std::fs::write(&path, &bytes).unwrap();
        let vault = Vault::open(path, Zeroizing::new("demopass".into())).unwrap();
        assert!(!vault.catalog().entries.is_empty());
        let exported = dir.path().join(format!("{name}-export.kdbx"));
        vault.export(&exported).unwrap();
        let reopened = Vault::open(exported, Zeroizing::new("demopass".into())).unwrap();
        assert_eq!(
            vault.catalog().entries.len(),
            reopened.catalog().entries.len()
        );
    }
}
#[test]
fn kdbx41_is_rejected_without_modification() {
    let bytes = include_bytes!("fixtures/aes.kdbx");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("newer.kdbx");
    std::fs::write(&path, bytes).unwrap();
    assert!(matches!(
        Vault::open(path.clone(), Zeroizing::new("demopass".into())),
        Err(VaultError::Unsupported)
    ));
    assert_eq!(std::fs::read(path).unwrap(), bytes);
}
