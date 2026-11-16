use base64::{Engine as _, engine::general_purpose::STANDARD};
use passwords_keeper::{
    credentials::CredentialsInput,
    error::VaultError,
    keyfile,
    vault::{EntryDraft, Vault},
};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};
use zeroize::Zeroizing;

const PASSWORD: &str = "synthetic key file password";
fn credentials(password: bool, key: Option<&Path>) -> passwords_keeper::credentials::Credentials {
    CredentialsInput {
        password: password.then(|| Zeroizing::new(PASSWORD.into())),
        key_file: key.map(Path::to_path_buf),
    }
    .load()
    .unwrap()
}

#[test]
fn normalizes_standard_key_file_formats_and_checks_xml_checksum() {
    let bytes = [0x5au8; 32];
    let hex = "5A".repeat(32);
    assert_eq!(*keyfile::decode(&bytes).unwrap(), bytes);
    assert_eq!(*keyfile::decode(hex.as_bytes()).unwrap(), bytes);
    let xml1 = format!(
        "<KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>{}</Data></Key></KeyFile>",
        STANDARD.encode(bytes)
    );
    assert_eq!(*keyfile::decode(xml1.as_bytes()).unwrap(), bytes);
    let hash: String = Sha256::digest(bytes)[..4]
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    let xml2 = format!(
        "<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"{hash}\">{hex}</Data></Key></KeyFile>"
    );
    assert_eq!(*keyfile::decode(xml2.as_bytes()).unwrap(), bytes);
    assert!(matches!(
        keyfile::decode(xml2.replace(&hash, "00000000").as_bytes()),
        Err(VaultError::KeyFile)
    ));
    assert!(matches!(
        keyfile::decode(xml2.replace("</KeyFile>", "").as_bytes()),
        Err(VaultError::KeyFile)
    ));
    assert!(matches!(
        keyfile::decode(xml2.replace("2.0", "3.0").as_bytes()),
        Err(VaultError::KeyFile)
    ));
    assert!(matches!(
        keyfile::decode(b"<!DOCTYPE KeyFile [<!ENTITY a 'x'>]><KeyFile/>"),
        Err(VaultError::KeyFile)
    ));
    assert!(matches!(
        keyfile::decode(&vec![1; keyfile::MAX_KEY_FILE + 1]),
        Err(VaultError::KeyFile)
    ));
    assert!(matches!(keyfile::decode(&[]), Err(VaultError::KeyFile)));
    let arbitrary = b"a synthetic file with an arbitrary length";
    assert_eq!(
        *keyfile::decode(arbitrary).unwrap(),
        <[u8; 32]>::from(Sha256::digest(arbitrary))
    );
}

#[test]
fn generated_key_files_are_unique_valid_and_never_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.keyx");
    let b = dir.path().join("b.keyx");
    keyfile::generate(&a).unwrap();
    keyfile::generate(&b).unwrap();
    assert_ne!(*keyfile::read(&a).unwrap(), *keyfile::read(&b).unwrap());
    let original = std::fs::read(&a).unwrap();
    assert!(keyfile::generate(&a).is_err());
    assert_eq!(std::fs::read(&a).unwrap(), original);
    assert!(keyfile::read(&dir.path().join("missing.keyx")).is_err());
}

#[test]
fn opens_external_keepass_key_file_fixtures() {
    // Public synthetic fixtures from keepass-rs v0.8.12 (MIT, vendored license).
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for (database, key, password) in [
        ("test_db_kdbx4_with_keyfile.kdbx", "test_key.key", None),
        (
            "test_db_kdbx4_with_keyfile_v2.kdbx",
            "test_db_kdbx4_with_keyfile_v2.keyx",
            Some("demopass"),
        ),
    ] {
        let credentials = CredentialsInput {
            password: password.map(|p| Zeroizing::new(p.into())),
            key_file: Some(base.join(key)),
        }
        .load()
        .unwrap();
        let vault = Vault::open_with_credentials(base.join(database), credentials).unwrap();
        assert!(!vault.catalog().entries.is_empty());
    }
}

#[test]
fn composite_credentials_lock_rekey_and_cancellation_preserve_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.kdbx");
    let key = dir.path().join("vault.keyx");
    keyfile::generate(&key).unwrap();
    let wrong = dir.path().join("wrong.keyx");
    keyfile::generate(&wrong).unwrap();
    let mut vault =
        Vault::create_with_credentials(path.clone(), credentials(true, Some(&key))).unwrap();
    let mut draft = EntryDraft::default();
    draft.group = vault.catalog().groups[0].id;
    draft.title = "Synthetic entry".into();
    let id = vault.put(&draft).unwrap();
    vault.save(&AtomicBool::new(false)).unwrap();
    assert!(Vault::open_with_credentials(path.clone(), credentials(true, None)).is_err());
    assert!(Vault::open_with_credentials(path.clone(), credentials(false, Some(&key))).is_err());
    assert!(Vault::open_with_credentials(path.clone(), credentials(true, Some(&wrong))).is_err());
    draft.id = Some(id);
    draft.notes = "unsaved synthetic note".into();
    let sealed = vault.seal(Some(&draft)).unwrap();
    drop(vault);
    assert!(
        sealed
            .unlock_with_credentials(credentials(true, Some(&wrong)))
            .is_err()
    );
    let (mut vault, restored) = sealed
        .unlock_with_credentials(credentials(true, Some(&key)))
        .unwrap();
    assert_eq!(restored.unwrap().notes, draft.notes);
    let original = std::fs::read(&path).unwrap();
    assert!(matches!(
        vault.rekey(credentials(false, Some(&wrong)), &AtomicBool::new(true)),
        Err(VaultError::Cancelled)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), original);
    assert!(vault.authenticate_credentials(&credentials(true, Some(&key))));
    std::fs::write(&path, b"synthetic external replacement").unwrap();
    assert!(matches!(
        vault.rekey(credentials(false, Some(&wrong)), &AtomicBool::new(false)),
        Err(VaultError::Conflict)
    ));
    assert!(vault.authenticate_credentials(&credentials(true, Some(&key))));
    std::fs::write(&path, original).unwrap();
    vault
        .rekey(credentials(false, Some(&key)), &AtomicBool::new(false))
        .unwrap();
    drop(vault);
    assert!(Vault::open_with_credentials(path.clone(), credentials(true, Some(&key))).is_err());
    let mut vault =
        Vault::open_with_credentials(path.clone(), credentials(false, Some(&key))).unwrap();
    assert_eq!(vault.entry(id).unwrap().title, "Synthetic entry");
    vault
        .rekey(credentials(true, None), &AtomicBool::new(false))
        .unwrap();
    drop(vault);
    assert!(Vault::open_with_credentials(path, credentials(true, None)).is_ok());
}
