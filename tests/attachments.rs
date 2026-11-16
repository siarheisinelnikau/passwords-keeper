use keepass::{
    Database, DatabaseKey,
    config::{DatabaseConfig, KdfConfig, OuterCipherConfig},
    db::{Entry, HeaderAttachment, History, Node, Value},
};
use passwords_keeper::{
    error::VaultError,
    vault::{MAX_ATTACHMENT, MAX_ATTACHMENTS, Vault},
};
use std::{path::Path, sync::atomic::AtomicBool};
use uuid::Uuid;
use zeroize::Zeroizing;

const PASSWORD: &str = "synthetic attachment password";
const SHARED: &[u8] = b"shared synthetic attachment\0\xff\n";
fn password() -> Zeroizing<String> {
    Zeroizing::new(PASSWORD.into())
}
fn write_db(path: &Path, db: &Database) {
    let mut bytes = Vec::new();
    db.save(&mut bytes, DatabaseKey::new().with_password(PASSWORD))
        .unwrap();
    std::fs::write(path, bytes).unwrap();
}
fn parse(path: &Path) -> Database {
    Database::parse(
        &std::fs::read(path).unwrap(),
        DatabaseKey::new().with_password(PASSWORD),
    )
    .unwrap()
}
fn fixture(path: &Path, chacha: bool) -> (Uuid, Uuid) {
    let config = DatabaseConfig {
        kdf_config: KdfConfig::Aes { rounds: 1000 },
        outer_cipher_config: if chacha {
            OuterCipherConfig::ChaCha20
        } else {
            OuterCipherConfig::AES256
        },
        ..Default::default()
    };
    let mut db = Database::new(config);
    for (flags, content) in [(0, b"unused".as_slice()), (1, SHARED), (0, b"history only")] {
        db.header_attachments.push(HeaderAttachment {
            flags,
            content: content.to_vec(),
        });
    }
    let mut a = Entry::new();
    a.fields
        .insert("Title".into(), Value::Unprotected("First".into()));
    a.attachments.insert("shared.bin".into(), 1);
    let mut old = a.clone();
    old.attachments.clear();
    old.attachments.insert("old.txt".into(), 2);
    let mut history = History::default();
    history.add_entry(old);
    a.history = Some(history);
    let mut b = Entry::new();
    b.fields
        .insert("Title".into(), Value::Unprotected("Second".into()));
    b.attachments.insert("shared.bin".into(), 1);
    let ids = (a.uuid, b.uuid);
    db.root.add_child(a);
    db.root.add_child(b);
    write_db(path, &db);
    ids
}
fn entry(db: &Database, id: Uuid) -> &Entry {
    db.root
        .children
        .iter()
        .find_map(|n| {
            if let Node::Entry(e) = n {
                (e.uuid == id).then_some(e)
            } else {
                None
            }
        })
        .unwrap()
}

#[test]
fn shared_and_historical_attachments_survive_edit_delete_lock_and_reopen() {
    for chacha in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.kdbx");
        let (a, b) = fixture(&path, chacha);
        let original = std::fs::read(&path).unwrap();
        let mut vault = Vault::open(path.clone(), password()).unwrap();
        assert_eq!(vault.entry(a).unwrap().attachments[0].size, SHARED.len());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let mut draft = vault.entry(a).unwrap();
        draft.title = "Updated title".into();
        draft.attachments.clear();
        vault.put(&draft).unwrap(); // Editable draft metadata cannot remove binary references.
        let same = dir.path().join("same.bin");
        std::fs::write(&same, SHARED).unwrap();
        vault.add_attachment(a, &same).unwrap();
        assert!(matches!(
            vault.add_attachment(a, &same),
            Err(VaultError::AttachmentExists)
        ));
        vault.remove_attachment(a, "shared.bin").unwrap();
        let exported = dir.path().join("exported.bin");
        vault.export_attachment(b, "shared.bin", &exported).unwrap();
        assert_eq!(std::fs::read(&exported).unwrap(), SHARED);
        assert!(vault.export_attachment(b, "shared.bin", &exported).is_err());
        assert_eq!(std::fs::read(&exported).unwrap(), SHARED);
        draft = vault.entry(a).unwrap();
        draft.notes = "unsaved note".into();
        let sealed = vault.seal(Some(&draft)).unwrap();
        drop(vault);
        let (mut vault, restored) = sealed.unlock(password()).unwrap();
        let restored = restored.unwrap();
        assert_eq!(restored.notes, "unsaved note");
        assert_eq!(restored.attachments[0].name, "same.bin");
        vault.save(&AtomicBool::new(false)).unwrap();
        let db = parse(&path);
        assert_eq!(db.header_attachments.len(), 2);
        assert_eq!(
            db.header_attachments[entry(&db, b).attachments["shared.bin"]].content,
            SHARED
        );
        let old = &entry(&db, a).history.as_ref().unwrap().get_entries()[0];
        assert_eq!(
            db.header_attachments[old.attachments["old.txt"]].content,
            b"history only"
        );
        drop(db);
        vault.delete_entry(a).unwrap();
        vault.save(&AtomicBool::new(false)).unwrap();
        drop(vault);
        let mut vault = Vault::open(path.clone(), password()).unwrap();
        assert_eq!(parse(&path).header_attachments.len(), 1);
        vault
            .export_attachment(b, "shared.bin", &dir.path().join("after-delete.bin"))
            .unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("after-delete.bin")).unwrap(),
            SHARED
        );
        vault.remove_attachment(b, "shared.bin").unwrap();
        vault.save(&AtomicBool::new(false)).unwrap();
        assert!(parse(&path).header_attachments.is_empty());
    }
}

#[test]
fn invalid_references_and_oversized_attachment_pools_are_rejected_without_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid.kdbx");
    let (a, _) = fixture(&path, false);
    let mut db = parse(&path);
    for node in &mut db.root.children {
        if let Node::Entry(e) = node
            && e.uuid == a
        {
            e.attachments.insert("invalid.bin".into(), 999);
        }
    }
    write_db(&path, &db);
    let original = std::fs::read(&path).unwrap();
    assert!(matches!(
        Vault::open(path.clone(), password()),
        Err(VaultError::Corrupt)
    ));
    assert_eq!(std::fs::read(&path).unwrap(), original);
    db.root.children.clear();
    db.header_attachments.clear();
    for _ in 0..=MAX_ATTACHMENTS {
        db.header_attachments.push(HeaderAttachment {
            flags: 0,
            content: Vec::new(),
        });
    }
    write_db(&path, &db);
    assert!(matches!(
        Vault::open(path, password()),
        Err(VaultError::Limit)
    ));
}

#[test]
fn rejects_large_files_and_supports_empty_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.kdbx");
    let (a, _) = fixture(&path, false);
    let mut vault = Vault::open(path, password()).unwrap();
    let large = dir.path().join("large.bin");
    let file = std::fs::File::create(&large).unwrap();
    file.set_len(MAX_ATTACHMENT as u64 + 1).unwrap();
    drop(file);
    assert!(matches!(
        vault.add_attachment(a, &large),
        Err(VaultError::Limit)
    ));
    let empty = dir.path().join("empty.bin");
    std::fs::write(&empty, []).unwrap();
    vault.add_attachment(a, &empty).unwrap();
    vault
        .export_attachment(a, "empty.bin", &dir.path().join("empty-copy.bin"))
        .unwrap();
    assert!(
        std::fs::read(dir.path().join("empty-copy.bin"))
            .unwrap()
            .is_empty()
    );
}
