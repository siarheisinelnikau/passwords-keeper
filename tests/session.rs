use passwords_keeper::{
    service::{Command, Engine, Response},
    vault::EntryDraft,
};
use zeroize::Zeroizing;
const PASSWORD: &str = "synthetic session master";
#[test]
fn session_lock_unlock_and_failed_seal_preserve_work() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("session.kdbx");
    let mut engine = Engine::default();
    let root = match engine.handle(Command::Open {
        path,
        password: Zeroizing::new(PASSWORD.into()),
        create: true,
    }) {
        Response::Opened { catalog, .. } => catalog.groups[0].id,
        _ => panic!("create failed"),
    };
    let mut draft = EntryDraft::default();
    draft.group = root;
    draft.password = "synthetic secret".into();
    draft.notes = "\"\n".repeat(64 * 1024);
    assert!(matches!(
        engine.handle(Command::Lock(Some(draft.clone()))),
        Response::Locked { unsaved: true }
    ));
    assert!(matches!(
        engine.handle(Command::Unlock(Zeroizing::new("wrong".into()))),
        Response::Failed { .. }
    ));
    match engine.handle(Command::Unlock(Zeroizing::new(PASSWORD.into()))) {
        Response::Opened {
            draft: Some(restored),
            ..
        } => assert_eq!(restored.notes, draft.notes),
        _ => panic!("unlock failed"),
    }
    draft.notes = "x".repeat(256 * 1024 + 1);
    assert!(matches!(
        engine.handle(Command::Lock(Some(draft.clone()))),
        Response::Failed {
            lock_failed: true,
            ..
        }
    ));
    assert!(matches!(
        engine.handle(Command::Unlock(Zeroizing::new("wrong".into()))),
        Response::Failed { .. }
    ));
    match engine.handle(Command::Unlock(Zeroizing::new(PASSWORD.into()))) {
        Response::Opened {
            draft: Some(restored),
            ..
        } => assert_eq!(restored.notes, draft.notes),
        _ => panic!("failed seal lost draft"),
    }
}
