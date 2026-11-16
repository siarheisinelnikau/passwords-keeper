use crate::{
    error::{Result, VaultError},
    security::{Clipboard, ClipboardLease},
    vault::{Catalog, EntryDraft, SealedVault, Vault},
};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool, mpsc},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub enum Command {
    Open {
        path: PathBuf,
        password: Zeroizing<String>,
        create: bool,
    },
    Unlock(Zeroizing<String>),
    Entry(Uuid),
    Apply(EntryDraft),
    Save {
        draft: Option<EntryDraft>,
        export: Option<PathBuf>,
        cancel: Arc<AtomicBool>,
    },
    AddGroup(Uuid, String),
    RenameGroup(Uuid, String),
    DeleteGroup(Uuid),
    DeleteEntry(Uuid),
    Lock(Option<EntryDraft>),
    Close,
    Shutdown,
}
pub enum Response {
    Opened {
        catalog: Catalog,
        path: PathBuf,
        draft: Option<EntryDraft>,
    },
    Catalog {
        catalog: Catalog,
        selected: Option<Uuid>,
        saved: bool,
    },
    Entry(EntryDraft),
    Locked {
        unsaved: bool,
    },
    Closed,
    Failed {
        error: VaultError,
        lock_failed: bool,
    },
}
#[derive(Default)]
pub struct Engine {
    vault: Option<Vault>,
    sealed: Option<SealedVault>,
    pending_draft: Option<EntryDraft>,
}
impl Engine {
    pub fn handle(&mut self, command: Command) -> Response {
        let locking = matches!(&command, Command::Lock(_));
        match self.execute(command) {
            Ok(response) => response,
            Err(error) => Response::Failed {
                error,
                lock_failed: locking,
            },
        }
    }
    fn execute(&mut self, command: Command) -> Result<Response> {
        match command {
            Command::Open {
                path,
                password,
                create,
            } => {
                if self.vault.is_some() || self.sealed.is_some() {
                    return Err(VaultError::Busy);
                }
                let mut v = if create {
                    let mut v = Vault::create(path, password)?;
                    v.save(&AtomicBool::new(false))?;
                    v
                } else {
                    Vault::open(path, password)?
                };
                let catalog = v.catalog();
                let path = v.path.clone();
                v.dirty = false;
                self.vault = Some(v);
                Ok(Response::Opened {
                    catalog,
                    path,
                    draft: None,
                })
            }
            Command::Unlock(password) => {
                let (v, draft) = if let Some(sealed) = self.sealed.as_ref() {
                    sealed.unlock(password)?
                } else {
                    let v = self.vault.as_ref().ok_or(VaultError::Locked)?;
                    if !v.authenticate(&password) {
                        return Err(VaultError::Credentials);
                    }
                    (
                        self.vault.take().ok_or(VaultError::Locked)?,
                        self.pending_draft.take(),
                    )
                };
                let catalog = v.catalog();
                let path = v.path.clone();
                self.vault = Some(v);
                self.sealed = None;
                Ok(Response::Opened {
                    catalog,
                    path,
                    draft,
                })
            }
            Command::Entry(id) => Ok(Response::Entry(
                self.vault.as_ref().ok_or(VaultError::Locked)?.entry(id)?,
            )),
            Command::Lock(draft) => {
                let v = self.vault.as_mut().ok_or(VaultError::Locked)?;
                self.pending_draft = draft;
                let unsaved = v.dirty || self.pending_draft.is_some();
                let sealed = v.seal(self.pending_draft.as_ref())?;
                self.pending_draft = None;
                self.vault = None;
                self.sealed = Some(sealed);
                Ok(Response::Locked { unsaved })
            }
            Command::Close | Command::Shutdown => {
                self.vault = None;
                self.sealed = None;
                self.pending_draft = None;
                Ok(Response::Closed)
            }
            command => {
                let v = self.vault.as_mut().ok_or(VaultError::Locked)?;
                let mut selected = None;
                let mut saved = false;
                match command {
                    Command::Apply(draft) => {
                        selected = Some(v.put(&draft)?);
                    }
                    Command::Save {
                        draft,
                        export,
                        cancel,
                    } => {
                        if let Some(draft) = draft {
                            selected = Some(v.put(&draft)?);
                        }
                        if let Some(path) = export {
                            v.export(&path)?;
                        } else {
                            v.save(&cancel)?;
                            saved = true;
                        }
                    }
                    Command::AddGroup(parent, name) => {
                        v.add_group(parent, &name)?;
                    }
                    Command::RenameGroup(id, name) => v.rename_group(id, &name)?,
                    Command::DeleteGroup(id) => v.delete_group(id)?,
                    Command::DeleteEntry(id) => v.delete_entry(id)?,
                    _ => return Err(VaultError::Locked),
                }
                Ok(Response::Catalog {
                    catalog: v.catalog(),
                    selected,
                    saved,
                })
            }
        }
    }
}
pub struct VaultWorker {
    pub sender: mpsc::Sender<Command>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Drop for VaultWorker {
    fn drop(&mut self) {
        let _ = self.sender.send(Command::Shutdown);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
pub fn spawn(send: impl Fn(Response) + Send + 'static) -> VaultWorker {
    let (tx, rx) = mpsc::channel();
    let thread = thread::Builder::new()
        .name("vault-crypto-and-io".into())
        .spawn(move || {
            let mut engine = Engine::default();
            while let Ok(command) = rx.recv() {
                let shutdown = matches!(command, Command::Shutdown);
                let response = engine.handle(command);
                if shutdown {
                    break;
                }
                send(response);
            }
        })
        .expect("start vault worker");
    VaultWorker {
        sender: tx,
        thread: Some(thread),
    }
}
pub enum ClipboardCommand {
    Copy(Zeroizing<String>, Duration),
    Clear,
    Shutdown,
    Read(u64),
}
pub struct ClipboardWorker {
    pub sender: mpsc::Sender<ClipboardCommand>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Drop for ClipboardWorker {
    fn drop(&mut self) {
        let _ = self.sender.send(ClipboardCommand::Shutdown);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
pub fn spawn_clipboard<C: Clipboard + 'static>(
    adapter: C,
    on_error: impl Fn() + Send + 'static,
    on_paste: impl Fn(u64, Zeroizing<String>) + Send + 'static,
) -> ClipboardWorker {
    let (tx, rx) = mpsc::channel();
    let thread = thread::Builder::new()
        .name("owned-clipboard".into())
        .spawn(move || {
            let start = Instant::now();
            let mut lease = ClipboardLease::new(adapter);
            let mut deadline: Option<Instant> = None;
            let mut reported_error = false;
            loop {
                let command = if let Some(when) = deadline {
                    rx.recv_timeout(when.saturating_duration_since(Instant::now()))
                } else {
                    match rx.recv() {
                        Ok(c) => Ok(c),
                        Err(_) => break,
                    }
                };
                match command {
                    Ok(ClipboardCommand::Copy(text, ttl)) => {
                        reported_error = false;
                        if lease.copy(&text, start.elapsed(), ttl).is_err() {
                            on_error();
                            reported_error = true;
                        } else {
                            deadline = Some(Instant::now() + ttl);
                        }
                    }
                    Ok(ClipboardCommand::Clear) => {
                        if lease.clear().is_err() {
                            if !reported_error {
                                on_error();
                                reported_error = true;
                            }
                            deadline = Some(Instant::now() + Duration::from_secs(1));
                        } else {
                            deadline = None;
                            reported_error = false;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if lease.tick(start.elapsed()).is_err() {
                            if !reported_error {
                                on_error();
                                reported_error = true;
                            }
                            deadline = Some(Instant::now() + Duration::from_secs(1));
                        } else {
                            deadline = None;
                            reported_error = false;
                        }
                    }
                    Ok(ClipboardCommand::Shutdown) => break,
                    Ok(ClipboardCommand::Read(epoch)) => match lease.adapter.read_text() {
                        Ok(text) => on_paste(epoch, text),
                        Err(_) => on_error(),
                    },
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
        .expect("start clipboard worker");
    ClipboardWorker {
        sender: tx,
        thread: Some(thread),
    }
}
