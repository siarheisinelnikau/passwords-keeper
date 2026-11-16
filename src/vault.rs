use crate::{
    error::{Result, VaultError},
    preflight,
    storage::{self, Fingerprint},
};
use keepass::{
    Database, DatabaseKey,
    config::{DatabaseConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig},
    db::{Entry, Group, Node, Times, Value},
    secret::SecStr,
};
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Clone, Default, Zeroize, ZeroizeOnDrop, serde::Serialize, serde::Deserialize)]
pub struct EntryDraft {
    #[zeroize(skip)]
    pub id: Option<Uuid>,
    #[zeroize(skip)]
    pub group: Uuid,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
}
impl std::fmt::Debug for EntryDraft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EntryDraft([REDACTED])")
    }
}
#[derive(Clone, Debug)]
pub struct EntrySummary {
    pub id: Uuid,
    pub group: Uuid,
    pub title: String,
    pub username: String,
    pub url: String,
}
#[derive(Clone, Debug)]
pub struct GroupSummary {
    pub id: Uuid,
    pub name: String,
    pub depth: usize,
}
#[derive(Clone, Default, Debug)]
pub struct Catalog {
    pub groups: Vec<GroupSummary>,
    pub entries: Vec<EntrySummary>,
    pub dirty: bool,
}

pub struct Vault {
    db: Database,
    password: Zeroizing<String>,
    pub path: PathBuf,
    stamp: Option<Fingerprint>,
    pub dirty: bool,
}
pub struct SealedVault {
    data: Vec<u8>,
    path: PathBuf,
    stamp: Option<Fingerprint>,
    dirty: bool,
    draft_id: Option<Uuid>,
    draft_origin: Option<(Option<Uuid>, Uuid)>,
}
impl SealedVault {
    pub fn unlock(&self, password: Zeroizing<String>) -> Result<(Vault, Option<EntryDraft>)> {
        preflight::check(&self.data)?;
        let db = Database::parse(&self.data, DatabaseKey::new().with_password(&password))
            .map_err(|_| VaultError::Credentials)?;
        let mut vault = Vault {
            db,
            password,
            path: self.path.clone(),
            stamp: self.stamp.clone(),
            dirty: self.dirty,
        };
        let draft = if let Some(id) = self.draft_id {
            let mut e = take_entry(&mut vault.db.root, id).ok_or(VaultError::Corrupt)?;
            let (id, group) = self.draft_origin.ok_or(VaultError::Corrupt)?;
            let draft = EntryDraft {
                id,
                group,
                title: e.get_title().unwrap_or_default().into(),
                username: e.get_username().unwrap_or_default().into(),
                password: e.get_password().unwrap_or_default().into(),
                url: e.get_url().unwrap_or_default().into(),
                notes: e.get("Notes").unwrap_or_default().into(),
            };
            wipe_entry(&mut e);
            Some(draft)
        } else {
            None
        };
        vault.validate_and_protect()?;
        Ok((vault, draft))
    }
}
impl Vault {
    pub fn authenticate(&self, password: &str) -> bool {
        use subtle::ConstantTimeEq;
        self.password.as_bytes().ct_eq(password.as_bytes()).into()
    }
    pub fn create(path: PathBuf, password: Zeroizing<String>) -> Result<Self> {
        if password.chars().count() < 12 || password.len() > 4096 {
            return Err(VaultError::InvalidEntry);
        }
        let config = DatabaseConfig {
            kdf_config: KdfConfig::Argon2id {
                iterations: 3,
                memory: 64 * 1024 * 1024,
                parallelism: 1,
                version: keepass_argon_version(),
            },
            ..Default::default()
        };
        let mut db = Database::new(config);
        db.root.name = "Vault".into();
        db.meta.generator = Some("Passwords Keeper".into());
        let path = storage::absolute(&path)?;
        Ok(Self {
            db,
            password,
            path,
            stamp: None,
            dirty: true,
        })
    }
    pub fn open(path: PathBuf, password: Zeroizing<String>) -> Result<Self> {
        let path = storage::absolute(&path)?;
        let (data, stamp) = storage::read(&path)?;
        preflight::check(&data)?;
        let db = Database::parse(&data, DatabaseKey::new().with_password(&password)).map_err(
            |e| match e {
                keepass::error::DatabaseOpenError::Key(_) => VaultError::Credentials,
                keepass::error::DatabaseOpenError::UnsupportedVersion => VaultError::Unsupported,
                keepass::error::DatabaseOpenError::DatabaseIntegrity(
                    keepass::error::DatabaseIntegrityError::Xml(
                        keepass::error::XmlParseError::Unsupported,
                    ),
                ) => VaultError::Unsupported,
                keepass::error::DatabaseOpenError::DatabaseIntegrity(
                    keepass::error::DatabaseIntegrityError::Xml(
                        keepass::error::XmlParseError::ResourceLimit,
                    ),
                ) => VaultError::Limit,
                keepass::error::DatabaseOpenError::Io(ref e)
                    if e.kind() == std::io::ErrorKind::InvalidData =>
                {
                    VaultError::Limit
                }
                _ => VaultError::Corrupt,
            },
        )?;
        let mut vault = Self {
            db,
            password,
            path,
            stamp: Some(stamp),
            dirty: false,
        };
        vault.validate_and_protect()?;
        Ok(vault)
    }
    fn validate_and_protect(&mut self) -> Result<()> {
        if !self.db.header_attachments.is_empty() {
            return Err(VaultError::Unsupported);
        }
        fn visit(
            group: &mut Group,
            depth: usize,
            count: &mut usize,
            ids: &mut std::collections::HashSet<Uuid>,
        ) -> Result<()> {
            *count += 1;
            if depth > preflight::MAX_DEPTH || *count > preflight::MAX_ITEMS {
                return Err(VaultError::Limit);
            }
            if !ids.insert(group.uuid) {
                return Err(VaultError::Corrupt);
            }
            for child in &mut group.children {
                match child {
                    Node::Group(g) => visit(g, depth + 1, count, ids)?,
                    Node::Entry(e) => {
                        *count += 1;
                        if *count > preflight::MAX_ITEMS || !ids.insert(e.uuid) {
                            return Err(VaultError::Corrupt);
                        }
                        // Protect every owned field, including imported plaintext passwords.
                        for value in e.fields.values_mut() {
                            if let Value::Unprotected(s) = value {
                                *value =
                                    Value::Protected(SecStr::new(std::mem::take(s).into_bytes()));
                            }
                        }
                    }
                }
            }
            Ok(())
        }
        visit(
            &mut self.db.root,
            0,
            &mut 0,
            &mut std::collections::HashSet::new(),
        )
    }
    pub fn catalog(&self) -> Catalog {
        fn walk(g: &Group, depth: usize, out: &mut Catalog) {
            out.groups.push(GroupSummary {
                id: g.uuid,
                name: g.name.clone(),
                depth,
            });
            for n in &g.children {
                match n {
                    Node::Group(c) => walk(c, depth + 1, out),
                    Node::Entry(e) => out.entries.push(EntrySummary {
                        id: e.uuid,
                        group: g.uuid,
                        title: e.get_title().unwrap_or_default().into(),
                        username: e.get_username().unwrap_or_default().into(),
                        url: e.get_url().unwrap_or_default().into(),
                    }),
                }
            }
        }
        let mut result = Catalog {
            dirty: self.dirty,
            ..Default::default()
        };
        walk(&self.db.root, 0, &mut result);
        result.entries.sort_by_key(|e| e.title.to_lowercase());
        result
    }
    pub fn entry(&self, id: Uuid) -> Result<EntryDraft> {
        fn find(g: &Group, id: Uuid) -> Option<(&Entry, Uuid)> {
            for n in &g.children {
                match n {
                    Node::Entry(e) if e.uuid == id => return Some((e, g.uuid)),
                    Node::Group(c) => {
                        if let Some(e) = find(c, id) {
                            return Some(e);
                        }
                    }
                    _ => {}
                }
            }
            None
        }
        let (e, group) = find(&self.db.root, id).ok_or(VaultError::NotFound)?;
        Ok(EntryDraft {
            id: Some(e.uuid),
            group,
            title: e.get_title().unwrap_or_default().into(),
            username: e.get_username().unwrap_or_default().into(),
            password: e.get_password().unwrap_or_default().into(),
            url: e.get_url().unwrap_or_default().into(),
            notes: e.get("Notes").unwrap_or_default().into(),
        })
    }
    pub fn put(&mut self, draft: &EntryDraft) -> Result<Uuid> {
        if draft.title.trim().is_empty()
            || [
                draft.title.len(),
                draft.username.len(),
                draft.password.len(),
                draft.url.len(),
                draft.notes.len(),
            ]
            .iter()
            .any(|n| *n > 256 * 1024)
        {
            return Err(VaultError::InvalidEntry);
        }
        if group(&self.db.root, draft.group).is_none() {
            return Err(VaultError::InvalidEntry);
        }
        let count = self.catalog();
        if draft.id.is_none() && count.entries.len() + count.groups.len() >= preflight::MAX_ITEMS {
            return Err(VaultError::Limit);
        }
        let mut entry = match draft.id {
            Some(id) => take_entry(&mut self.db.root, id).ok_or(VaultError::NotFound)?,
            None => Entry::new(),
        };
        for (key, val) in [
            ("Title", &draft.title),
            ("UserName", &draft.username),
            ("Password", &draft.password),
            ("URL", &draft.url),
            ("Notes", &draft.notes),
        ] {
            if let Some(mut old) = entry.fields.insert(
                key.into(),
                Value::Protected(SecStr::new(val.as_bytes().to_vec())),
            ) {
                wipe_value(&mut old);
            }
        }
        entry.times.set_last_modification(Times::now());
        let id = entry.uuid;
        group_mut(&mut self.db.root, draft.group)
            .ok_or(VaultError::InvalidEntry)?
            .add_child(entry);
        self.dirty = true;
        Ok(id)
    }
    pub fn add_group(&mut self, parent: Uuid, name: &str) -> Result<Uuid> {
        if name.trim().is_empty()
            || name.chars().any(char::is_control)
            || name.len() > 256
            || self.catalog().groups.len() >= 512
        {
            return Err(VaultError::InvalidEntry);
        }
        let catalog = self.catalog();
        if catalog.entries.len() + catalog.groups.len() >= preflight::MAX_ITEMS {
            return Err(VaultError::Limit);
        }
        fn depth(g: &Group, id: Uuid, level: usize) -> Option<usize> {
            if g.uuid == id {
                return Some(level);
            }
            g.children.iter().find_map(|n| {
                if let Node::Group(c) = n {
                    depth(c, id, level + 1)
                } else {
                    None
                }
            })
        }
        if depth(&self.db.root, parent, 0).ok_or(VaultError::NotFound)? >= preflight::MAX_DEPTH {
            return Err(VaultError::Limit);
        }
        let g = Group::new(name.trim());
        let id = g.uuid;
        let parent = group_mut(&mut self.db.root, parent).ok_or(VaultError::NotFound)?;
        parent.add_child(g);
        self.dirty = true;
        Ok(id)
    }
    pub fn rename_group(&mut self, id: Uuid, name: &str) -> Result<()> {
        if name.trim().is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
            return Err(VaultError::InvalidEntry);
        }
        let g = group_mut(&mut self.db.root, id).ok_or(VaultError::NotFound)?;
        g.name = name.trim().into();
        g.times.set_last_modification(Times::now());
        self.dirty = true;
        Ok(())
    }
    pub fn delete_entry(&mut self, id: Uuid) -> Result<()> {
        let mut e = take_entry(&mut self.db.root, id).ok_or(VaultError::NotFound)?;
        wipe_entry(&mut e);
        self.dirty = true;
        Ok(())
    }
    pub fn delete_group(&mut self, id: Uuid) -> Result<()> {
        fn remove(g: &mut Group, id: Uuid) -> bool {
            if let Some(i) = g
                .children
                .iter()
                .position(|n| matches!(n,Node::Group(c) if c.uuid==id && c.children.is_empty()))
            {
                g.children.remove(i);
                return true;
            }
            g.children.iter_mut().any(|n| {
                if let Node::Group(c) = n {
                    remove(c, id)
                } else {
                    false
                }
            })
        }
        if !remove(&mut self.db.root, id) {
            return Err(VaultError::InvalidEntry);
        }
        self.dirty = true;
        Ok(())
    }
    pub fn encrypted(&self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        self.db
            .save(&mut data, DatabaseKey::new().with_password(&self.password))
            .map_err(|_| VaultError::Corrupt)?;
        preflight::check(&data)?;
        Ok(data)
    }
    pub fn save(&mut self, cancel: &AtomicBool) -> Result<()> {
        if cancel.load(Ordering::SeqCst) {
            return Err(VaultError::Cancelled);
        }
        let bytes = self.encrypted()?;
        let stamp = storage::save(&self.path, &bytes, self.stamp.as_ref(), cancel)?;
        self.stamp = Some(stamp);
        self.dirty = false;
        Ok(())
    }
    pub fn export(&self, path: &Path) -> Result<()> {
        if storage::absolute(path)? == self.path {
            return Err(VaultError::Conflict);
        }
        storage::save_new(path, &self.encrypted()?)?;
        Ok(())
    }
    pub fn recover_unsaved(&self) -> Result<PathBuf> {
        let data = self.encrypted()?;
        let base = storage::recovery_path(&self.path);
        let path = if base.exists() {
            self.path
                .with_file_name(format!("recovery-{}.kdbx", Uuid::new_v4()))
        } else {
            base
        };
        storage::save_new(&path, &data)?;
        Ok(path)
    }
    pub fn seal(&mut self, draft: Option<&EntryDraft>) -> Result<SealedVault> {
        let draft_id = if let Some(draft) = draft {
            let mut e = Entry::new();
            let id = e.uuid;
            for (name, value) in [
                ("Title", &draft.title),
                ("UserName", &draft.username),
                ("Password", &draft.password),
                ("URL", &draft.url),
                ("Notes", &draft.notes),
            ] {
                if value.len() > 256 * 1024 {
                    return Err(VaultError::Limit);
                }
                e.fields.insert(
                    name.into(),
                    Value::Protected(SecStr::new(value.as_bytes().to_vec())),
                );
            }
            self.db.root.add_child(e);
            Some(id)
        } else {
            None
        };
        let result = self.encrypted();
        if let Some(id) = draft_id
            && let Some(mut e) = take_entry(&mut self.db.root, id)
        {
            wipe_entry(&mut e);
        }
        Ok(SealedVault {
            data: result?,
            path: self.path.clone(),
            stamp: self.stamp.clone(),
            dirty: self.dirty,
            draft_id,
            draft_origin: draft.map(|d| (d.id, d.group)),
        })
    }
    pub fn set_cipher(&mut self, chacha: bool) {
        self.db.config.outer_cipher_config = if chacha {
            OuterCipherConfig::ChaCha20
        } else {
            OuterCipherConfig::AES256
        };
        self.db.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
        self.dirty = true;
    }
}
fn keepass_argon_version() -> argon2::Version {
    argon2::Version::V0x13
}
fn group(g: &Group, id: Uuid) -> Option<&Group> {
    if g.uuid == id {
        return Some(g);
    }
    g.children.iter().find_map(|n| {
        if let Node::Group(c) = n {
            group(c, id)
        } else {
            None
        }
    })
}
fn group_mut(g: &mut Group, id: Uuid) -> Option<&mut Group> {
    if g.uuid == id {
        return Some(g);
    }
    g.children.iter_mut().find_map(|n| {
        if let Node::Group(c) = n {
            group_mut(c, id)
        } else {
            None
        }
    })
}
fn take_entry(g: &mut Group, id: Uuid) -> Option<Entry> {
    if let Some(i) = g
        .children
        .iter()
        .position(|n| matches!(n,Node::Entry(e) if e.uuid==id))
        && let Node::Entry(e) = g.children.remove(i)
    {
        return Some(e);
    }
    g.children.iter_mut().find_map(|n| {
        if let Node::Group(c) = n {
            take_entry(c, id)
        } else {
            None
        }
    })
}
fn wipe_value(v: &mut Value) {
    match v {
        Value::Bytes(b) => b.zeroize(),
        Value::Unprotected(s) => s.zeroize(),
        Value::Protected(_) => {}
    }
}
fn wipe_entry(e: &mut Entry) {
    e.erase_owned_fields();
}
impl Drop for Vault {
    fn drop(&mut self) {
        fn wipe(g: &mut Group) {
            g.name.zeroize();
            g.notes.zeroize();
            for n in &mut g.children {
                match n {
                    Node::Entry(e) => wipe_entry(e),
                    Node::Group(c) => wipe(c),
                }
            }
        }
        wipe(&mut self.db.root);
    }
}

pub fn search<'a>(
    catalog: &'a Catalog,
    selected: Option<Uuid>,
    query: &str,
) -> Vec<&'a EntrySummary> {
    let words: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    catalog
        .entries
        .iter()
        .filter(|e| {
            selected.is_none_or(|g| e.group == g)
                && words.iter().all(|w| {
                    [&e.title, &e.username, &e.url]
                        .iter()
                        .any(|v| v.to_lowercase().contains(w))
                })
        })
        .collect()
}
