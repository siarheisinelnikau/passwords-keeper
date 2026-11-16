use crate::{
    credentials::Credentials,
    error::{Result, VaultError},
    preflight,
    storage::{self, Fingerprint},
};
use keepass::{
    Database,
    config::{DatabaseConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig},
    db::{Entry, Group, HeaderAttachment, Node, Times, Value},
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
    pub attachments: Vec<AttachmentSummary>,
}
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop, serde::Serialize, serde::Deserialize)]
pub struct AttachmentSummary {
    pub name: String,
    pub size: usize,
}
pub const MAX_ATTACHMENT: usize = 8 * 1024 * 1024;
pub const MAX_ATTACHMENT_TOTAL: usize = 16 * 1024 * 1024;
pub const MAX_ATTACHMENTS: usize = 256;
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
    credentials: Credentials,
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
        self.unlock_with_credentials(Credentials::password(password))
    }
    pub fn unlock_with_credentials(
        &self,
        credentials: Credentials,
    ) -> Result<(Vault, Option<EntryDraft>)> {
        preflight::check(&self.data)?;
        let db = Database::parse(&self.data, credentials.database_key())
            .map_err(|_| VaultError::Credentials)?;
        let mut vault = Vault {
            db,
            credentials,
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
                attachments: if let Some(id) = id {
                    vault.attachment_summaries(id)?
                } else {
                    Vec::new()
                },
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
        self.credentials
            .matches(&Credentials::password(Zeroizing::new(password.to_owned())))
    }
    pub fn authenticate_credentials(&self, credentials: &Credentials) -> bool {
        self.credentials.matches(credentials)
    }
    pub fn create(path: PathBuf, password: Zeroizing<String>) -> Result<Self> {
        Self::create_with_credentials(path, Credentials::password(password))
    }
    pub fn create_with_credentials(path: PathBuf, credentials: Credentials) -> Result<Self> {
        credentials.validate(true)?;
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
            credentials,
            path,
            stamp: None,
            dirty: true,
        })
    }
    pub fn open(path: PathBuf, password: Zeroizing<String>) -> Result<Self> {
        Self::open_with_credentials(path, Credentials::password(password))
    }
    pub fn open_with_credentials(path: PathBuf, credentials: Credentials) -> Result<Self> {
        credentials.validate(false)?;
        let path = storage::absolute(&path)?;
        let (data, stamp) = storage::read(&path)?;
        preflight::check(&data)?;
        let db = Database::parse(&data, credentials.database_key()).map_err(|e| match e {
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
        })?;
        let mut vault = Self {
            db,
            credentials,
            path,
            stamp: Some(stamp),
            dirty: false,
        };
        vault.validate_and_protect()?;
        Ok(vault)
    }
    fn validate_and_protect(&mut self) -> Result<()> {
        self.compact_attachments()?;
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
            attachments: self.attachment_summaries(id)?,
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
        self.compact_attachments()?;
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
        self.encrypted_with_credentials(&self.credentials)
    }
    fn encrypted_with_credentials(&self, credentials: &Credentials) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        self.db
            .save(&mut data, credentials.database_key())
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
    pub fn rekey(
        &mut self,
        credentials: Credentials,
        cancel: &AtomicBool,
    ) -> Result<Option<PathBuf>> {
        if cancel.load(Ordering::SeqCst) {
            return Err(VaultError::Cancelled);
        }
        credentials.validate(true)?;
        let bytes = self.encrypted_with_credentials(&credentials)?;
        let result = storage::save(&self.path, &bytes, self.stamp.as_ref(), cancel);
        let warning = match result {
            Ok(stamp) => {
                self.stamp = Some(stamp);
                None
            }
            Err(VaultError::ConflictRecovered(path)) => {
                self.stamp = Some(Fingerprint::of(&bytes));
                Some(path)
            }
            Err(error) => return Err(error),
        };
        self.credentials = credentials;
        self.dirty = false;
        Ok(warning)
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
    pub fn attachment_summaries(&self, id: Uuid) -> Result<Vec<AttachmentSummary>> {
        let entry = find_entry(&self.db.root, id).ok_or(VaultError::NotFound)?;
        let mut items = Vec::new();
        for (name, index) in &entry.attachments {
            let binary = self
                .db
                .header_attachments
                .get(*index)
                .ok_or(VaultError::Corrupt)?;
            items.push(AttachmentSummary {
                name: name.clone(),
                size: binary.content.len(),
            });
        }
        items.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(items)
    }
    fn compact_attachments(&mut self) -> Result<()> {
        let pool = &self.db.header_attachments;
        if pool.len() > MAX_ATTACHMENTS
            || pool.iter().any(|a| a.content.len() > MAX_ATTACHMENT)
            || pool.iter().map(|a| a.content.len()).sum::<usize>() > MAX_ATTACHMENT_TOTAL
        {
            return Err(VaultError::Limit);
        }
        let mut used = std::collections::BTreeSet::new();
        let mut invalid = false;
        visit_entries(&self.db.root, &mut |entry| {
            entry.visit_attachments(&mut |name, index| {
                if name.is_empty()
                    || name.len() > 256
                    || name.chars().any(char::is_control)
                    || index >= pool.len()
                {
                    invalid = true;
                }
                used.insert(index);
            })
        });
        if invalid {
            return Err(VaultError::Corrupt);
        }
        let mut mapping = vec![0; pool.len()];
        let mut compact = Vec::new();
        for (index, binary) in self.db.header_attachments.drain(..).enumerate() {
            if used.contains(&index) {
                mapping[index] = compact.len();
                compact.push(binary);
            }
        }
        visit_entries_mut(&mut self.db.root, &mut |entry| {
            entry.visit_attachments_mut(&mut |index| *index = mapping[*index])
        });
        self.db.header_attachments = compact;
        Ok(())
    }
    pub fn add_attachment(&mut self, id: Uuid, path: &Path) -> Result<()> {
        use std::io::Read;
        if find_entry(&self.db.root, id).is_none() {
            return Err(VaultError::NotFound);
        }
        let name = path
            .file_name()
            .and_then(|v| v.to_str())
            .ok_or(VaultError::InvalidEntry)?
            .to_owned();
        if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
            return Err(VaultError::InvalidEntry);
        }
        if find_entry(&self.db.root, id).is_some_and(|e| e.attachments.contains_key(&name)) {
            return Err(VaultError::AttachmentExists);
        }
        let file = std::fs::File::open(path)?;
        if file.metadata()?.len() > MAX_ATTACHMENT as u64 {
            return Err(VaultError::Limit);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(MAX_ATTACHMENT as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_ATTACHMENT {
            return Err(VaultError::Limit);
        }
        self.compact_attachments()?;
        let index = if let Some(index) = self
            .db
            .header_attachments
            .iter()
            .position(|v| v.content == *bytes)
        {
            index
        } else {
            if self.db.header_attachments.len() >= MAX_ATTACHMENTS
                || self
                    .db
                    .header_attachments
                    .iter()
                    .map(|a| a.content.len())
                    .sum::<usize>()
                    + bytes.len()
                    > MAX_ATTACHMENT_TOTAL
            {
                return Err(VaultError::Limit);
            }
            let index = self.db.header_attachments.len();
            self.db.header_attachments.push(HeaderAttachment {
                flags: 1,
                content: std::mem::take(&mut *bytes),
            });
            index
        };
        let entry = find_entry_mut(&mut self.db.root, id).ok_or(VaultError::NotFound)?;
        entry.attachments.insert(name, index);
        entry.times.set_last_modification(Times::now());
        self.dirty = true;
        Ok(())
    }
    pub fn remove_attachment(&mut self, id: Uuid, name: &str) -> Result<()> {
        let entry = find_entry_mut(&mut self.db.root, id).ok_or(VaultError::NotFound)?;
        entry.attachments.remove(name).ok_or(VaultError::NotFound)?;
        entry.times.set_last_modification(Times::now());
        self.compact_attachments()?;
        self.dirty = true;
        Ok(())
    }
    pub fn export_attachment(&self, id: Uuid, name: &str, path: &Path) -> Result<()> {
        use std::io::Write;
        let entry = find_entry(&self.db.root, id).ok_or(VaultError::NotFound)?;
        let index = entry.attachments.get(name).ok_or(VaultError::NotFound)?;
        let binary = self
            .db
            .header_attachments
            .get(*index)
            .ok_or(VaultError::Corrupt)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(&binary.content)?;
        file.as_file().sync_all()?;
        file.persist_noclobber(path)
            .map_err(|e| VaultError::Io(e.error))?;
        Ok(())
    }
}
fn find_entry(g: &Group, id: Uuid) -> Option<&Entry> {
    g.children.iter().find_map(|node| match node {
        Node::Entry(e) if e.uuid == id => Some(e),
        Node::Group(g) => find_entry(g, id),
        _ => None,
    })
}
fn find_entry_mut(g: &mut Group, id: Uuid) -> Option<&mut Entry> {
    g.children.iter_mut().find_map(|node| match node {
        Node::Entry(e) if e.uuid == id => Some(e),
        Node::Group(g) => find_entry_mut(g, id),
        _ => None,
    })
}
fn visit_entries(g: &Group, f: &mut impl FnMut(&Entry)) {
    for node in &g.children {
        match node {
            Node::Entry(e) => f(e),
            Node::Group(g) => visit_entries(g, f),
        }
    }
}
fn visit_entries_mut(g: &mut Group, f: &mut impl FnMut(&mut Entry)) {
    for node in &mut g.children {
        match node {
            Node::Entry(e) => f(e),
            Node::Group(g) => visit_entries_mut(g, f),
        }
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
