use crate::{
    error::{Result, VaultError},
    keyfile,
};
use keepass::DatabaseKey;
use std::path::PathBuf;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub struct CredentialsInput {
    pub password: Option<Zeroizing<String>>,
    pub key_file: Option<PathBuf>,
}
impl CredentialsInput {
    pub fn password(password: Zeroizing<String>) -> Self {
        Self {
            password: Some(password),
            key_file: None,
        }
    }
    pub fn load(self) -> Result<Credentials> {
        let key_file = self.key_file.as_deref().map(keyfile::read).transpose()?;
        let value = Credentials {
            password: self.password,
            key_file,
        };
        value.validate(false)?;
        Ok(value)
    }
}
pub struct Credentials {
    password: Option<Zeroizing<String>>,
    key_file: Option<Zeroizing<[u8; 32]>>,
}
impl Credentials {
    pub fn password(password: Zeroizing<String>) -> Self {
        Self {
            password: Some(password),
            key_file: None,
        }
    }
    pub fn validate(&self, creating: bool) -> Result<()> {
        if self.password.is_none() && self.key_file.is_none() {
            return Err(VaultError::CredentialsRequired);
        }
        if let Some(password) = &self.password {
            if password.len() > 4096 {
                return Err(VaultError::Limit);
            }
            if creating && password.chars().count() < 12 {
                return Err(VaultError::CredentialsRequired);
            }
        }
        Ok(())
    }
    pub fn database_key(&self) -> DatabaseKey {
        let mut key = DatabaseKey::new();
        if let Some(password) = &self.password {
            key = key.with_password(password);
        }
        if let Some(component) = &self.key_file {
            key = key.with_keyfile_component(component);
        }
        key
    }
    pub fn matches(&self, other: &Self) -> bool {
        let password = match (&self.password, &other.password) {
            (Some(a), Some(b)) => bool::from(a.as_bytes().ct_eq(b.as_bytes())),
            (None, None) => true,
            _ => false,
        };
        let key = match (&self.key_file, &other.key_file) {
            (Some(a), Some(b)) => bool::from(a.as_ref().ct_eq(b.as_ref())),
            (None, None) => true,
            _ => false,
        };
        password & key
    }
}
