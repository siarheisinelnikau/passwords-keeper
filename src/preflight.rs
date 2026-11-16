//! Resource and structural limits are checked before running any KDF.
use crate::error::{Result, VaultError};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const MAX_FILE: usize = 32 * 1024 * 1024;
pub const MAX_HEADER: usize = 64 * 1024;
pub const MAX_XML: usize = 32 * 1024 * 1024;
pub const MAX_DEPTH: usize = 64;
pub const MAX_ITEMS: usize = 5_000;
const AES: [u8; 16] = [
    0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff,
];
const CHACHA: [u8; 16] = [
    0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5, 0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb, 0xb5, 0x9a,
];
const AES_KDF: [u8; 16] = [
    0x7c, 0x02, 0xbb, 0x82, 0x79, 0xa7, 0x4a, 0xc0, 0x92, 0x7d, 0x11, 0x4a, 0x00, 0x64, 0x82, 0x38,
];
const AES_KDF_LEGACY: [u8; 16] = [
    0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f, 0xea,
];
const ARGON_D: [u8; 16] = [
    0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c,
];
const ARGON_ID: [u8; 16] = [
    0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6,
];

pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    pub pos: usize,
}
impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    pub fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or(VaultError::Limit)?;
        let value = self.data.get(self.pos..end).ok_or(VaultError::Corrupt)?;
        self.pos = end;
        Ok(value)
    }
    pub fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| VaultError::Corrupt)?,
        ))
    }
    pub fn field(&mut self) -> Result<(u8, &'a [u8])> {
        let id = self.byte()?;
        let len = self.u32()? as usize;
        Ok((id, self.take(len)?))
    }
}

fn number(bytes: &[u8], width: usize) -> Result<u64> {
    if bytes.len() != width {
        return Err(VaultError::Corrupt);
    }
    let mut out = [0; 8];
    out[..width].copy_from_slice(bytes);
    Ok(u64::from_le_bytes(out))
}
fn kdf(data: &[u8]) -> Result<()> {
    let mut r = Cursor::new(data);
    if r.take(2)? != [0, 1] {
        return Err(VaultError::Unsupported);
    }
    let mut fields = HashMap::new();
    loop {
        let kind = r.byte()?;
        if kind == 0 {
            break;
        }
        let key_len = r.u32()? as usize;
        if key_len > 32 {
            return Err(VaultError::Limit);
        }
        let key = r.take(key_len)?;
        let value_len = r.u32()? as usize;
        if value_len > 1024 {
            return Err(VaultError::Limit);
        }
        let value = r.take(value_len)?;
        if fields.insert(key, (kind, value)).is_some() {
            return Err(VaultError::Corrupt);
        }
    }
    if r.pos != data.len() {
        return Err(VaultError::Corrupt);
    }
    let get = |key: &[u8], kind: u8| -> Result<&[u8]> {
        let (t, v) = fields.get(key).ok_or(VaultError::Corrupt)?;
        if *t != kind {
            return Err(VaultError::Corrupt);
        }
        Ok(*v)
    };
    let id = get(b"$UUID", 0x42)?;
    let salt = get(b"S", 0x42)?;
    if id == AES_KDF || id == AES_KDF_LEGACY {
        if fields.len() != 3 || salt.len() != 32 {
            return Err(VaultError::Unsupported);
        }
        let rounds = number(get(b"R", 5)?, 8)?;
        if !(1..=10_000_000).contains(&rounds) {
            return Err(VaultError::Limit);
        }
    } else if id == ARGON_D || id == ARGON_ID {
        if fields.len() != 6 || !(8..=64).contains(&salt.len()) {
            return Err(VaultError::Unsupported);
        }
        let memory = number(get(b"M", 5)?, 8)?;
        let iterations = number(get(b"I", 5)?, 8)?;
        let parallelism = number(get(b"P", 4)?, 4)?;
        let version = number(get(b"V", 4)?, 4)?;
        if version != 0x13 {
            return Err(VaultError::Unsupported);
        }
        if !(1..=8).contains(&parallelism)
            || !(1..=16).contains(&iterations)
            || memory < 8192 * parallelism
            || memory > 256 * 1024 * 1024
            || memory % 1024 != 0
            || memory.saturating_mul(iterations) > 1024 * 1024 * 1024
        {
            return Err(VaultError::Limit);
        }
    } else {
        return Err(VaultError::Unsupported);
    }
    Ok(())
}

pub fn check(data: &[u8]) -> Result<()> {
    if data.len() > MAX_FILE {
        return Err(VaultError::Limit);
    }
    let mut r = Cursor::new(data);
    if r.take(8)? != [3, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5] {
        return Err(VaultError::Unsupported);
    }
    // Strictly KDBX 4.0: later XML extensions must not silently disappear on save.
    if r.u32()? != 0x0004_0000 {
        return Err(VaultError::Unsupported);
    }
    let mut fields = HashMap::new();
    loop {
        let (id, v) = r.field()?;
        if r.pos > MAX_HEADER {
            return Err(VaultError::Limit);
        }
        if fields.insert(id, v).is_some() {
            return Err(VaultError::Corrupt);
        }
        if id == 0 {
            if v != [13, 10, 13, 10] {
                return Err(VaultError::Corrupt);
            }
            break;
        }
        if ![1, 2, 3, 4, 7, 11].contains(&id) {
            return Err(VaultError::Unsupported);
        }
    }
    let end = r.pos;
    let cipher = fields.get(&2).ok_or(VaultError::Corrupt)?;
    if *cipher != AES && *cipher != CHACHA {
        return Err(VaultError::Unsupported);
    }
    let iv = fields.get(&7).ok_or(VaultError::Corrupt)?;
    if iv.len() != if *cipher == AES { 16 } else { 12 }
        || fields.get(&4).map(|v| v.len()) != Some(32)
    {
        return Err(VaultError::Corrupt);
    }
    let compression = number(fields.get(&3).ok_or(VaultError::Corrupt)?, 4)?;
    if compression > 1 {
        return Err(VaultError::Unsupported);
    }
    kdf(fields.get(&11).ok_or(VaultError::Corrupt)?)?;
    if r.take(32)? != Sha256::digest(&data[..end]).as_slice() {
        return Err(VaultError::Corrupt);
    }
    r.take(32)?;
    // Require the authenticated terminal block, reject trailing bytes and oversized chunks.
    let mut blocks = 0;
    loop {
        r.take(32)?;
        let size = r.u32()? as usize;
        if size > MAX_FILE || blocks > 32_768 {
            return Err(VaultError::Limit);
        }
        r.take(size)?;
        blocks += 1;
        if size == 0 {
            break;
        }
    }
    if r.pos != data.len() {
        return Err(VaultError::Corrupt);
    }
    Ok(())
}
