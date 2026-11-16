//! KeePass key-file normalization. No key bytes are persisted in preferences.
use crate::error::{Result, VaultError};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;
pub const MAX_KEY_FILE: usize = 1024 * 1024;

pub fn read(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let file = File::open(path)?;
    if file.metadata()?.len() > MAX_KEY_FILE as u64 {
        return Err(VaultError::KeyFile);
    }
    let mut data = Zeroizing::new(Vec::new());
    file.take(MAX_KEY_FILE as u64 + 1).read_to_end(&mut data)?;
    decode(&data)
}
fn hex(data: &str) -> Result<Zeroizing<Vec<u8>>> {
    let clean = Zeroizing::new(
        data.chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<String>(),
    );
    if clean.len() != 64 || !clean.is_ascii() {
        return Err(VaultError::KeyFile);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(32));
    for pair in clean.as_bytes().chunks_exact(2) {
        let digit = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        };
        bytes.push(
            digit(pair[0]).ok_or(VaultError::KeyFile)? * 16
                + digit(pair[1]).ok_or(VaultError::KeyFile)?,
        );
    }
    Ok(bytes)
}
fn key(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    Ok(Zeroizing::new(
        bytes.try_into().map_err(|_| VaultError::KeyFile)?,
    ))
}
pub fn decode(data: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if data.is_empty() || data.len() > MAX_KEY_FILE || data.starts_with(&[3, 0xd9, 0xa2, 0x9a]) {
        return Err(VaultError::KeyFile);
    }
    if data.len() == 32 {
        return key(data);
    }
    if data.len() == 64 && data.iter().all(u8::is_ascii_hexdigit) {
        return key(&hex(
            std::str::from_utf8(data).map_err(|_| VaultError::KeyFile)?
        )?);
    }
    let utf8 = std::str::from_utf8(data).ok();
    if utf8.is_some_and(|s| {
        s.trim_start_matches('\u{feff}')
            .trim_start()
            .starts_with('<')
    }) {
        if data
            .windows(9)
            .any(|v| v.eq_ignore_ascii_case(b"<!DOCTYPE"))
        {
            return Err(VaultError::KeyFile);
        }
        let parser = xml::reader::ParserConfig2::new()
            .max_name_length(64)
            .max_attributes(8)
            .max_attribute_length(128)
            .max_data_length(4096)
            .max_entity_expansion_length(128)
            .allow_multiple_root_elements(false)
            .create_reader(data);
        let mut stack = Vec::new();
        let mut recognized = false;
        let mut version = String::new();
        let mut value = Zeroizing::new(String::new());
        let mut checksum = None;
        let mut seen_version = false;
        let mut seen_value = false;
        for event in parser {
            let event = match event {
                Ok(event) => event,
                Err(_) if !recognized => break,
                Err(_) => return Err(VaultError::KeyFile),
            };
            match event {
                xml::reader::XmlEvent::StartElement {
                    name, attributes, ..
                } => {
                    if stack.is_empty() {
                        recognized = name.local_name == "KeyFile";
                        if !recognized {
                            break;
                        }
                    }
                    if name.namespace.is_some() || name.prefix.is_some() {
                        return Err(VaultError::KeyFile);
                    }
                    stack.push(name.local_name);
                    match stack
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .as_slice()
                    {
                        ["KeyFile"] | ["KeyFile", "Meta"] | ["KeyFile", "Key"] => {}
                        ["KeyFile", "Meta", "Version"] => {
                            if seen_version {
                                return Err(VaultError::KeyFile);
                            }
                            seen_version = true;
                        }
                        ["KeyFile", "Key", "Data"] => {
                            if seen_value {
                                return Err(VaultError::KeyFile);
                            }
                            seen_value = true;
                            for attribute in attributes {
                                if attribute.name.local_name != "Hash" || checksum.is_some() {
                                    return Err(VaultError::KeyFile);
                                }
                                checksum = Some(attribute.value);
                            }
                        }
                        _ => return Err(VaultError::KeyFile),
                    }
                }
                xml::reader::XmlEvent::EndElement { .. } => {
                    stack.pop();
                }
                xml::reader::XmlEvent::Characters(text) | xml::reader::XmlEvent::CData(text) => {
                    if stack.last().is_some_and(|v| v == "Version") {
                        version.push_str(&text);
                    } else if stack.last().is_some_and(|v| v == "Data") {
                        value.push_str(&text);
                    } else if !text.trim().is_empty() {
                        return Err(VaultError::KeyFile);
                    }
                }
                _ => {}
            }
        }
        if recognized {
            if !stack.is_empty() || !seen_version || !seen_value {
                return Err(VaultError::KeyFile);
            }
            return match version.trim() {
                "1.0" | "1.00" => {
                    let clean = Zeroizing::new(
                        value
                            .chars()
                            .filter(|c| !c.is_ascii_whitespace())
                            .collect::<String>(),
                    );
                    let decoded = Zeroizing::new(
                        STANDARD
                            .decode(clean.as_bytes())
                            .map_err(|_| VaultError::KeyFile)?,
                    );
                    key(&decoded)
                }
                "2.0" => {
                    let decoded = hex(&value)?;
                    let expected = checksum.ok_or(VaultError::KeyFile)?;
                    let actual = Sha256::digest(&decoded);
                    if expected.len() != 8
                        || !expected.is_ascii()
                        || !actual[..4]
                            .iter()
                            .map(|v| format!("{v:02X}"))
                            .collect::<String>()
                            .eq_ignore_ascii_case(&expected)
                    {
                        return Err(VaultError::KeyFile);
                    }
                    key(&decoded)
                }
                _ => Err(VaultError::KeyFile),
            };
        }
    }
    Ok(Zeroizing::new(Sha256::digest(data).into()))
}
pub fn generate(path: &Path) -> Result<()> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| VaultError::Random)?;
    let digest = Sha256::digest(bytes.as_ref());
    let body = Zeroizing::new(bytes.iter().map(|v| format!("{v:02X}")).collect::<String>());
    let checksum = digest[..4]
        .iter()
        .map(|v| format!("{v:02X}"))
        .collect::<String>();
    let xml = Zeroizing::new(format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"{checksum}\">{}</Data></Key></KeyFile>\n",
        body.as_str()
    ));
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(xml.as_bytes())?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)
        .map_err(|e| VaultError::Io(e.error))?;
    Ok(())
}
