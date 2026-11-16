//! Owned secret bytes, zeroed on drop. This does not prevent OS paging or copies.
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct SecStr(Zeroizing<Vec<u8>>);
impl SecStr {
    pub fn new(bytes: Vec<u8>) -> Self { Self(Zeroizing::new(bytes)) }
    pub fn unsecure(&self) -> &[u8] { &self.0 }
}
impl From<Vec<u8>> for SecStr {
    fn from(value: Vec<u8>) -> Self { Self::new(value) }
}
impl From<String> for SecStr {
    fn from(value: String) -> Self { Self::new(value.into_bytes()) }
}
impl std::fmt::Debug for SecStr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("[REDACTED]") }
}
impl PartialEq for SecStr {
    fn eq(&self, other: &Self) -> bool { self.unsecure().ct_eq(other.unsecure()).into() }
}
impl Eq for SecStr {}
