use crate::error::{Result, VaultError};
use std::{fmt, time::Duration};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct Secret(pub String);
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
#[derive(Clone, Debug)]
pub struct Generator {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    pub ambiguous: bool,
}
impl Default for Generator {
    fn default() -> Self {
        Self {
            length: 24,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            ambiguous: false,
        }
    }
}
impl Generator {
    pub fn generate(&self) -> Result<Zeroizing<String>> {
        if !(8..=128).contains(&self.length) {
            return Err(VaultError::Limit);
        }
        let mut groups: Vec<Vec<u8>> = Vec::new();
        for (enabled, chars) in [
            (self.lower, b"abcdefghijklmnopqrstuvwxyz".as_slice()),
            (self.upper, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ".as_slice()),
            (self.digits, b"0123456789".as_slice()),
            (self.symbols, b"!@#$%^&*()-_=+[]{}:,.?".as_slice()),
        ] {
            if enabled {
                groups.push(
                    chars
                        .iter()
                        .copied()
                        .filter(|c| self.ambiguous || !b"0O1lI|".contains(c))
                        .collect(),
                );
            }
        }
        if groups.is_empty() {
            return Err(VaultError::InvalidEntry);
        }
        let alphabet: Vec<u8> = groups.iter().flatten().copied().collect();
        // Rejection sampling avoids modulo bias; rejecting whole candidates gives a
        // uniform distribution over strings containing every selected character class.
        for _ in 0..4096 {
            let mut bytes = Zeroizing::new(Vec::with_capacity(self.length));
            for _ in 0..self.length {
                bytes.push(alphabet[random_index(alphabet.len())?]);
            }
            if groups.iter().all(|g| bytes.iter().any(|c| g.contains(c))) {
                let text = String::from_utf8(std::mem::take(&mut *bytes))
                    .map_err(|_| VaultError::Random)?;
                return Ok(Zeroizing::new(text));
            }
        }
        Err(VaultError::Random)
    }
}
fn random_index(bound: usize) -> Result<usize> {
    let ceiling = 256usize / bound * bound;
    for _ in 0..4096 {
        let mut byte = [0];
        getrandom::fill(&mut byte).map_err(|_| VaultError::Random)?;
        if (byte[0] as usize) < ceiling {
            return Ok(byte[0] as usize % bound);
        }
    }
    Err(VaultError::Random)
}

/// Implementations must check ownership while holding the OS clipboard lock.
pub trait Clipboard: Send {
    fn read_text(&mut self) -> Result<Zeroizing<String>> {
        Err(VaultError::Clipboard)
    }
    fn write_secret(&mut self, text: &str) -> Result<u64>;
    fn clear_if_owned(&mut self, token: u64) -> Result<bool>;
}
pub struct ClipboardLease<C: Clipboard> {
    pub adapter: C,
    pending: Option<(u64, Duration)>,
}
impl<C: Clipboard> ClipboardLease<C> {
    pub fn new(adapter: C) -> Self {
        Self {
            adapter,
            pending: None,
        }
    }
    pub fn copy(&mut self, text: &str, now: Duration, ttl: Duration) -> Result<()> {
        self.clear()?;
        let token = self.adapter.write_secret(text)?;
        self.pending = Some((token, now + ttl));
        Ok(())
    }
    pub fn tick(&mut self, now: Duration) -> Result<()> {
        if self.pending.is_some_and(|(_, until)| now >= until) {
            self.clear()?;
        }
        Ok(())
    }
    pub fn clear(&mut self) -> Result<()> {
        if let Some((token, _)) = self.pending {
            self.adapter.clear_if_owned(token)?;
            self.pending = None;
        }
        Ok(())
    }
}
impl<C: Clipboard> Drop for ClipboardLease<C> {
    fn drop(&mut self) {
        let _ = self.clear();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    Manual,
    Idle,
    WindowsSession,
}
pub struct IdleGuard {
    last: Duration,
    timeout: Duration,
    locked: bool,
}
impl IdleGuard {
    pub fn new(now: Duration, timeout: Duration) -> Self {
        Self {
            last: now,
            timeout,
            locked: true,
        }
    }
    pub fn unlock(&mut self, now: Duration) {
        self.last = now;
        self.locked = false;
    }
    pub fn activity(&mut self, now: Duration) {
        if !self.locked {
            self.last = now;
        }
    }
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }
    pub fn poll(&mut self, now: Duration, session_locked: bool) -> Option<LockReason> {
        if self.locked {
            return None;
        }
        let reason = if session_locked {
            Some(LockReason::WindowsSession)
        } else if now.saturating_sub(self.last) >= self.timeout {
            Some(LockReason::Idle)
        } else {
            None
        };
        if reason.is_some() {
            self.locked = true;
        }
        reason
    }
    pub fn lock(&mut self) {
        self.locked = true;
    }
}
