use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("The master password is incorrect, or the authenticated file was modified.")]
    Credentials,
    #[error("The vault is damaged or incomplete. The original file has not been changed.")]
    Corrupt,
    #[error("This KDBX feature is not supported by this version.")]
    Unsupported,
    #[error("The vault exceeds a safe resource limit.")]
    Limit,
    #[error("The vault changed outside this application. Save a copy, then reopen the original.")]
    Conflict,
    #[error("A late external change was preserved at {0}")]
    ConflictRecovered(std::path::PathBuf),
    #[error("Another save is in progress. Try again.")]
    Busy,
    #[error("The operation was cancelled. No file was replaced.")]
    Cancelled,
    #[error("The vault is locked.")]
    Locked,
    #[error("The requested item no longer exists.")]
    NotFound,
    #[error("A title and a valid destination group are required.")]
    InvalidEntry,
    #[error("Operating system randomness is unavailable.")]
    Random,
    #[error("The clipboard is unavailable. Try copying again.")]
    Clipboard,
    #[error("File access failed: {0}")]
    Io(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, VaultError>;
