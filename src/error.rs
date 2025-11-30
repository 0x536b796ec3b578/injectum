//! Centralized error handling types for the library.
//!
//! This module leverages the `thiserror` crate to provide a unified [`Error`] enum
//! that aggregates low-level OS failures (IO, Win32), logical inconsistencies
//! (Validation, Mismatch), and runtime execution errors.

/// A convenience alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// The exhaustive list of failure modes for the injection lifecycle.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Wraps standard Input/Output failures (e.g., file not found, permission denied).
    #[error("{0}")]
    Io(#[from] std::io::Error),

    /// A raw Operating System API failure.
    ///
    /// Contains the name of the failed function and the raw error code (decimal).
    #[error("Win32 API '{0}' failed with error code: {1}")]
    Win32(&'static str, u32),

    /// The configuration or builder arguments are invalid (e.g., missing required fields).
    #[error("Validation error: {0}")]
    Validation(String),

    /// The payload binary is malformed or does not match the expected format.
    ///
    /// (e.g., Missing PE magic bytes, invalid sections).
    #[error("Invalid image format: {0}")]
    InvalidImage(String),

    /// A logical error where the Strategy and Payload are incompatible.
    ///
    /// (e.g., Attempting 'Process Hollowing' using a raw 'Shellcode' payload)
    #[error("Strategy '{strategy}' incompatible with payload type '{variant}'")]
    Mismatch {
        strategy: &'static str,
        variant: &'static str,
    },

    /// The requested functionality is disabled via Cargo features or not supported on this OS.
    #[error("Capability unavailable: {0}")]
    Unsupported(String),

    /// A generic runtime failure not covered by specific variants.
    #[error("Execution failed: {0}")]
    Execution(String),
}

// Helper: Enables usage of `?` on String to convert automatically to Error::Execution.
impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Execution(s)
    }
}

// Helper: Enables usage of `?` on &str to convert automatically to Error::Execution.
impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Execution(s.to_string())
    }
}
