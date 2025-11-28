//! Unified error handling for the library.

use thiserror::Error;

/// Enumeration of all possible errors that can occur during the injection lifecycle.
#[derive(Error)]
pub enum InjectumError {
    /// Standard Input/Output errors.
    #[error("{0}")]
    Io(#[from] std::io::Error),

    /// Returned when a Win32 API call fails.
    /// Contains the function name and the error code (GetLastError).
    #[error("Win32 API '{0}' failed with error code: {1}")]
    Win32Error(&'static str, u32),

    /// Returned when a strategy requires a PID but none was provided.
    #[error("Strategy '{0}' requires a Target PID.")]
    PidRequired(&'static str),

    /// Returned when the payload type doesn't match the strategy requirements.
    #[error("Strategy '{strategy}' does not support payload type '{payload_type}'.")]
    PayloadMismatch {
        strategy: &'static str,
        payload_type: &'static str,
    },

    /// Returned when a specific method is requested but the feature is not compiled.
    #[error("Method '{0}' is disabled in this build. Enable the feature '{1}' in Cargo.toml.")]
    FeatureDisabled(String, String),

    /// Returned when a method string is unknown.
    #[error("Unknown injection method: '{0}'.")]
    MethodNotSupported(String),

    /// Returned when trying to execute a strategy when no features are enabled.
    #[error("No injection feature is enabled. Please enable at least one feature in Cargo.toml.")]
    NoFeatureEnabled,

    /// Malformed PE/DLL data.
    #[error("Invalid PE Format: {0}")]
    InvalidPe(String),

    /// General failure during the execution phase (Win32 API failures, etc.).
    #[error("{0}")]
    ExecutionFailure(String),

    /// Builder construction errors.
    #[error("{0}")]
    Builder(String),

    /// Invalid arguments provided to the library.
    #[error("{0}")]
    Argument(String),
}

impl std::fmt::Debug for InjectumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}
