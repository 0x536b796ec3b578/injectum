//! # Injectum
//!
//! **Injectum** is a modular, type-safe library for process injection in Rust. It provides a
//! structured interface for executing various injection strategies (mapped to MITRE ATT&CK T1055
//! techniques) while abstracting platform-specific implementations and memory management.
//!
//! ## Core Architecture
//!
//! The library is built around a unidirectional data flow:
//! **Builder** $\to$ **Configuration** $\to$ **Factory** $\to$ **Execution**.
//!
//! ## Usage Example
//!
//! The following example demonstrates how to perform a **Classic DLL Injection** (T1055.001)
//! into a remote process.
//!
//! ```rust,no_run
//! use injectum::{
//!     InjectorBuilder, InjectumError, Payload, PayloadMetadata, StrategyType, Target, Technique
//! };
//! use std::path::PathBuf;
//!
//! fn main() -> Result<(), InjectumError> {
//!     // 1. Define the payload (e.g., a DLL on disk)
//!     let payload = Payload::DllFile {
//!         path: Some(PathBuf::from("C:\\temp\\payload.dll")),
//!         image: None, // Not needed for Classic injection
//!         meta: PayloadMetadata {
//!             description: Some("Test Payload".into()),
//!             safe_sample: true,
//!             ..Default::default()
//!         },
//!     };
//!
//!     // 2. Select the strategy (DLL Injection -> Classic Method)
//!     // Strategies are resolved at runtime via the Factory.
//!     let strategy = StrategyType::new(Technique::T1055_001, Some("Classic"));
//!
//!     // 3. Select the target (Remote Process ID)
//!     let target = Target::Pid(1024);
//!
//!     // 4. Build and Execute
//!     // The builder ensures the configuration is valid before execution.
//!     InjectorBuilder::new()
//!         .target(target)
//!         .payload(payload)
//!         .strategy(strategy)
//!         .execute()?; // Compile and run
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Feature Flags
//!
//! To minimize binary size and detection surface, specific techniques are gated behind Cargo features.
//! You must enable the features corresponding to the strategies you intend to use.
//!
//! ```toml
//! [features]
//! T1055_001 = [] # Dynamic-link Library Injection
//! T1055_002 = [] # Portable Executable Injection
//! T1055_003 = [] # Thread Execution Hijacking
//! # ...
//! ```

/// The builder module for constructing injection configurations.
pub mod builder;
/// Error types for injection failures and validation.
pub mod error;
/// Internal factory for strategy instantiation.
pub(crate) mod factory;
/// The core execution engine.
pub mod injector;
/// Data structures for injection material and metadata.
pub mod payload;
/// Injection strategies and MITRE ATT&CK technique mapping.
pub mod strategy;
/// Abstractions for injection targets (PID vs None).
pub mod target;

// Re-exports (Public API)
pub use builder::InjectorBuilder;
pub use error::InjectumError;
pub use injector::Injector;
pub use payload::{Payload, PayloadMetadata};
pub use strategy::{Method, StrategyType, Technique};
pub use target::Target;

// Re-export log macros for internal use across modules.
// This allows strategy files to use `crate::debug!` regardless of the logging backend.
#[cfg(feature = "tracing")]
#[allow(unused_imports)]
pub(crate) use tracing::{debug, error, info, warn};

#[cfg(not(feature = "tracing"))]
mod stealth {
    #[macro_export]
    macro_rules! debug {
        ($($arg:tt)*) => {};
    }
    #[macro_export]
    macro_rules! error {
        ($($arg:tt)*) => {};
    }
    #[macro_export]
    macro_rules! info {
        ($($arg:tt)*) => {};
    }
    #[macro_export]
    macro_rules! trace {
        ($($arg:tt)*) => {};
    }
    #[macro_export]
    macro_rules! warn {
        ($($arg:tt)*) => {};
    }
}

#[cfg(not(feature = "tracing"))]
pub(crate) use stealth::*;
