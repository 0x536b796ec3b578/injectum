//! Defines the catalog of injection techniques and the interface for their implementation.
//!
//! This module serves as the central registry for the library. It maps high-level
//! MITRE ATT&CK identifiers (e.g., T1055.001) to concrete Rust types and defines the
//! [`Strategy`] trait that unifies their execution logic.

#[cfg(all(feature = "T1055_001", target_os = "windows"))]
#[allow(non_snake_case)]
pub(crate) mod T1055_001;

#[cfg(all(feature = "T1055_002", target_os = "windows"))]
#[allow(non_snake_case)]
pub(crate) mod T1055_002;

#[cfg(all(feature = "T1055_003", target_os = "windows"))]
#[allow(non_snake_case)]
pub(crate) mod T1055_003;

#[cfg(all(feature = "T1055_004", target_os = "windows"))]
#[allow(non_snake_case)]
pub(crate) mod T1055_004;

#[cfg(all(feature = "T1055_005", target_os = "windows"))]
#[allow(non_snake_case)]
pub(crate) mod T1055_005;

#[cfg(all(feature = "T1055_008", target_os = "linux"))]
#[allow(non_snake_case)]
pub(crate) mod T1055_008;

#[cfg(all(feature = "T1055_009", target_os = "windows"))]
#[allow(non_snake_case)]
pub(crate) mod T1055_009;

#[cfg(all(feature = "T1055_011", target_os = "windows"))]
#[allow(non_snake_case)]
pub(crate) mod T1055_011;

#[cfg(all(feature = "T1055_012", target_os = "windows"))]
#[allow(non_snake_case)]
pub(crate) mod T1055_012;

#[cfg(all(feature = "T1055_013", target_os = "windows"))]
#[allow(non_snake_case)]
pub(crate) mod T1055_013;

#[cfg(all(feature = "T1055_014", target_os = "linux"))]
#[allow(non_snake_case)]
pub(crate) mod T1055_014;

#[cfg(all(feature = "T1055_015", target_os = "windows"))]
#[allow(non_snake_case)]
pub(crate) mod T1055_015;

use crate::{Result, payload::Payload, target::Target};

/// The comprehensive registry of supported Process Injection techniques.
///
/// Each variant corresponds to a specific MITRE ATT&CK sub-technique (T1055).
///
/// # Feature Flags
/// Variants are conditionally compiled. You must enable the corresponding feature
/// in `Cargo.toml` (e.g., `feature = "T1055_001"`) for the variant to be available.
#[non_exhaustive]
pub enum Technique {
    /// **T1055.001**: Dynamic-link Library Injection.
    #[cfg(all(feature = "T1055_001", target_os = "windows"))]
    T1055_001(DynamicLinkLibrary),

    /// **T1055.002**: Portable Executable Injection.
    #[cfg(all(feature = "T1055_002", target_os = "windows"))]
    T1055_002(PortableExecutable),

    /// **T1055.003**: Thread Execution Hijacking.
    #[cfg(all(feature = "T1055_003", target_os = "windows"))]
    T1055_003(ThreadExecutionHijacking),

    /// **T1055.004**: Asynchronous Procedure Call (APC) Injection.
    #[cfg(all(feature = "T1055_004", target_os = "windows"))]
    T1055_004(AsynchronousProcedureCall),

    /// **T1055.005**: Thread Local Storage (TLS) Injection.
    #[cfg(all(feature = "T1055_005", target_os = "windows"))]
    T1055_005(ThreadLocalStorage),

    /// **T1055.008**: Ptrace System Calls (Linux).
    #[cfg(all(feature = "T1055_008", target_os = "linux"))]
    T1055_008(PtraceSystemCalls),

    /// **T1055.009**: Process Memory Injection.
    #[cfg(all(feature = "T1055_009", target_os = "windows"))]
    T1055_009(ProcMemory),

    /// **T1055.011**: Extra Window Memory Injection.
    #[cfg(all(feature = "T1055_011", target_os = "windows"))]
    T1055_011(ExtraWindowMemoryInjection),

    /// **T1055.012**: Process Hollowing.
    #[cfg(all(feature = "T1055_012", target_os = "windows"))]
    T1055_012(ProcessHollowing),

    /// **T1055.013**: Process Doppelgänging.
    #[cfg(all(feature = "T1055_013", target_os = "windows"))]
    T1055_013(ProcessDoppelgänging),

    /// **T1055.014**: VDSO Hijacking (Linux).
    #[cfg(all(feature = "T1055_014", target_os = "linux"))]
    T1055_014(VDSOHijacking),

    /// **T1055.015**: ListPlanting.
    #[cfg(all(feature = "T1055_015", target_os = "windows"))]
    T1055_015(ListPlanting),

    #[doc(hidden)]
    __Placeholder,
}

/// Configuration options for T1055.001 (DLL Injection).
#[cfg(all(feature = "T1055_001", target_os = "windows"))]
#[derive(Default)]
pub enum DynamicLinkLibrary {
    /// Standard `LoadLibraryA` injection.
    #[default]
    Classic,
    Reflective,
}

/// Configuration options for T1055.002 (PE Injection).
#[cfg(all(feature = "T1055_002", target_os = "windows"))]
#[derive(Default)]
pub enum PortableExecutable {
    /// Injection via `CreateRemoteThread`.
    #[default]
    RemoteThread,
}

/// Configuration options for T1055.003 (Thread Hijacking).
#[cfg(all(feature = "T1055_003", target_os = "windows"))]
#[derive(Default)]
pub enum ThreadExecutionHijacking {
    /// Suspends thread and updates `EIP`/`RIP` context.
    #[default]
    Default,
}

/// Configuration options for T1055.004 (APC Injection).
#[cfg(all(feature = "T1055_004", target_os = "windows"))]
#[derive(Default)]
pub enum AsynchronousProcedureCall {
    /// Queue APC to a single specific thread.
    #[default]
    Sniper,
    /// Queue APCs to all threads in the target process.
    Spray,
    /// Injection during process initialization (Early Bird).
    EarlyBird,
}

/// Configuration options for T1055.005 (TLS Injection).
#[cfg(all(feature = "T1055_005", target_os = "windows"))]
#[derive(Default)]
pub enum ThreadLocalStorage {
    #[default]
    Default,
}

/// Configuration options for T1055.008 (Ptrace - Linux).
#[cfg(all(feature = "T1055_008", target_os = "linux"))]
#[derive(Default)]
pub enum PtraceSystemCalls {
    #[default]
    Default,
}

/// Configuration options for T1055.009 (Proc Memory).
#[cfg(all(feature = "T1055_009", target_os = "windows"))]
#[derive(Default)]
pub enum ProcMemory {
    #[default]
    Default,
}

/// Configuration options for T1055.011 (Extra Window Memory).
#[cfg(all(feature = "T1055_011", target_os = "windows"))]
#[derive(Default)]
pub enum ExtraWindowMemoryInjection {
    #[default]
    Default,
}

/// Configuration options for T1055.012 (Process Hollowing).
#[cfg(all(feature = "T1055_012", target_os = "windows"))]
#[derive(Default)]
pub enum ProcessHollowing {
    /// Standard unmapping and remapping of sections.
    #[default]
    Standard,
    /// Overwriting the Entry Point (OEP) without unmapping.
    EntryPointStomping,
}

/// Configuration options for T1055.013 (Process Doppelgänging).
#[cfg(all(feature = "T1055_013", target_os = "windows"))]
#[derive(Default)]
pub enum ProcessDoppelgänging {
    #[default]
    Default,
}

/// Configuration options for T1055.014 (VDSO Hijacking - Linux).
#[cfg(all(feature = "T1055_014", target_os = "linux"))]
#[derive(Default)]
pub enum VDSOHijacking {
    #[default]
    Default,
}

/// Configuration options for T1055.015 (ListPlanting).
#[cfg(all(feature = "T1055_015", target_os = "windows"))]
#[derive(Default)]
pub enum ListPlanting {
    #[default]
    Default,
}

/// Descriptive metadata about a specific technique.
pub struct StrategyInfo {
    /// The human-readable name of the technique.
    pub name: &'static str,
    /// The official MITRE ATT&CK identifier (e.g., "T1055.001").
    pub mitre_id: &'static str,
}

impl Technique {
    /// Retrieves static metadata associated with the technique variant.
    pub fn info(&self) -> StrategyInfo {
        match self {
            #[cfg(all(feature = "T1055_001", target_os = "windows"))]
            Self::T1055_001(_) => StrategyInfo {
                name: "Dynamic-link Library Injection",
                mitre_id: "T1055.001",
            },

            #[cfg(all(feature = "T1055_002", target_os = "windows"))]
            Self::T1055_002(_) => StrategyInfo {
                name: "Portable Executable Injection",
                mitre_id: "T1055.002",
            },

            #[cfg(all(feature = "T1055_003", target_os = "windows"))]
            Self::T1055_003(_) => StrategyInfo {
                name: "Thread Execution Hijacking",
                mitre_id: "T1055.003",
            },

            #[cfg(all(feature = "T1055_004", target_os = "windows"))]
            Self::T1055_004(_) => StrategyInfo {
                name: "Asynchronous Procedure Call",
                mitre_id: "T1055.004",
            },

            #[cfg(all(feature = "T1055_005", target_os = "windows"))]
            Self::T1055_005(_) => StrategyInfo {
                name: "Thread Local Storage",
                mitre_id: "T1055.005",
            },

            #[cfg(all(feature = "T1055_008", target_os = "linux"))]
            Self::T1055_008(_) => StrategyInfo {
                name: "Ptrace System Calls",
                mitre_id: "T1055.008",
            },

            #[cfg(all(feature = "T1055_009", target_os = "windows"))]
            Self::T1055_009(_) => StrategyInfo {
                name: "Proc Memory",
                mitre_id: "T1055.009",
            },

            #[cfg(all(feature = "T1055_011", target_os = "windows"))]
            Self::T1055_011(_) => StrategyInfo {
                name: "Extra Window Memory Injection",
                mitre_id: "T1055.011",
            },

            #[cfg(all(feature = "T1055_012", target_os = "windows"))]
            Self::T1055_012(_) => StrategyInfo {
                name: "Process Hollowing",
                mitre_id: "T1055.012",
            },

            #[cfg(all(feature = "T1055_013", target_os = "windows"))]
            Self::T1055_013(_) => StrategyInfo {
                name: "Process Doppelgänging",
                mitre_id: "T1055.013",
            },

            #[cfg(all(feature = "T1055_014", target_os = "linux"))]
            Self::T1055_014(_) => StrategyInfo {
                name: "VDSO Hijacking",
                mitre_id: "T1055.014",
            },

            #[cfg(all(feature = "T1055_015", target_os = "windows"))]
            Self::T1055_015(_) => StrategyInfo {
                name: "ListPlanting",
                mitre_id: "T1055.015",
            },

            _ => StrategyInfo {
                name: "Unknown",
                mitre_id: "???",
            },
        }
    }
}

/// The unified behavior contract that all injection logic must implement.
///
/// This trait enforces the **Strategy Design Pattern**, ensuring that every
/// injection technique exposes the same `execute` method regardless of its
/// internal complexity.
pub(crate) trait Strategy {
    /// Performs the injection.
    ///
    /// # Arguments
    /// * `technique` - Configuration specific to the chosen technique.
    /// * `payload` - The raw data/code to inject.
    /// * `target` - The destination process.
    fn execute(&self, technique: &Technique, payload: &Payload, target: &Target) -> Result<()>;
}
