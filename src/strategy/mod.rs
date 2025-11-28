//! Registry for injection techniques and common traits.
//!
//! This module defines the [Technique] catalog, which maps to MITRE ATT&CK IDs,
//! and the [Strategy] trait that all concrete implementations must satisfy.

#[cfg(all(feature = "T1055_001", target_os = "windows"))]
#[allow(non_snake_case)]
pub mod T1055_001;
#[cfg(all(feature = "T1055_002", target_os = "windows"))]
#[allow(non_snake_case)]
pub mod T1055_002;
#[cfg(all(feature = "T1055_003", target_os = "windows"))]
#[allow(non_snake_case)]
pub mod T1055_003;
#[cfg(all(feature = "T1055_004", target_os = "windows"))]
#[allow(non_snake_case)]
pub mod T1055_004;
#[cfg(all(feature = "T1055_005", target_os = "windows"))]
#[allow(non_snake_case)]
pub mod T1055_005;
#[cfg(all(feature = "T1055_008", target_os = "linux"))]
#[allow(non_snake_case)]
pub mod T1055_008;
#[cfg(all(feature = "T1055_009", target_os = "windows"))]
#[allow(non_snake_case)]
pub mod T1055_009;
#[cfg(all(feature = "T1055_011", target_os = "windows"))]
#[allow(non_snake_case)]
pub mod T1055_011;
#[cfg(all(feature = "T1055_012", target_os = "windows"))]
#[allow(non_snake_case)]
pub mod T1055_012;
#[cfg(all(feature = "T1055_013", target_os = "windows"))]
#[allow(non_snake_case)]
pub mod T1055_013;
#[cfg(all(feature = "T1055_014", target_os = "linux"))]
#[allow(non_snake_case)]
pub mod T1055_014;
#[cfg(all(feature = "T1055_015", target_os = "windows"))]
#[allow(non_snake_case)]
pub mod T1055_015;

use crate::{error::InjectumError, payload::Payload, target::Target};

/// Enumeration of supported MITRE ATT&CK T1055 sub-techniques.
///
/// Variants are conditionally compiled based on feature flags and the target OS.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Technique {
    /// T1055.001: Dynamic-link Library Injection
    #[cfg(all(feature = "T1055_001", target_os = "windows"))]
    T1055_001,
    /// T1055.002: Portable Executable Injection
    #[cfg(all(feature = "T1055_002", target_os = "windows"))]
    T1055_002,
    /// T1055.003: Thread Execution Hijacking
    #[cfg(all(feature = "T1055_003", target_os = "windows"))]
    T1055_003,
    /// T1055.004: Asynchronous Procedure Call
    #[cfg(all(feature = "T1055_004", target_os = "windows"))]
    T1055_004,
    /// T1055.005: Thread Local Storage
    #[cfg(all(feature = "T1055_005", target_os = "windows"))]
    T1055_005,
    /// T1055.008: Ptrace System Calls
    #[cfg(all(feature = "T1055_008", target_os = "linux"))]
    T1055_008,
    /// T1055.009: Proc Memory
    #[cfg(all(feature = "T1055_009", target_os = "windows"))]
    T1055_009,
    /// T1055.011: Extra Window Memory Injection
    #[cfg(all(feature = "T1055_011", target_os = "windows"))]
    T1055_011,
    /// T1055.012: Process Hollowing
    #[cfg(all(feature = "T1055_012", target_os = "windows"))]
    T1055_012,
    /// T1055.013: Process Doppelgänging
    #[cfg(all(feature = "T1055_013", target_os = "windows"))]
    T1055_013,
    /// T1055.014: VDSO Hijacking
    #[cfg(all(feature = "T1055_014", target_os = "linux"))]
    T1055_014,
    /// T1055.015: ListPlanting
    #[cfg(all(feature = "T1055_015", target_os = "windows"))]
    T1055_015,

    #[doc(hidden)]
    __Placeholder,

    // Internal: Used only for unit testing infrastructure
    #[cfg(test)]
    MockTest,
    #[cfg(test)]
    MockNoPid,
}

/// A specific method or variation of a technique (e.g., "Reflective" vs "Classic").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Method(pub &'static str);

/// A complete strategy specification, combining a [Technique] and a specific [Method].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StrategyType {
    pub technique: Technique,
    pub method: Method,
}

impl StrategyType {
    /// Creates a new strategy configuration.
    ///
    /// If `method` is `None`, it defaults to "Default" (usually the classic implementation).
    pub fn new(technique: Technique, method: Option<&'static str>) -> Self {
        Self {
            technique,
            method: Method(method.unwrap_or("Default")),
        }
    }
}

/// Informational metadata about a strategy.
pub struct StrategyInfo {
    pub name: &'static str,
    pub mitre_id: &'static str,
    pub kind: Technique,
}

impl Technique {
    /// Returns static metadata about the technique.
    pub fn info(&self) -> StrategyInfo {
        match self {
            #[cfg(all(feature = "T1055_001", target_os = "windows"))]
            Self::T1055_001 => StrategyInfo {
                name: "Dynamic-link Library Injection",
                mitre_id: "T1055.001",
                kind: *self,
            },
            #[cfg(all(feature = "T1055_002", target_os = "windows"))]
            Self::T1055_002 => StrategyInfo {
                name: "Portable Executable Injection",
                mitre_id: "T1055.002",
                kind: *self,
            },
            #[cfg(all(feature = "T1055_003", target_os = "windows"))]
            Self::T1055_003 => StrategyInfo {
                name: "Thread Execution Hijacking",
                mitre_id: "T1055.003",
                kind: *self,
            },
            #[cfg(all(feature = "T1055_004", target_os = "windows"))]
            Self::T1055_004 => StrategyInfo {
                name: "Asynchronous Procedure Call",
                mitre_id: "T1055.004",
                kind: *self,
            },
            #[cfg(all(feature = "T1055_005", target_os = "windows"))]
            Self::T1055_005 => StrategyInfo {
                name: "Thread Local Storage",
                mitre_id: "T1055.005",
                kind: *self,
            },
            #[cfg(all(feature = "T1055_008", target_os = "linux"))]
            Self::T1055_008 => StrategyInfo {
                name: "Ptrace System Calls",
                mitre_id: "T1055.008",
                kind: *self,
            },
            #[cfg(all(feature = "T1055_009", target_os = "windows"))]
            Self::T1055_009 => StrategyInfo {
                name: "Proc Memory",
                mitre_id: "T1055.009",
                kind: *self,
            },
            #[cfg(all(feature = "T1055_011", target_os = "windows"))]
            Self::T1055_011 => StrategyInfo {
                name: "Extra Window Memory Injection",
                mitre_id: "T1055.011",
                kind: *self,
            },
            #[cfg(all(feature = "T1055_012", target_os = "windows"))]
            Self::T1055_012 => StrategyInfo {
                name: "Process Hollowing",
                mitre_id: "T1055.012",
                kind: *self,
            },
            #[cfg(all(feature = "T1055_013", target_os = "windows"))]
            Self::T1055_013 => StrategyInfo {
                name: "Process Doppelgänging",
                mitre_id: "T1055.013",
                kind: *self,
            },
            #[cfg(all(feature = "T1055_014", target_os = "linux"))]
            Self::T1055_014 => StrategyInfo {
                name: "VDSO Hijacking",
                mitre_id: "T1055.014",
                kind: *self,
            },
            #[cfg(all(feature = "T1055_015", target_os = "windows"))]
            Self::T1055_015 => StrategyInfo {
                name: "ListPlanting",
                mitre_id: "T1055.015",
                kind: *self,
            },
            Self::__Placeholder => StrategyInfo {
                name: "No technique (no features enabled)",
                mitre_id: "NONE",
                kind: *self,
            },
            #[cfg(test)]
            Self::MockTest => StrategyInfo {
                name: "Mock Strategy",
                mitre_id: "TEST.000",
                kind: *self,
            },
            #[cfg(test)]
            Self::MockNoPid => StrategyInfo {
                name: "Mock No PID",
                mitre_id: "TEST.001",
                kind: *self,
            },
        }
    }
}

/// Defines the interface for all injection strategies.
///
/// Concrete implementations of this trait perform the actual platform-specific
/// injection logic.
pub(crate) trait Strategy {
    /// Determines if the specific method variant requires a Target PID.
    fn requires_pid(&self, method: Method) -> bool;

    /// Executes the injection logic using the provided payload and target.
    fn execute(
        &self,
        payload: &Payload,
        target: &Target,
        method: Method,
    ) -> Result<(), InjectumError>;
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub struct MockStrategy {
        pub requires_pid: bool,
    }

    impl Strategy for MockStrategy {
        fn requires_pid(&self, _m: Method) -> bool {
            self.requires_pid
        }
        fn execute(&self, _p: &Payload, _t: &Target, _m: Method) -> Result<(), InjectumError> {
            Ok(())
        }
    }

    #[test]
    fn mock_strategy_returns_correct_info() {
        let info = Technique::MockTest.info();
        assert_eq!(info.mitre_id, "TEST.000");
    }

    // Windows Specific Test: T1055.001
    // This test will only compile/run if the feature is ON and we are on Windows
    #[test]
    #[cfg(all(feature = "T1055_001", target_os = "windows"))]
    fn verify_t1055_001_info() {
        let info = Technique::T1055_001.info();
        assert_eq!(info.mitre_id, "T1055.001");
        assert!(info.name.contains("Dynamic-link"));
    }

    // Linux Specific Test: T1055.008
    #[test]
    #[cfg(all(feature = "T1055_008", target_os = "linux"))]
    fn verify_t1055_008_info() {
        let info = Technique::T1055_008.info();
        assert_eq!(info.mitre_id, "T1055.008");
        assert!(info.name.contains("Ptrace"));
    }
}
