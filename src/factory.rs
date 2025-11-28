//! Internal factory for creating strategy instances.
//!
//! Handles the resolution of [StrategyType] to concrete [Strategy] implementations
//! based on on active Cargo features and the target operating system.

use crate::{
    error::InjectumError,
    payload::Payload,
    strategy::{Method, Strategy, StrategyType, Technique},
    target::Target,
};

/// A private, no-op strategy that returns an error, used as a placeholder
/// when no features are enabled.
struct PlaceholderStrategy;

impl Strategy for PlaceholderStrategy {
    fn requires_pid(&self, _method: Method) -> bool {
        false
    }

    fn execute(
        &self,
        _payload: &Payload,
        _target: &Target,
        _method: Method,
    ) -> Result<(), InjectumError> {
        Err(InjectumError::NoFeatureEnabled)
    }
}

pub(crate) struct Factory;

impl Factory {
    /// Creates a static reference to a concrete Strategy implementation.
    pub(crate) fn create(kind: StrategyType) -> &'static dyn Strategy {
        static PLACEHOLDER: PlaceholderStrategy = PlaceholderStrategy;

        match kind.technique {
            #[cfg(all(feature = "T1055_001", target_os = "windows"))]
            Technique::T1055_001 => &crate::strategy::T1055_001::T1055_001,
            #[cfg(all(feature = "T1055_002", target_os = "windows"))]
            Technique::T1055_002 => &crate::strategy::T1055_002::T1055_002,
            #[cfg(all(feature = "T1055_003", target_os = "windows"))]
            Technique::T1055_003 => &crate::strategy::T1055_003::T1055_003,
            #[cfg(all(feature = "T1055_004", target_os = "windows"))]
            Technique::T1055_004 => &crate::strategy::T1055_004::T1055_004,
            #[cfg(all(feature = "T1055_005", target_os = "windows"))]
            Technique::T1055_005 => &crate::strategy::T1055_005::T1055_005,
            #[cfg(all(feature = "T1055_008", target_os = "linux"))]
            Technique::T1055_008 => &crate::strategy::T1055_008::T1055_008,
            #[cfg(all(feature = "T1055_009", target_os = "windows"))]
            Technique::T1055_009 => &crate::strategy::T1055_009::T1055_009,
            #[cfg(all(feature = "T1055_011", target_os = "windows"))]
            Technique::T1055_011 => &crate::strategy::T1055_011::T1055_011,
            #[cfg(all(feature = "T1055_012", target_os = "windows"))]
            Technique::T1055_012 => &crate::strategy::T1055_012::T1055_012,
            #[cfg(all(feature = "T1055_013", target_os = "windows"))]
            Technique::T1055_013 => &crate::strategy::T1055_013::T1055_013,
            #[cfg(all(feature = "T1055_014", target_os = "linux"))]
            Technique::T1055_014 => &crate::strategy::T1055_014::T1055_014,
            #[cfg(all(feature = "T1055_015", target_os = "windows"))]
            Technique::T1055_015 => &crate::strategy::T1055_015::T1055_015,

            Technique::__Placeholder => &PLACEHOLDER,

            #[cfg(test)]
            Technique::MockTest => &crate::strategy::tests::MockStrategy { requires_pid: true },
            #[cfg(test)]
            Technique::MockNoPid => &crate::strategy::tests::MockStrategy {
                requires_pid: false,
            },
        }
    }
}
