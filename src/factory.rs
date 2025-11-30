//! Internal factory for resolving injection strategies.
//!
//! This module implements the **Factory Pattern**, acting as the bridge between the
//! high-level [`Technique`] enum and the concrete [`Strategy`] implementations.
//! It relies heavily on conditional compilation to ensure only enabled features
//! and OS-compatible strategies are compiled into the final binary.

use crate::{
    Error, Result,
    payload::Payload,
    strategy::{Strategy, Technique},
    target::Target,
};

/// A fallback strategy used when a requested technique is unavailable.
///
/// This serves as a safety net to return a distinct error if the internal logic
/// routes to a placeholder (e.g., if feature flags are misconfigured), rather
/// than panicking or executing undefined behavior.
struct PlaceholderStrategy;

impl Strategy for PlaceholderStrategy {
    fn execute(&self, _: &Technique, _: &Payload, _: &Target) -> Result<()> {
        Err(Error::Unsupported(
            "No injection feature is enabled. Please enable at least one feature in Cargo.toml."
                .into(),
        ))
    }
}

pub(crate) struct Factory;

impl Factory {
    /// This method matches the [`Technique`] variant to its corresponding logic module.
    ///
    /// # Compile-time Safety
    /// This block uses `#[cfg(...)]` attributes to ensure that Windows-specific techniques
    /// are not compiled on Linux, and that unused strategies are stripped from the binary
    /// if their feature flag is not enabled in `Cargo.toml`.
    pub(crate) fn create(technique: &Technique) -> &'static dyn Strategy {
        static PLACEHOLDER: PlaceholderStrategy = PlaceholderStrategy;

        match technique {
            #[cfg(all(feature = "T1055_001", target_os = "windows"))]
            Technique::T1055_001(_) => &crate::strategy::T1055_001::T1055_001,

            #[cfg(all(feature = "T1055_002", target_os = "windows"))]
            Technique::T1055_002(_) => &crate::strategy::T1055_002::T1055_002,

            #[cfg(all(feature = "T1055_003", target_os = "windows"))]
            Technique::T1055_003(_) => &crate::strategy::T1055_003::T1055_003,

            #[cfg(all(feature = "T1055_004", target_os = "windows"))]
            Technique::T1055_004(_) => &crate::strategy::T1055_004::T1055_004,

            #[cfg(all(feature = "T1055_005", target_os = "windows"))]
            Technique::T1055_005(_) => &crate::strategy::T1055_005::T1055_005,

            #[cfg(all(feature = "T1055_008", target_os = "linux"))]
            Technique::T1055_008(_) => &crate::strategy::T1055_008::T1055_008,

            #[cfg(all(feature = "T1055_009", target_os = "windows"))]
            Technique::T1055_009(_) => &crate::strategy::T1055_009::T1055_009,

            #[cfg(all(feature = "T1055_011", target_os = "windows"))]
            Technique::T1055_011(_) => &crate::strategy::T1055_011::T1055_011,

            #[cfg(all(feature = "T1055_012", target_os = "windows"))]
            Technique::T1055_012(_) => &crate::strategy::T1055_012::T1055_012,

            #[cfg(all(feature = "T1055_013", target_os = "windows"))]
            Technique::T1055_013(_) => &crate::strategy::T1055_013::T1055_013,

            #[cfg(all(feature = "T1055_014", target_os = "linux"))]
            Technique::T1055_014(_) => &crate::strategy::T1055_014::T1055_014,

            #[cfg(all(feature = "T1055_015", target_os = "windows"))]
            Technique::T1055_015(_) => &crate::strategy::T1055_015::T1055_015,

            // Catches internal placeholders or variants that somehow exist without
            // their corresponding feature flag being active.
            Technique::__Placeholder => &PLACEHOLDER,
        }
    }
}
