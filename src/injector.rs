//! The high-level entry point for performing code injection.
//!
//! This module acts as a Facade, abstracting the complexity of instantiating
//! specific strategies. It orchestrates the "How" ([`Technique`]), the "What" ([`Payload`]),
//! and the "Where" ([`Target`]).

use crate::{Result, Technique, factory::Factory, payload::Payload, target::Target};

/// A stateless facade that coordinates the injection lifecycle.
///
/// This struct serves as the primary public API for library users, decoupling them
/// from the internal implementation details of specific injection strategies.
pub struct Injector;

impl Injector {
    /// Executes a specific injection strategy using the provided materials.
    ///
    /// This function delegates the creation of the specific strategy implementation
    /// to the [`Factory`] and then triggers the execution.
    ///
    /// # Arguments
    ///
    /// * `technique` - The specific method to use (e.g., `ProcessHollowing`, `ReflectiveDll`).
    /// * `payload` - The code or data to be injected.
    /// * `target` - The destination process or executable.
    pub fn run(technique: &Technique, payload: &Payload, target: &Target) -> Result<()> {
        let strategy = Factory::create(technique);
        strategy.execute(technique, payload, target)
    }
}
