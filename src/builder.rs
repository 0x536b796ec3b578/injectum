//! Implements the **Builder Pattern** for configuring injection operations.
//!
//! This module provides a fluent interface ([`InjectorBuilder`]) to construct a valid
//! [`ImmutableInjection`]. It handles input validation and applies sensible defaults
//! (e.g., defaulting to Self-Injection if no target is specified) before execution.

use crate::{Error, Injector, Payload, Result, Target, Technique};

/// A fluent builder for creating a validated [`ImmutableInjection`] configuration.
#[derive(Default)]
pub struct InjectorBuilder {
    technique: Option<Technique>,
    payload: Option<Payload>,
    target: Option<Target>,
}

impl InjectorBuilder {
    /// Creates a new, empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the specific injection technique (e.g., Process Hollowing, Reflective DLL).
    pub fn technique(mut self, technique: Technique) -> Self {
        self.technique = Some(technique);
        self
    }

    /// Sets the payload data (e.g., Shellcode, DLL) to be injected.
    pub fn payload(mut self, payload: Payload) -> Self {
        self.payload = Some(payload);
        self
    }

    /// Sets the target process.
    ///
    /// If this is not called, the builder defaults to [`Target::CurrentProcess`]
    /// (Self-Injection) upon [`build()`](Self::build).
    pub fn target(mut self, target: Target) -> Self {
        self.target = Some(target);
        self
    }

    /// Consumes the builder, validates inputs, and returns an immutable configuration.
    ///
    /// # Errors
    /// Returns [`Error::Validation`] if the `technique` or `payload` is missing.
    pub fn build(self) -> Result<ImmutableInjection> {
        let technique = self
            .technique
            .ok_or_else(|| Error::Validation("Missing technique".into()))?;

        let payload = self
            .payload
            .ok_or_else(|| Error::Validation("Missing payload".into()))?;

        // Logic check: Default to CurrentProcess (Self-Injection) if no target is specified.
        let target = self.target.unwrap_or(Target::CurrentProcess);

        Ok(ImmutableInjection {
            technique,
            payload,
            target,
        })
    }

    /// Convenience method to build and immediately execute the injection.
    ///
    /// This is equivalent to calling `.build()?.execute()`.
    pub fn execute(self) -> Result<()> {
        let injector = self.build()?;
        injector.execute()
    }
}

/// A fully configured, thread-safe injection request.
///
/// This struct guarantees that all necessary components (Technique, Payload, Target)
/// are present and valid. It cannot be modified after creation.
pub struct ImmutableInjection {
    pub(crate) technique: Technique,
    pub(crate) payload: Payload,
    pub(crate) target: Target,
}

impl ImmutableInjection {
    /// Executes the pre-configured injection strategy.
    pub fn execute(&self) -> Result<()> {
        Injector::run(&self.technique, &self.payload, &self.target)
    }
}
