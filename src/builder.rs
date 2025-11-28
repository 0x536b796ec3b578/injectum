//! Builder pattern implementation for constructing injection configurations.
//!
//! This module provides a fluent interface to create an [ImmutableInjection]
//! ensuring all necessary components are present before execution.

use crate::{Injector, Payload, StrategyType, Target, error::InjectumError};

/// A fluent builder for creating an [ImmutableInjection].
#[derive(Default)]
pub struct InjectorBuilder {
    strategy: Option<StrategyType>,
    payload: Option<Payload>,
    target: Option<Target>,
}

impl InjectorBuilder {
    /// Creates a new, empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the injection strategy.
    pub fn strategy(mut self, s: StrategyType) -> Self {
        self.strategy = Some(s);
        self
    }

    /// Sets the payload to inject.
    pub fn payload(mut self, p: Payload) -> Self {
        self.payload = Some(p);
        self
    }

    /// Sets the target process. Defaults to `Target::None` if not called.
    pub fn target(mut self, t: Target) -> Self {
        self.target = Some(t);
        self
    }

    /// Consumes the builder and returns an immutable injection configuration.
    pub fn build(self) -> Result<ImmutableInjection, InjectumError> {
        let strategy = self
            .strategy
            .ok_or_else(|| InjectumError::Builder("Missing strategy".into()))?;

        let payload = self
            .payload
            .ok_or_else(|| InjectumError::Builder("Missing payload".into()))?;

        let target = self.target.unwrap_or(Target::None);

        Ok(ImmutableInjection {
            strategy,
            payload,
            target,
        })
    }

    /// Convenience method to build and immediately execute the injection.
    pub fn execute(self) -> Result<(), InjectumError> {
        let inj = self.build()?;
        inj.execute()
    }
}

/// A fully configured, immutable injection request.
pub struct ImmutableInjection {
    pub(crate) strategy: StrategyType,
    pub(crate) payload: Payload,
    pub(crate) target: Target,
}

impl ImmutableInjection {
    /// Executes the injection configuration using the core [Injector].
    pub fn execute(&self) -> Result<(), InjectumError> {
        Injector::run(self.strategy, &self.payload, &self.target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::PayloadMetadata;
    use crate::strategy::Technique;

    #[test]
    fn builder_fails_missing_fields() {
        let res = InjectorBuilder::new().build();
        assert!(res.is_err());
    }

    #[test]
    fn builder_succeeds_with_minimal_fields() {
        let payload = Payload::Blob {
            content_type: "test".into(),
            data: vec![],
            meta: PayloadMetadata::default(),
        };

        let res = InjectorBuilder::new()
            .strategy(StrategyType::new(Technique::MockTest, None))
            .payload(payload)
            .build();

        assert!(res.is_ok());
    }
}
