//! The core execution engine for driving injection strategies.
//!
//! This module coordinates the interaction between the configured [StrategyType],
//! the [Payload], and the [Target].

use crate::{
    error::InjectumError, factory::Factory, payload::Payload, strategy::StrategyType,
    target::Target,
};

/// Stateless driver that coordinates the injection process.
pub struct Injector;

impl Injector {
    /// Executes the specified strategy with the given payload and target.
    pub fn run(s: StrategyType, p: &Payload, t: &Target) -> Result<(), InjectumError> {
        let strategy = Factory::create(s);

        if strategy.requires_pid(s.method) && !t.has_pid() {
            return Err(InjectumError::PidRequired(s.technique.info().mitre_id));
        }

        strategy.execute(p, t, s.method)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{payload::PayloadMetadata, strategy::Technique};

    fn dummy_payload() -> Payload {
        Payload::Shellcode {
            bytes: vec![1, 2, 3],
            meta: PayloadMetadata::default(),
        }
    }

    #[test]
    fn pid_enforced_when_required() {
        let payload = dummy_payload();
        let target = Target::None; // No PID provided
        let strategy = StrategyType::new(Technique::MockTest, None);

        let result = Injector::run(strategy, &payload, &target);
        assert!(matches!(result, Err(InjectumError::PidRequired(_))));
    }

    #[test]
    fn strategy_runs_without_pid_if_allowed() {
        let payload = dummy_payload();
        let target = Target::None;
        let strategy = StrategyType::new(Technique::MockNoPid, None);

        let result = Injector::run(strategy, &payload, &target);
        assert!(result.is_ok());
    }
}
