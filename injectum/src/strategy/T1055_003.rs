//! Implementation of MITRE ATT&CK T1055.003: Thread Execution Hijacking.
//!
//! This module is a placeholder and the technique is not yet implemented.

use crate::{
    error::InjectumError,
    info,
    payload::Payload,
    strategy::{Method, Strategy, Technique},
    target::Target,
};

/// The strategy implementation for T1055.003 (Thread Execution Hijacking).
#[derive(Default)]
pub(crate) struct T1055_003;

impl Strategy for T1055_003 {
    fn requires_pid(&self, method: Method) -> bool {
        !matches!(method.0, "Self")
    }

    fn execute(
        &self,
        _payload: &Payload,
        _target: &Target,
        _method: Method,
    ) -> Result<(), InjectumError> {
        let info = Technique::T1055_003.info();
        info!("Strategy: {} ({})", info.mitre_id, info.name);

        todo!(
            "'{} ({})' is not yet implemented.",
            info.mitre_id,
            info.name
        );
    }
}
