//! Implementation of MITRE ATT&CK T1055.011: Extra Window Memory Injection.
//!
//! This module is a placeholder and the technique is not yet implemented.

use crate::{
    error::InjectumError,
    info,
    payload::Payload,
    strategy::{Method, Strategy, Technique},
    target::Target,
};

/// The strategy implementation for T1055.011 (Extra Window Memory Injection).
#[derive(Default)]
pub(crate) struct T1055_011;

impl Strategy for T1055_011 {
    fn requires_pid(&self, method: Method) -> bool {
        !matches!(method.0, "Self")
    }

    fn execute(
        &self,
        _payload: &Payload,
        _target: &Target,
        _method: Method,
    ) -> Result<(), InjectumError> {
        let info = Technique::T1055_011.info();
        info!("Strategy: {} ({})", info.mitre_id, info.name);

        todo!(
            "'{} ({})' is not yet implemented.",
            info.mitre_id,
            info.name
        );
    }
}
