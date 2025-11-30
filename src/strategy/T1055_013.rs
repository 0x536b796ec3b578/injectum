//! Placeholder implementation for **MITRE ATT&CK T1055.013: Process Doppelgänging**.
//!
//! # 🚧 Under Construction
//! Attempting to execute this strategy will result in a runtime panic.

use crate::{
    Result, info,
    payload::Payload,
    strategy::{Strategy, Technique},
    target::Target,
};

/// The concrete strategy implementation for T1055.013.
#[derive(Default)]
pub(crate) struct T1055_013;

impl Strategy for T1055_013 {
    fn execute(&self, technique: &Technique, _payload: &Payload, _target: &Target) -> Result<()> {
        let info = technique.info();
        info!("Strategy: {} ({})", info.mitre_id, info.name);

        // Explicitly panic to inform the developer/user that this feature is pending.
        todo!(
            "'{} ({})' is not yet implemented.",
            info.mitre_id,
            info.name
        );
    }
}
