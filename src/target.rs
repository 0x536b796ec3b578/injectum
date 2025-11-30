//! Defines the injection target abstraction.
//!
//! This module specifies the destination context where a payload will be executed,
//! supporting existing processes, new processes, or the current process (self-injection).

use std::path::PathBuf;

/// Represents the destination process for a code injection strategy.
pub enum Target {
    /// Targets an existing, active process via its Operating System PID.
    Pid(u32),
    /// Indicates that a new process should be spawned from the provided executable path to serve as the target.
    Spawn(PathBuf),
    /// Targets the current running process (self-injection).
    CurrentProcess,
}

impl Target {
    /// Returns `true` if the target is a specific Process ID ([`Target::Pid`]).
    pub fn is_pid(&self) -> bool {
        matches!(self, Target::Pid(_))
    }

    /// Returns the executable path if the target is [`Target::Spawn`].
    ///
    /// Returns [`None`] for [`Target::Pid`] or [`Target::CurrentProcess`].
    pub fn spawn_path(&self) -> Option<&PathBuf> {
        match self {
            Target::Spawn(target_path) => Some(target_path),
            _ => None,
        }
    }
}
