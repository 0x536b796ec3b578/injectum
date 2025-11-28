//! Abstractions for injection targets.
//!
//! This module defines where the payload will be executed, distinguishing between
//! remote processes (via PID) and self/local execution.

/// Specifies the destination process for the injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// Represents a target that does not require a remote process ID.
    /// Used for self-injection or strategies that spawn their own process.
    None,
    /// Targets a specific remote process by its ID.
    Pid(u32),
}

impl Target {
    /// Returns the Process ID if available.
    pub fn pid(&self) -> Option<u32> {
        match self {
            Target::Pid(p) => Some(*p),
            Target::None => None,
        }
    }

    /// Checks if the target is a specific PID.
    #[inline]
    pub fn has_pid(&self) -> bool {
        matches!(self, Target::Pid(_))
    }

    /// Checks if the target is `None`.
    #[inline]
    pub fn is_none(&self) -> bool {
        matches!(self, Target::None)
    }
}

#[cfg(test)]
mod tests {
    use super::Target;

    #[test]
    fn pid_returns_correct_value() {
        let t = Target::Pid(777);
        assert_eq!(t.pid(), Some(777));
        let none = Target::None;
        assert_eq!(none.pid(), None);
    }

    #[test]
    fn has_pid_detects_presence() {
        assert!(Target::Pid(42).has_pid());
        assert!(!Target::None.has_pid());
    }

    #[test]
    fn is_none_detects_none_variant() {
        assert!(Target::None.is_none());
        assert!(!Target::Pid(1).is_none());
    }

    #[test]
    fn target_equality() {
        assert_eq!(Target::Pid(10), Target::Pid(10));
        assert_ne!(Target::Pid(10), Target::Pid(11));
        assert_ne!(Target::Pid(10), Target::None);
    }
}
