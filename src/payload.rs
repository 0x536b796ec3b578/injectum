//! Defines the data structures for injection material and metadata.
//!
//! This module ensures type safety for various payload formats and includes
//! metadata structures for Operational Security (OpSec) compliance.

use std::path::PathBuf;

/// Represents the raw material to be injected into a target.
#[derive(Debug, Clone, PartialEq)]
pub enum Payload {
    /// Raw shellcode bytes.
    Shellcode {
        bytes: Vec<u8>,
        meta: PayloadMetadata,
    },
    /// A path to a DLL on disk, or the raw bytes of a DLL image.
    DllFile {
        path: Option<PathBuf>,
        image: Option<Vec<u8>>,
        meta: PayloadMetadata,
    },
    /// A path to an executable on disk, or the raw bytes of an EXE image.
    Executable {
        path: Option<PathBuf>,
        image: Option<Vec<u8>>,
        meta: PayloadMetadata,
    },
    /// A script to be executed (e.g., PowerShell, Python).
    Script {
        language: String,
        script: String,
        meta: PayloadMetadata,
    },
    /// A generic binary blob with a specified content type.
    Blob {
        content_type: String,
        data: Vec<u8>,
        meta: PayloadMetadata,
    },
}

impl Payload {
    /// Returns the string representation of the payload variant name.
    pub fn variant_name(&self) -> &'static str {
        match self {
            Payload::Shellcode { .. } => "Shellcode",
            Payload::DllFile { .. } => "DllFile",
            Payload::Executable { .. } => "Executable",
            Payload::Script { .. } => "Script",
            Payload::Blob { .. } => "Blob",
        }
    }
}

/// Metadata used to enforce Operational Security (OpSec) and safety checks.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct PayloadMetadata {
    /// A description of what the payload does (e.g., "Reverse TCP Shell").
    pub description: Option<String>,
    /// The source of the payload (e.g., "msfvenom", "cobalt_strike_beacon").
    /// Critical for debugging which tool generated a failing payload.
    pub origin: Option<String>,
    /// If true, this payload is considered safe for testing/debugging (e.g., calc.exe).
    /// If false, the Injector can be configured to block execution in "Safe Mode".
    pub safe_sample: bool,
    /// Arbitrary tags for dynamic logic (e.g., "x64", "needs_cleanup").
    pub labels: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_name_returns_correct_string() {
        let meta = PayloadMetadata::default();
        let p = Payload::Shellcode {
            bytes: vec![],
            meta,
        };
        assert_eq!(p.variant_name(), "Shellcode");
    }
}
