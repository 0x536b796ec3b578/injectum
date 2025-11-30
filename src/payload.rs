//! Defines the core data structures for injection payloads and their context.
//!
//! This module abstracts the "what" of an injection operation, providing a unified [`Payload`]
//! enum to handle various formats (shellcode, PE files, scripts) and an accompanying
//! [`PayloadMetadata`] struct for tracking OpSec compliance and provenance.

use std::{fs::read, path::PathBuf};

use crate::Result;

/// A unified representation of the code or data to be injected.
///
/// This enum wraps the raw bytes or file paths of the payload and attaches
/// [`PayloadMetadata`] to ensure operational context is carried throughout the injection lifecycle.
pub enum Payload {
    /// Raw position-independent shellcode.
    Shellcode {
        /// The raw bytecode.
        bytes: Vec<u8>,
        metadata: PayloadMetadata,
    },
    /// A Dynamic Link Library (DLL), either as a file path or raw image bytes.
    DllFile {
        /// The path to the DLL on disk, if available.
        file_path: Option<PathBuf>,
        /// The raw bytes of the DLL image.
        image_bytes: Option<Vec<u8>>,
        metadata: PayloadMetadata,
    },
    /// A Portable Executable (EXE), either as a file path or raw image bytes.
    Executable {
        /// The path to the EXE on disk, if available.
        file_path: Option<PathBuf>,
        /// The raw bytes of the EXE image.
        image_bytes: Option<Vec<u8>>,
        metadata: PayloadMetadata,
    },
    /// A high-level script (e.g., PowerShell, Python, Bash) to be executed by an interpreter.
    Script {
        /// The interpreter or language identifier (e.g., "ps1", "python").
        language: String,
        /// The source code of the script.
        script_code: String,
        metadata: PayloadMetadata,
    },
    /// A generic binary blob with a specified content type.
    ///
    /// Useful for stagers or data that does not fit standard executable formats.
    Blob {
        /// A MIME-type or custom identifier for the data format.
        content_type: String,
        /// The binary data.
        data: Vec<u8>,
        metadata: PayloadMetadata,
    },
}

impl Payload {
    /// Returns a string literal representing the variant name (e.g., "Shellcode", "DllFile").
    pub fn variant_name(&self) -> &'static str {
        match self {
            Payload::Shellcode { .. } => "Shellcode",
            Payload::DllFile { .. } => "DllFile",
            Payload::Executable { .. } => "Executable",
            Payload::Script { .. } => "Script",
            Payload::Blob { .. } => "Blob",
        }
    }

    /// Creates a [`Payload`] from a file path, automatically detecting if it is a DLL or an EXE.
    ///
    /// This function performs basic I/O to read the file and uses a lightweight PE header
    /// heuristic to determine the format.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read.
    pub fn from_file(file_path: impl Into<PathBuf>, metadata: PayloadMetadata) -> Result<Self> {
        let file_path = file_path.into();
        let file_bytes = read(&file_path)?;

        // Heuristic: Check PE headers to distinguish DLL from EXE.
        if Self::is_dll(&file_bytes) {
            Ok(Payload::DllFile {
                file_path: Some(file_path),
                image_bytes: Some(file_bytes),
                metadata,
            })
        } else {
            Ok(Payload::Executable {
                file_path: Some(file_path),
                image_bytes: Some(file_bytes),
                metadata,
            })
        }
    }

    /// Internal helper to parse PE headers and check for the `IMAGE_FILE_DLL` flag.
    ///
    /// This manually traverses the DOS Header and NT Headers to avoid heavy dependencies.
    fn is_dll(file_bytes: &[u8]) -> bool {
        // Minimum size check (DOS Header + PE Header)
        if file_bytes.len() < 0x40 {
            return false;
        }

        // 1. Read 'e_lfanew' at offset 0x3C in the DOS Header.
        //    This tells us the offset to the PE Signature (NT Headers).
        let nt_headers_offset = u32::from_le_bytes([
            file_bytes[0x3c],
            file_bytes[0x3d],
            file_bytes[0x3e],
            file_bytes[0x3f],
        ]) as usize;

        // Ensure buffer allows reading Signature (4 bytes) + File Header (20 bytes)
        if file_bytes.len() < nt_headers_offset + 4 + 20 {
            return false;
        }

        // 2. Locate the 'Characteristics' field inside the COFF File Header.
        //    Structure: [Signature (4)] + [Machine (2)] + [NumberOfSections (2)] +
        //               [TimeDateStamp (4)] + [PointerToSymbolTable (4)] +
        //               [NumberOfSymbols (4)] + [SizeOfOptionalHeader (2)] +
        //               [Characteristics (2)]
        //    Offset of Characteristics relative to NT Headers start = 4 + 18 = 22 (0x16).
        let characteristics_offset = nt_headers_offset + 4 + 18;

        let characteristics = u16::from_le_bytes([
            file_bytes[characteristics_offset],
            file_bytes[characteristics_offset + 1],
        ]);

        // 3. Check for IMAGE_FILE_DLL (0x2000)
        (characteristics & 0x2000) != 0
    }
}

/// Metadata used to enforce Operational Security (OpSec) and provenance checks.
///
/// This structure accompanies a [`Payload`] to assist the injector in making safety decisions
/// (e.g., blocking unsafe samples in production environments).
#[derive(Default)]
pub struct PayloadMetadata {
    /// A human-readable description of the payload (e.g., "Meterpreter Reverse TCP").
    pub description: Option<String>,
    /// The source/generator of the payload (e.g., "msfvenom", "manual_build").
    pub origin: Option<String>,
    /// Indicates if this payload is benign (e.g., `calc.exe`).
    ///
    /// If `true`, the injector may bypass certain safety warnings.
    pub safe_sample: bool,
    /// Custom tags for dynamic filtering (e.g., "x64", "needs_cleanup").
    pub labels: Vec<String>,
}
