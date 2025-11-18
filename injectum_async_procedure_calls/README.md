### Asynchronous Procedure Calls

The **Asynchronous Procedure Calls (APC)** crate demonstrates a process injection technique where code is executed in the context of an existing thread instead of creating a new one. 

This technique queues an APC on a target thread. When the thread enters an *alertable* state (for example, by calling `SleepEx` or `WaitForSingleObjectEx` with alertable mode), it executes the shellcode pointed to by the APC. To queue an APC, the injector must obtain a valid thread handle, which requires first performing a *thread walk* to locate a suitable thread in the target process.

This approach builds on classic injection methods but illustrates a more advanced technique for executing code within an existing thread, commonly used in red team operations to test process security and endpoint defenses.

#### Example: Simulating an Alertable State

An example binary is provided that runs a thread in a loop calling `SleepEx` with the alertable flag set. This simulates a thread that can receive and execute queued APCs, allowing you to safely test the injection technique.

#### Building the Example

To build the example:

```bash
cargo build --example alertable_thread --release
```

This generates a binary in target/x86_64-pc-windows-gnu/release/examples/alertable_thread.exe that can be run to create a process with an alertable thread for testing APC injection.

[Back to the main README](../README.md)
