### Classic Injection

The **Classic Injection** crate demonstrates a straightforward process injection method using Windows APIs: `VirtualAlloc`, `WriteProcessMemory`, and `CreateThread`.

This crate allocates executable memory in a target process, copies a payload into that memory, and executes it via a new thread. It represents a foundational injection technique frequently used in red team operations to test process security and endpoint defenses.

[Back to the main README](../README.md)
