### Classic Remote Injection

The **Classic Remote Injection** crate demonstrates a process injection technique targeting another running process. It builds on the classic injection approach, but adds the step of obtaining a handle to a target process using its Process ID (PID) via the Windows API `OpenProcess`.

This crate allocates executable memory in the target process, writes a payload into that memory, and executes it with `CreateRemoteThread`. It is designed to illustrate a core remote injection method commonly used in red team operations to test process security and endpoint defenses.

[Back to the main README](../README.md)
