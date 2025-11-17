### Thread Hijacking

The **Thread Hijacking** crate demonstrates a process injection technique where a thread is initially created in a suspended state, pointing to a benign location instead of the shellcode. After a short delay, the thread’s context is modified to point to the payload and then resumed. 

This approach helps evade detection by security solutions that monitor newly created threads for suspicious memory pointers. It builds on classic injection techniques while illustrating a more advanced method used in red team operations to manipulate thread execution safely.

[Back to the main README](../README.md)
