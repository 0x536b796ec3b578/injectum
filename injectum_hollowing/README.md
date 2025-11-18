### Hollowing Injection

The **Hollowing Injection** crate demonstrates a process injection technique where a new process is started in a suspended state and its execution is redirected to custom shellcode. Unlike full process hollowing, this implementation does not unmap the original PE. Instead, it overwrites the entry point with a payload.

To locate the entry point, the crate uses `NtQueryInformationProcess` to retrieve `PROCESS_BASIC_INFORMATION`, which includes the `PebBaseAddress`. From the PEB, it reads the process’s image base, then parses the DOS and NT headers to find the exact address of the entry point. The shellcode is written into memory, and the suspended thread is resumed so that the process begins executing the injected payload.

This crate provides a practical example of entry-point injection. It shows a middle ground between classic injection and full process hollowing and can be used to explore process manipulation and thread redirection techniques in a controlled environment.

[Back to the main README](../README.md)
