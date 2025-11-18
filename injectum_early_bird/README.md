### Early Bird APC Scheduling

The **Early Bird** crate demonstrates a timing-based APC technique that avoids the uncertainty of queuing an APC on an already running thread. Instead, a new process is started in a suspended state, an APC is queued on its primary thread, and the process is then resumed. Because the thread becomes alertable during its early initialization phase, the queued APC is reliably invoked.

This crate highlights how manipulating a process before it fully starts can be used in research and defensive testing to explore thread scheduling behavior and alertable states in Windows processes.

[Back to the main README](../README.md)
