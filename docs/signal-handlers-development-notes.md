# Signal Handling in Hyperlight

Hyperlight registers custom signal handlers to intercept and manage specific signals, primarily `SIGRTMIN`. Here's an overview of the registration process:
-  **Custom Handlers**:
  - **`SIGRTMIN` Handler**: Utilized for inter-thread signaling, such as execution cancellation.
- **Killing a sandbox**:
  - To stop a sandboxed process, a `SIGRTMIN` signal must be delivered to the thread running the sandboxed code.
  - The sandbox provides an interface to obtain an interrupt handle, which includes the thread ID and a method to dispatch the signal.
  - Hyperlight uses the `pthread_kill` function to send this signal directly to the targeted thread.
