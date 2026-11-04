# How code is run inside a VM

This document details how VMs are very quickly and efficiently created and configured to run arbitrary code.

## Background

Hyperlight is a library for creating micro virtual machines (VMs) intended for executing small, short-running functions. This use case is different from that of many other VM platforms, which are aimed at longer-running, more complex workloads.

A very rough contrast between Hyperlight's offerings and other platforms is as follows:

| Feature                                                                 | Hyperlight | Other platforms    |
|-------------------------------------------------------------------------|------------|--------------------|
| Hardware isolation (vCPU, virtual memory)                               | Yes        | Yes                |
| Shared memory between host and in-VM process                            | Yes        | Yes <sup>[2]</sup> |
| Lightweight function calls between host and in-VM process (the "guest") | Yes        | No                 |
| Bootloader/OS kernel                                                    | No         | Yes <sup>[1]</sup> |
| Virtual networking                                                      | No         | Yes <sup>[2]</sup> |
| Virtual filesystem                                                      | No         | Yes <sup>[1]</sup> |


As seen in this table, Hyperlight offers little more than a CPU and memory. We've removed every feature we could, while still providing a machine on which arbitrary code can execute, so we can achieve our various use cases and efficiency targets.

## How code runs

With this background in mind, it's well worth focusing on the "lifecycle" of a VM -- how, exactly, a VM is created, modified, loaded, executed, and ultimately destroyed.

At the highest level, Hyperlight takes roughly the following steps to create and run arbitrary code inside a VM:

1. Loads a specially built, statically linked binary (currently, the [PE](https://en.wikipedia.org/wiki/Portable_Executable) and [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) executable formats are supported) into memory. This is the code that is executed inside a virtual machine.
2. Allocates a scratch memory region. The guest maps its stack and heap from scratch on first touch. Scratch also holds the regions used for communication between the host and the guest.
3. Creates a Virtual Machine and maps shared memory into it
5. Create one virtual CPU (vCPU) within the newly created VM
6. Write appropriate values to the new vCPUs registers.
7. In a loop, tell previously created vCPU to run until we reach a halt message, one of several known error states, or an unsupported message
   1. In the former case, exit successfully
   2. In any of the latter cases, exit with a failure message

---

_<sup>[1]</sup> nearly universal support_

_<sup>[2]</sup> varied support_
