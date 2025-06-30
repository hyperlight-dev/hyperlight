# Glossary

* [Hyperlight](#hyperlight)
* [Host Application](#host-application)
* [Host](#host)
* [Hypervisor](#hypervisor)
* [Driver](#driver)
* [Hyper-V](#hyper-v)
* [KVM](#kvm)
* [Guest](#guest)
* [Micro Virtual Machine](#micro-virtual-machine)
* [Workload](#workload)
* [Sandbox](#sandbox)

## Hyperlight

Hyperlight refers to the Hyperlight Project and not a specific component. Hyperlight is intended to be used as a library to embed hypervisor-isolated execution support inside a [host application](#host-application).

## Host Application

This is an application that consumes the Hyperlight library, in order to execute code in an hypervisor-isolated environment.

## Host

Host is the machine on which the [host application](#host-application) is running. A host could be a bare metal or virtual machine, when the host is a virtual machine, the nested virtualization is required to run Hyperlight.

## Hypervisor

Hypervisor is the software responsible for creating isolated [micro virtual machines](#micro-virtual-machine), as well as executing [guests](#guest) inside of those micro virtual machines. Hyperlight has [drivers](#driver) for the following hypervisors: [Hyper-V](#hyper-v) on Windows, [Hyper-V](#hyper-v) on Linux, and [KVM](#kvm).

## Driver

Hyperlight supports executing workloads on particular [hypervisors](#hypervisor) through drivers. Each supported hypervisor has its own driver to manage interacting with that hypervisor.

## Hyper-V

Hyper-V is a [hypervisor](#hypervisor) capable of creating and executing isolated [micro virtual machines](#micro-virtual-machine) on both Windows and Linux. On Linux, Hyper-V is sometimes referred to as MSHV (Microsoft Hypervisor).

## KVM

Kernel-based Virtual Machine (KVM) is a [hypervisor](#hypervisor) capable of creating and executing isolated [micro virtual machines](#micro-virtual-machine) on Linux.

## MSHV

MSHV stands for Microsoft Hypervisor and is the name commonly used for Hyper-V when the hypervisor is running Linux dom0 (as opposed to Windows dom0).

## Guest

A guest is a standalone executable binary that is executed inside a hypervisor [micro virtual machine](#micro-virtual-machine). By having purpose-fit guests binaries, as opposed to running a full operating system, Hyperlight achieves low-latency startup times of workloads, since it doesn't need to first boot an entire operating system before executing the workload.

The interface that a guest must implement is specific to the associated [host](#host) and the type of workloads that it may be specialized for executing, such as WebAssembly Modules (Wasm), or a specific language.

## Micro Virtual Machine

A micro virtual machine is an execution environment managed by a hypervisor that isolates a [guest](#guest) from the [host](#host). A hypervisor prevents the guest from directly accessing the host's resources, such as memory, filesystem, devices, memory or CPU.

We use the term Micro Virtual Machine as the VMs are very lightweight compared to traditional VMs, containing no operating system or other unnecessary components. The goal is to provide a minimal environment for executing workloads with low latency and high density. However the isolation provided by the hypervisor is the same as that of a traditional VM.

## Workload

A workload is the code that the [host application](#host-application) wants to execute in an isolated [micro virtual machine](#micro-virtual-machine).

## Sandbox

A Sandbox is the abstraction used in Hyperlight to represent the isolated environment in which a workload is executed. A sandbox is used to create, configure, execute and destroy a [micro virtual machine](#micro-virtual-machine) that runs a [guest](#guest) workload. Sandboxes are created by the [host application](#host-application) using the Hyperlight host library.
