# Security

A primary goal of Hyperlight is to safely execute untrusted or unsafe code.

## Threat Model

Hyperlight assumes that guest binaries are untrusted, and are running arbitrary, potentially malicious code. Despite this, the host should never be compromised. This document outlines some of the steps Hyperlight takes to uphold this strong security guarantee.

### Hypervisor Isolation

Hyperlight runs all guest code inside a Virtual Machine, Each VM only has access to a very specific, small (by default) pre-allocated memory buffer in the host's process, no dynamic memory allocations are allowed. As a result, any attempt by the guest to read or write to memory anywhere outside of that particular buffer is caught by the hypervisor. Similarly, the guest VM does not have any access to devices since none are provided by the hyperlight host library, therefore there is no file, network, etc. access available to guest code.

### Host-Guest Communication (Serialization and Deserialization)

All communication between the host and the guest is done through a shared memory buffer. Messages are serialized and deserialized using [FlatBuffers](https://flatbuffers.dev/). To minimize attack surface area, we rely on FlatBuffers to formally specify the data structures passed to/from the host and guest, and to generate serialization/deserialization code. Of course, a compromised guest can write arbitrary data to the shared memory buffer, but the host will not accept anything that does not match our strongly typed FlatBuffer [schemas](../src/schema).

### Accessing host functionality from the guest

Hyperlight provides a mechanism for the host to register functions that may be called from the guest. This mechanism is useful to allow developers to provide guests with strictly controlled access to functionality we don't make available by default inside the VM. This mechanism likely represents the largest attack surface area of this project.

To mitigate the risk, only functions that have been explicitly exposed to the guest by the host application, are allowed to be called from the guest. Any attempt to call other host functions will result in an error.
