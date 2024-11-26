# HIP 0001 - Hyperfile

<!-- toc -->
- [Summary](#summary)
- [Motivation](#motivation)
    - [Goals](#goals)
    - [Non-Goals](#non-goals)
- [Proposal](#proposal)
    - [User Stories (Optional)](#user-stories-optional)
        - [Story 1](#story-1)
        - [Story 2](#story-2)
    - [Notes/Constraints/Caveats (Optional)](#notesconstraintscaveats-optional)
    - [Risks and Mitigations](#risks-and-mitigations)
- [Design Details](#design-details)
    - [Test Plan](#test-plan)
        - [Unit tests](#unit-tests)
        - [Integration tests](#integration-tests)
        - [e2e tests](#e2e-tests)
- [Implementation History](#implementation-history)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)
<!-- /toc -->

## Summary

This proposal introduces the concept of a `hyperfile.toml` configuration file for specifying
sandbox settings in Hyperlight. This feature will allow users to define configurations such
as `stack_size_override`, `max_execution_time`, and execution modes (`RunInHypervisor` or
`RunInProcess`) in a structured and human-readable format. The goal is to enable host 
applications built with Hyperlight to be configurable in a non-programmatic way, 
allowing users to modify microVM settings without directly altering the host code.

## Motivation

### Goals

- Enable the creation and use of a `hyperfile.toml` configuration file for defining sandbox 
settings.
- Support all current configuration options (e.g., `stack_size_override`, `max_execution_time`) 
in the new format.
- Maintain backwards compatibility with direct code-based sandbox configuration.

### Non-Goals

- This proposal does not aim to change how sandbox configurations are applied programmatically.
- It does not address dynamic configuration updates while a sandbox is running.

## Proposal

The `hyperfile.toml` will serve as a configuration file for sandbox initialization. Users will 
specify parameters in the TOML format. The Hyperlight API will expose methods to parse the 
file and use it to initialize sandboxes.

### User Stories

#### Story 1: Simplifying Development

As a developer, I want to define my sandbox settings in a `hyperfile.toml` so I can avoid 
repetitive code when creating multiple sandboxes with similar configurations.

#### Story 2: Easier Debugging and Sharing

As a systems engineer, I want a standardized configuration file to share with teammates for
debugging or reproducing issues without requiring them to modify source code.

#### Story 3: Supporting Off-the-Shelf Hosts

As a host provider offering an off-the-shelf host leveraging Hyperlight, I want to use a 
`hyperfile.toml` to define configurable sandbox settings. This allows end users to adjust 
microVM parameters without modifying the host's code, ensuring the integrity of the host 
application while providing flexibility to users.

### Notes/Constraints/Caveats

- **Validation**: The parser must validate the TOML file to ensure all required fields are 
provided and within acceptable ranges. Defaults will be used for any omitted optional fields.
- **Error Handling**: Errors during parsing should provide detailed feedback to help users 
correct their configuration files.

### Risks and Mitigations

#### Increased Complexity for New Users

Introducing a configuration file may add initial complexity for users unfamiliar with TOML. 

- **Mitigation**: Provide a well-documented template and examples in the Hyperlight 
documentation.

## Design Details

### Rough Sketch of a `hyperfile.toml`

Below is a sample configuration file that demonstrates how sandbox parameters might be 
defined using TOML syntax:

```toml
# Sandbox Configuration File for Hyperlight

# Define sandbox memory settings
input_data_size = 1024                # Size of input data buffer in bytes
output_data_size = 2048               # Size of output data buffer in bytes
function_definition_size = 512        # Size of function definition buffer in bytes
host_exception_size = 256             # Size of host exception buffer in bytes
guest_error_buffer_size = 128         # Size of guest error buffer in bytes

# Optional overrides for memory sizes
stack_size_override = 4_194_304       # Stack size in bytes (4 MiB)
heap_size_override = 8_388_608        # Heap size in bytes (8 MiB)

# Kernel-specific settings
kernel_stack_size = 8192              # Kernel stack size in bytes

# Execution limits
max_execution_time = "100ms"           # Maximum execution time (in milliseconds)
max_initialization_time = "100ms"      # Maximum initialization time (in milliseconds)
max_wait_for_cancellation = "10ms"     # Maximum wait time for cancellation (in milliseconds)

# Error handling
guest_panic_context_buffer_size = 1024 # Size of guest panic context buffer in bytes

# Execution mode
execution_mode = "RunInHypervisor"    # Options: "RunInHypervisor", "RunInProcess"
```

### Test Plan

#### Unit Tests

- Validate parsing of correct and incorrect `hyperfile.toml` files.
- Ensure all fields map correctly from TOML to sandbox configurations.

#### Integration Tests

- Test initialization of sandboxes using `hyperfile.toml` with different configurations.
- Ensure compatibility with existing programmatic APIs.

#### e2e Tests

- Confirm that sandboxes initialized via `hyperfile.toml` behave identically to those 
configured programmatically.


## Implementation History

- [x] Draft proposal created (November 2024).
- [ ] Initial implementation of TOML parser for sandbox configuration.
- [ ] Test cases and documentation updates.

## Drawbacks

- Adds another layer of configuration that may not be necessary for simple use cases.
- Potentially increases the learning curve for new users.

## Alternatives

1. **YAML or JSON Configurations**:
   - Rejected due to TOML's better readability for specifying nested configurations.

2. **Environment Variables**:
   - Less maintainable and harder to validate compared to a dedicated file.