This repository contains hyperlight. Hyperlight is a lightweight Virtual Machine Manager (VMM) designed to be embedded within applications.
It enables safe execution of untrusted code within micro virtual machines with very low latency and minimal overhead.

This project uses just as a runner for building, testing etc. Just should already be installed. Most of the code in the repository is written in Rust, with a few files in C.

## Code Standards

Make sure that code is formatted and linted before committing. You can do this by running the following command:

```bash
just fmt-apply
```
This will format the code and apply any necessary changes. You can also run the following command to check for any linting errors:

```bash
just clippy debug
just clippy release
```

If any lints fail you can try to fix them by running the following command for debug failures:

```bash
    cargo clippy --fix --all
```
And the following command for release failures:

```bash
    cargo clippy --fix --all --release
```

If this does not work, you should try and fix the errors and then run the commands again.

## Development flow

- build:
    - `just build` - builds the project in debug mode
    - `just build release` - builds the project in release mode
    - `just guests` - builds the guest library and test guests for both debug and release modes
- test
    - `just test` - runs all tests in debug mode
    - `just test release` - runs all tests in release mode

**IMPORTANT** You will need to run `just guests` to build the guest library before running the tests.

Before pushing your code, make sure to run the following commands to ensure that everything is working correctly make sure all tests pass by running
```bash
just test-like-ci
just test-like-ci release
```

## Key Instructions

**IMPORTANT**: Please make sure to follow these instructions when making changes to the codebase. If you cannot follow these instructions, please discuss it with the team first.

Follow best practices and idioms for writing Rust code.
Maintain the structure and organization of the codebase. Do not introduce new crates or dependencies without discussing them first.
Make sure to write tests for any new code you add. Follow the existing testing patterns in the codebase.
Make sure to fully document any new code you add. Use rustdoc comments and follow guidelines for good documentation.
Make sure that any changes which alter anything documented in the README or the documentation in the docs directory are reflected in the documentation.
Make sure that you label the PRs that you create with the correct labels. You can find details about which labels to use in the documents `docs/github-labels.md`.
Make sure that you do not include any large binary files in your PR. If you need to include a large binary file, please discuss it with the team first.
Make sure that you keep commits small and focused. Each commit should represent a single change or addition to the codebase. This will make it easier for reviewers to understand your changes and for you to revert them if necessary.
Make sure that you arrange your commits in a logical order. You can use `git rebase -i` to do this.
If you update your PR branch with new commits, make sure to rebase your branch on top of the main branch. This will help keep the commit history clean and make it easier to review your changes.
Make sure that you do not have any merge commits in your PR.
If when running tests you receive an Error like this "Error("No Hypervisor was found for Sandbox, Hypervisor Handler Message Receive Timedout")" then the real error is the string inside the brackets before the comma, so in this example
the error is "No Hypervisor was found for Sandbox".
If you see the error "No Hypervisor was found for Sandbox" then you if you are running on Linux you should check to see if there is a device called "kvm" or "mshv" in `/dev` and if it is present you should also check to see if you have rw access to it. You should ensure that you output the results of these checks for diagnostic purposes. 
This repository requires commits to be signed you should ensure that any commits that you create are done with `commit.gpgsign=true`. Also commits should also be signed with the `--signoff` option to comply with the DCO requirement.

## Repository Structure
- `dev/` - contains development scripts and tools
- `src/` - contains the source code for the project
- `.editorconfig` - contains the editor config for the project you should use this to configure your editor to use the same settings as the rest of the project
- `Justfile` - contains the just commands for building, testing and running the project
- `fuzz` - contains the fuzzing tests for the project
- `src/hyperlight_common/` - contains the common code shared between the host and guest
- `src/hyperlight_guest/` - contains the hyperlight-guest library code
- `src/hyperlight_host/` - contains the hyperlight-host library code
- `src/hyperlight_guest_capi/` - contains the hyperlight-guest C library code
- `src/hyperlight_testing/` - contains the shared code for tests
- `schema/` - contains the flatbuffer schemas for the project
- `tests/` - contains the test guest code for the project in C and Rust
