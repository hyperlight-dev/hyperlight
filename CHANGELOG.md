# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Prerelease] - Unreleased

### Fixed

- Fix race condition when killing sandboxes by @simongdavies in https://github.com/hyperlight-dev/hyperlight/pull/959

### Changed

- Added poison sandbox detection  by @ludfjig in https://github.com/hyperlight-dev/hyperlight/pull/931
- Update mshv crates for Azure Linux to v0.6.4 (from v0.6.1) by @simongdavies in https://github.com/hyperlight-dev/hyperlight/pull/993

### Removed
- Removed seccomp feature from hyperlight-host by @dblnz in https://github.com/hyperlight-dev/hyperlight/pull/971
- Removed support for Azure Linux 2 by @dblnz in https://github.com/hyperlight-dev/hyperlight/pull/973

## [v0.10.0] - 2025-10-02

### Fixed

- Fix error code conversion for Exception enum TryFrom implementation by @vshailesh in https://github.com/hyperlight-dev/hyperlight/pull/869
- Remove Allocations from Panic Handler by @adamperlin in https://github.com/hyperlight-dev/hyperlight/pull/818

### Changed

- Update rust to 1.89 by @simongdavies in https://github.com/hyperlight-dev/hyperlight/pull/883
- Update mshv crates for Azure Linux to v0.6.1 (from v0.3.2) by @simongdavies in https://github.com/hyperlight-dev/hyperlight/pull/891
- Only clear io buffer after unsuccessful guest call by @ludfjig in https://github.com/hyperlight-dev/hyperlight/pull/811

## [v0.9.0] - 2025-08-28

### Fixed

- fix release blocker so it only blocks on release branches by @simongdavies in https://github.com/hyperlight-dev/hyperlight/pull/777
- Enforce release builds for benchmarks and simplify command interface by @Copilot in https://github.com/hyperlight-dev/hyperlight/pull/741
- fix(guest-bin): align user memory allocations by @andreiltd in https://github.com/hyperlight-dev/hyperlight/pull/753
- Fix unbounded growth of panic hook after each new sandbox by @ludfjig in https://github.com/hyperlight-dev/hyperlight/pull/827
- Update the like-ci recipe by @simongdavies in https://github.com/hyperlight-dev/hyperlight/pull/837
- Fixes to Host Call Fuzzing by @adamperlin in https://github.com/hyperlight-dev/hyperlight/pull/840

### Changed

- Optimize function call serializing by @ludfjig in https://github.com/hyperlight-dev/hyperlight/pull/778
- Make the component macros support passing host resources to guests by @syntactically in https://github.com/hyperlight-dev/hyperlight/pull/839
- Build c guests as required by benchmarks by @ludfjig in https://github.com/hyperlight-dev/hyperlight/pull/822

### Removed
- Remove DbgMemAccessHandlerCaller trait and DbgMemAccessHandlerWrapper abstractions by @Copilot in https://github.com/hyperlight-dev/hyperlight/pull/824

## [v0.8.0] - 2025-08-08

:warning: `hyperlight_component_macro::host_bindgen` and `hyperlight_component_macro::guest_bindgen` used the `Callable` trait which no longer restores state after each function call and requires an explicit Snapshot Restore using the newly exposed Snapshot API. See https://github.com/hyperlight-dev/hyperlight/pull/697 and https://github.com/hyperlight-dev/hyperlight/pull/761

### Fixed
- gdb: fix issue "Debug not enabled" when `gdb` feature was enabled by @dblnz in https://github.com/hyperlight-dev/hyperlight/pull/678
- Fix Windows build with `--no-default-features` by @danbugs in https://github.com/hyperlight-dev/hyperlight/pull/712
- fix(guest-bin): move logger initialization by @andreiltd in https://github.com/hyperlight-dev/hyperlight/pull/755
- Fix mem mgr not initialized by @dblnz in https://github.com/hyperlight-dev/hyperlight/pull/745

### Changed
- Remove some dev-dependencies and cargo features to speed up compilation by @ludfjig in https://github.com/hyperlight-dev/hyperlight/pull/535
- Introduce a separate KVM error variant of HyperlightError. by @ludfjig in https://github.com/hyperlight-dev/hyperlight/pull/771API. by @jprendes in https://github.com/hyperlight-dev/hyperlight/pull/697
- Evolving and Devolving apis replaced by Snapshot API
  - Remove sandbox evolving and devolving and replace it with snapshotting API. by @jprendes in https://github.com/hyperlight-dev/hyperlight/pull/697
  - Bring back the previous behavior of `call_guest_function_by_name` by @jprendes in https://github.com/hyperlight-dev/hyperlight/pull/761

### Added
- Memory Mapping Support 
  - Support mapping host memory into the guest by @syntactically in https://github.com/hyperlight-dev/hyperlight/pull/696
  - Make MultiUseSandbox::map_file_cow public by @ludfjig in https://github.com/hyperlight-dev/hyperlight/pull/725
  - Add memory mapping support with KVM by @jprendes in https://github.com/hyperlight-dev/hyperlight/pull/709
  - Make sure mmapped memory is not mapped writeable into sandbox in kvm by @ludfjig in https://github.com/hyperlight-dev/hyperlight/pull/740
  - Make snapshots region aware by @ludfjig in https://github.com/hyperlight-dev/hyperlight/pull/742
  - Restrict restoring sandboxes to snapshot taken on self by @ludfjig in https://github.com/hyperlight-dev/hyperlight/pull/746
- Enable guest tracing  by @dblnz in https://github.com/hyperlight-dev/hyperlight/pull/695

### Removed
- Removed the OutBHandler and MemAccessHandler abstractions and related implementations. by @simongdavies in https://github.com/hyperlight-dev/hyperlight/pull/732
  
## [v0.7.0] - 2025-06-26

### Fixed
- gdb: fix sandbox function cancellation when gdb enabled by @dblnz in https://github.com/hyperlight-dev/hyperlight/pull/621
- Let windows decide at which address to map shared memory in surrogate process by @ludfjig in https://github.com/hyperlight-dev/hyperlight/pull/637
- Don't log expected error on each guest function call by @ludfjig in https://github.com/hyperlight-dev/hyperlight/pull/662
- Adds a missing clippy allow by @jsturtevant in https://github.com/hyperlight-dev/hyperlight/pull/663

### Changed
- improve the performance of building page tables by @simongdavies in https://github.com/hyperlight-dev/hyperlight/pull/635
- Make interrupt retry delay methods Linux-only by @copilot-swe-agent in https://github.com/hyperlight-dev/hyperlight/pull/647
  
### Added
- Support ELF core dump creation on guest crash by @dblnz in https://github.com/hyperlight-dev/hyperlight/pull/417
- Added capability to load extra blob data in sandbox by @danbugs in https://github.com/hyperlight-dev/hyperlight/pull/605
- Add license scan report and status by @fossabot in https://github.com/hyperlight-dev/hyperlight/pull/598
- Create GOVERNANCE.md by @benazirk in https://github.com/hyperlight-dev/hyperlight/pull/556
- [host] adds init-paging feature by @danbugs in https://github.com/hyperlight-dev/hyperlight/pull/639
- Enable guest debugging for HyperV on windows by @dblnz in https://github.com/hyperlight-dev/hyperlight/pull/478

### Removed  
- Remove support for building PE files from hyperlight-guest-bin build.rs by @simongdavies in https://github.com/hyperlight-dev/hyperlight/pull/572

## [v0.6.1] - 2025-06-12

### Fixed

- Make OS_PAGE_SIZE public again by @jprendes in https://github.com/hyperlight-dev/hyperlight/pull/609
- Bring back HostFunctionDefinitions Region by @danbugs in https://github.com/hyperlight-dev/hyperlight/pull/600
- Allow hyperlight-host to build with x86_64-unknown-linux-musl target by @simongdavies in https://github.com/hyperlight-dev/hyperlight/pull/601

## [v0.6.0] - 2025-06-06

### Fixed
- Prevent openat from trapping on seccomp thread, by making it return EACCES instead by @ludfjig in https://github.com/hyperlight-dev/hyperlight/pull/573

### Changed
- Remove hypervisor_handler thread by @ludfjig in https://github.com/hyperlight-dev/hyperlight/pull/533
- Make GuestBinary::Buffer variant take slice instead of owned vec by @ludfjig in https://github.com/hyperlight-dev/hyperlight/pull/559

### Added
- Add component bindgen macros by @syntactically in https://github.com/hyperlight-dev/hyperlight/pull/376
- Adding ws2025 to the dep_rest matrix by @marosset in https://github.com/hyperlight-dev/hyperlight/pull/551

## [v0.5.1] - 2025-06-02
### Fixed
- Fixed an issue with the `hyperlight_host` not building on v0.5.0

## [v0.5.0] - 2025-05-28

### Changed
- Change base address from 0x200_000 to 0x0 by @danbugs in https://github.com/hyperlight-dev/hyperlight/pull/450
- Unify HostFunctionXX traits into a single HostFunction by @jprendes in https://github.com/hyperlight-dev/hyperlight/pull/
- Improve the ergonomics of registering host functions by @jprendes in https://github.com/hyperlight-dev/hyperlight/pull/468
- Remove generics from SupportedParameterType and SupportedReturnType traits by @jprendes in https://github.com/hyperlight-dev/hyperlight/pull/475
- Improve ergonomics of SupportedParameterType and SupportedReturnType by @jprendes in https://github.com/hyperlight-dev/hyperlight/pull/476

### Fixed
- Add error logging when MapViewOfFileNuma2 fails by @ludfjig in https://github.com/hyperlight-dev/hyperlight/pull/460
- Make common and guest libs portable by @danbugs in https://github.com/hyperlight-dev/hyperlight/pull/524
- Fix breaking changes for hyperlight js by @simongdavies in https://github.com/hyperlight-dev/hyperlight/pull/531

### Added
- Gdb debug improvements by @dblnz in https://github.com/hyperlight-dev/hyperlight/pull/456

### Removed  
- Remove kernel stack and boot stack memory regions by @danbugs in https://github.com/hyperlight-dev/hyperlight/pull/451
- Removing HostFunctionDefinitions region by @danbugs in https://github.com/hyperlight-dev/hyperlight/pull/453
- Removed host error region by @danbugs in https://github.com/hyperlight-dev/hyperlight/pull/457
- Remove dependency on the paste crate by @jprendes in https://github.com/hyperlight-dev/hyperlight/pull/467
- Remove support from hyperlight_host for PE formatted guests by @simongdavies in https://github.com/hyperlight-dev/hyperlight/pull/485
- Remove in process mode from hyperlight-host by @simongdavies in https://github.com/hyperlight-dev/hyperlight/pull/490
- Remove `host_print_writer` from the arguments to `UninitializedSandbox::new` by @jprendes in https://github.com/hyperlight-dev/hyperlight/pull/487


## [v0.4.0] - 2025-04-30

### Changed
- Metrics are now emitted using the [metrics](https://crates.io/crates/metrics) crate by @ludfjig in [#361](https://github.com/hyperlight-dev/hyperlight/pull/361)

### Fixed
- Fixed race condition causing thread to incorrectly believe it finished executing by @ludfjig in [#385](https://github.com/hyperlight-dev/hyperlight/pull/385)
- Fixed incorrect logging levels in guest by @simongdavies in [#410](https://github.com/hyperlight-dev/hyperlight/pull/410)
- Fixed missing compiler flags for building c guests by @prydt in [#421](https://github.com/hyperlight-dev/hyperlight/pull/421) 

## [v0.3.0] - 2025-03-27

### Added
- Gdb support for mshv guests #327 by @dblnz in [#327](https://github.com/hyperlight-dev/hyperlight/pull/327)
- Add fuzzing targets for fuzzing guest and host call parameters and return value by @ludfjig in [#259](https://github.com/hyperlight-dev/hyperlight/pull/259)

### Changed
- Make host-guest result API generic by @ludfjig in [#259](https://github.com/hyperlight-dev/hyperlight/pull/259)

### Removed  
- 

### Fixed  
- Fixed devcontainer permission issues by @myadav in [#326](https://github.com/hyperlight-dev/hyperlight/pull/326)

## [v0.2.0] - 2025-02-25

### Added  
- Adds support for Azure Linux 3 by @simongdavies in [#51](https://github.com/hyperlight-dev/hyperlight/pull/51)  
- Add GDB support by @dblnz in [#111](https://github.com/hyperlight-dev/hyperlight/pull/111)  
- Document DCO by @devigned in [#22](https://github.com/hyperlight-dev/hyperlight/pull/22)  
- Run CI on intel machines by @danbugs in [#32](https://github.com/hyperlight-dev/hyperlight/pull/32)  
- Run spell checks on repo by @andreiltd in [#58](https://github.com/hyperlight-dev/hyperlight/pull/58)  
- Add devcontainer config by @dblnz in [#54](https://github.com/hyperlight-dev/hyperlight/pull/54)  
- Add exception handling to Hyperlight guest by @danbugs in [#250](https://github.com/hyperlight-dev/hyperlight/pull/250)  
- Add community meeting info to our README.md by @marosset in [#231](https://github.com/hyperlight-dev/hyperlight/pull/231)  

### Changed  
- Avoid eagerly doing unnecessary string formatting by @ludfjig in [#73](https://github.com/hyperlight-dev/hyperlight/pull/73)  
- Use `CreateFileMapping\MapViewOfFile` and `UnmapViewOfFile\CloseHandle` instead of `VirtualAllocEx` and `VirtualFreeEx` on Windows by @simongdavies in [#135](https://github.com/hyperlight-dev/hyperlight/pull/135)  
- Avoid requiring specific environment variables during testing by @ludfjig in [#108](https://github.com/hyperlight-dev/hyperlight/pull/108)  

### Removed  
- Remove SingleUseSandbox by @ludfjig in [#125](https://github.com/hyperlight-dev/hyperlight/pull/125)  
- Remove custom alloca by @ludfjig in [#106](https://github.com/hyperlight-dev/hyperlight/pull/106)  

### Fixed  
- Fix issues with using `CreateMapViewOfFile` with `inprocess` feature by @simongdavies in [#2340](https://github.com/hyperlight-dev/hyperlight/pull/2340)  
- Reset guest memory when guest function fails by @ludfjig in [#208](https://github.com/hyperlight-dev/hyperlight/pull/208)  
- Improve error when guest binary not found by @ludfjig in [#55](https://github.com/hyperlight-dev/hyperlight/pull/55)  
- Ensure windows version is supported by @simongdavies in [#110](https://github.com/hyperlight-dev/hyperlight/pull/110)  



## [v0.1.0] - 2024-11-24

The Initial Hyperlight Release 🎉 


[Prerelease]: <https://github.com/hyperlight-dev/hyperlight/compare/v0.10.1..HEAD>
[v0.10.1]: <https://github.com/hyperlight-dev/hyperlight/compare/v0.10.0...v0.10.1>
[v0.10.0]: <https://github.com/hyperlight-dev/hyperlight/compare/v0.9.0...v0.10.0>
[v0.9.0]: <https://github.com/hyperlight-dev/hyperlight/compare/v0.8.0...v0.9.0>
[v0.8.0]: <https://github.com/hyperlight-dev/hyperlight/compare/v0.7.0...v0.8.0>
[v0.7.0]: <https://github.com/hyperlight-dev/hyperlight/compare/v0.6.1...v0.7.0>
[v0.6.1]: <https://github.com/hyperlight-dev/hyperlight/compare/v0.6.0...v0.6.1>
[v0.6.0]: <https://github.com/hyperlight-dev/hyperlight/compare/v0.5.1...v0.6.0>
[v0.5.1]: <https://github.com/hyperlight-dev/hyperlight/compare/v0.5.0...v0.5.1>
[v0.5.0]: <https://github.com/hyperlight-dev/hyperlight/compare/v0.4.0...v0.5.0>
[v0.4.0]: <https://github.com/hyperlight-dev/hyperlight/compare/v0.3.0...v0.4.0>
[v0.3.0]: <https://github.com/hyperlight-dev/hyperlight/compare/v0.2.0...v0.3.0>
[v0.2.0]: <https://github.com/hyperlight-dev/hyperlight/compare/v0.1.0...v0.2.0>
[v0.1.0]: <https://github.com/hyperlight-dev/hyperlight/releases/tag/v0.1.0>
