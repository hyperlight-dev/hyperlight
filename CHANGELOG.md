# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Prerelease] - Unreleased

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


[Prerelease]: <https://github.com/hyperlight-dev/hyperlight/compare/v0.4.0..HEAD>
[v0.4.0]: <https://github.com/hyperlight-dev/hyperlight/compare/v0.3.0...v0.4.0>
[v0.3.0]: <https://github.com/hyperlight-dev/hyperlight/compare/v0.2.0...v0.3.0>
[v0.2.0]: <https://github.com/hyperlight-dev/hyperlight/compare/v0.1.0...v0.2.0>
[v0.1.0]: <https://github.com/hyperlight-dev/hyperlight/releases/tag/v0.1.0>
