# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Prerelease] - Unreleased


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
