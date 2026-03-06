# Third Party Library Use

This project makes use of the following third party libraries, each of which is contained in a subdirectory of `third_party` with a COPYRIGHT/LICENSE file in the root of the subdirectory. These libraries are used under the terms of their respective licenses. They are also listed in the NOTICE file in the root of the repository.

## picolibc

[picolibc](https://github.com/picolibc/picolibc) is a C library designed for embedded systems, derived from newlib. It is included as a git submodule.

- **Version**: 1.8.11
- **License**: BSD-3-Clause (picolibc), with BSD/MIT-compatible licenses for newlib portions (see `COPYING.picolibc` and `COPYING.NEWLIB`)
- **Submodule path**: `third_party/picolibc`

The submodule uses sparse checkout to exclude GPL/AGPL-licensed files (`test/`, `scripts/`, `COPYING.GPL2`) that are not needed for building and are not compatible with the project's license.

Only the `newlib/` subtree is used by the build (libc and libm sources). Complex math (`complex/`) files from libm are intentionally excluded to reduce binary size.
