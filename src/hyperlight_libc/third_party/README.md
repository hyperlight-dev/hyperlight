# Third Party Library Use

This project makes use of the following third party libraries, each of which is contained in a
subdirectory of `third_party` with a COPYRIGHT/LICENSE file in the root of the subdirectory. These
libraries are used under the terms of their respective licenses. They are also listed in the NOTICE
file in the root of the repository.

## picolibc

[picolibc](https://github.com/picolibc/picolibc) is a C library designed for embedded systems,
derived from newlib. It is included as a git submodule pointing to the
[picolibc-bsd](https://github.com/hyperlight-dev/picolibc-bsd) fork.

- **Version**: 1.8.11
- **License**: BSD-3-Clause (picolibc), with BSD/MIT-compatible licenses for newlib portions (see
  `COPYING.picolibc` and `COPYING.NEWLIB`)
- **Submodule path**: `third_party/picolibc`

The submodule uses the picolibc-bsd fork, which is a redistribution of picolibc with all
copyleft-licensed files (GPL/AGPL) removed from the tree and history. Only permissively-licensed
source files are present.
