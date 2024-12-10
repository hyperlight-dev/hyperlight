# Third Party Library Use

This project makes use of the following third party libraries, each of which is contained in a subdirectory of `third_party` with a COPYRIGHT/LICENSE file in the root of the subdirectory. These libraries are used under the terms of their respective licenses. They are also listed in the NOTICE file in the root of the repository


## printf

This implementation of printf is from [here](https://github.com/mpaland/printf.git)
The copy was taken at version at [version 4.0](https://github.com/mpaland/printf/releases/tag/v4.0.0)
Changes have been applied to the original code for Hyperlight using this [patch](./printf/printf.patch)

## libc

A partial version of musl libc is used by hyperlight and is located in the [musl](./musl) directory as a git subtree.

The current version is release [v1.2.5](https://git.musl-libc.org/cgit/musl/tag/?h=v1.2.5). Many files have been deleted and changes have been made to some of the remaining files.
