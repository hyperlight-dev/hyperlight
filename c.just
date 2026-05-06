mkdir := if os() == "windows" { "mkdir -f -p" } else { "mkdir -p"} 

# Elf options
# We don't support stack protectors at the moment, but Arch Linux clang auto-enables them for -linux platforms, so explicitly disable them.
c-compile-options-elf := '-nostdlibinc -H --target=x86_64-unknown-linux-none -fno-stack-protector -fstack-clash-protection -mstack-probe-size=4096 -fPIC'
c-include-flags-elf := "-I " + root / "src/hyperlight_guest_capi/include/"  + " -I " + root / "src/hyperlight_libc/third_party/picolibc/libc/include/" + " -I " + root / "src/hyperlight_libc/third_party/picolibc/libc/stdio/" + " -I " + root / "src/hyperlight_libc/include/"
c-linker-options-elf := '--entry "entrypoint" --nostdlib -pie --no-dynamic-linker'
c-flags-debug-elf := '-O0'
c-flags-release-elf := '-O3'

build-c-guests target=default-target: (build-rust-capi target) (compile-c-guest target) (link-c-guest target)

build-rust-capi target=default-target: (ensure-cargo-hyperlight)
    cd src/hyperlight_guest_capi && cargo hyperlight build --profile {{ if target == "debug" { "dev" } else { target } }}

compile-c-guest target=default-target:
    # elf
    cd src/tests/c_guests/c_simpleguest && {{ mkdir }} "./out/{{target}}" && clang -c {{ c-compile-options-elf }} {{ if target == "debug" { c-flags-debug-elf } else { c-flags-release-elf } }} main.c {{c-include-flags-elf}} -o "out/{{ target }}/main.o"

link-c-guest target=default-target:
    # elf
    cd src/tests/c_guests/c_simpleguest && ld.lld -o out/{{target}}/simpleguest {{c-linker-options-elf}} out/{{target}}/main.o -l hyperlight_guest_capi -L "{{justfile_directory()}}/target/x86_64-hyperlight-none/{{target}}"

move-c-guests target=default-target:
    # elf
    cp src/tests/c_guests/c_simpleguest/out/{{target}}/simpleguest src/tests/c_guests/bin/{{target}}/
