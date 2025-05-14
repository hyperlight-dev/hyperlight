mkdir := if os() == "windows" { "mkdir -f -p" } else { "mkdir -p"} 

# Elf options
# We don't support stack protectors at the moment, but Arch Linux clang auto-enables them for -linux platforms, so explicitly disable them.
c-compile-options-elf := '-nobuiltininc -H --target=x86_64-unknown-linux-none -fno-stack-protector -fstack-clash-protection -mstack-probe-size=4096 -fPIC'
c-include-flags-elf := "-I " + root / "src/hyperlight_guest_capi/include/"  + " -I " + root / "src/hyperlight_guest/third_party/musl/include/" + " -I " + root / "src/hyperlight_guest/third_party/musl/arch/x86_64" + " -I " + root / "src/hyperlight_guest/third_party/printf"
c-linker-options-elf := '--entry "entrypoint" --nostdlib -pie'
c-flags-debug-elf := '-O0'
c-flags-release-elf := '-O3'

build-c-guests target=default-target: (build-rust-capi target) (compile-c-guest target) (link-c-guest target)

build-rust-capi target=default-target:
    cd src/hyperlight_guest_capi && cargo build --profile {{ if target == "debug" { "dev" } else { target } }}

compile-c-guest target=default-target:
    # elf
    cd src/tests/c_guests/c_simpleguest && {{ mkdir }} "./out/{{target}}" && clang -c {{ c-compile-options-elf }} {{ if target == "debug" { c-flags-debug-elf } else { c-flags-release-elf } }} main.c {{c-include-flags-elf}} -o "out/{{ target }}/main.o"
    cd src/tests/c_guests/c_callbackguest && {{ mkdir }} "./out/{{target}}" && clang -c {{ c-compile-options-elf }} {{ if target == "debug" { c-flags-debug-elf } else { c-flags-release-elf } }} main.c {{c-include-flags-elf}} -o "out/{{ target }}/main.o"

link-c-guest target=default-target:
    # elf
    cd src/tests/c_guests/c_simpleguest && ld.lld -o out/{{target}}/simpleguest {{c-linker-options-elf}} out/{{target}}/main.o -l hyperlight_guest_capi -L "{{justfile_directory()}}/target/x86_64-unknown-none/{{target}}"
    cd src/tests/c_guests/c_callbackguest && ld.lld -o out/{{target}}/callbackguest {{c-linker-options-elf}} out/{{target}}/main.o -l hyperlight_guest_capi -L "{{justfile_directory()}}/target/x86_64-unknown-none/{{target}}"

move-c-guests target=default-target:
    # elf
    cp src/tests/c_guests/c_simpleguest/out/{{target}}/simpleguest src/tests/c_guests/bin/{{target}}/
    cp src/tests/c_guests/c_callbackguest/out/{{target}}/callbackguest src/tests/c_guests/bin/{{target}}/
