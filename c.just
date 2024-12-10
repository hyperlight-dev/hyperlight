mkdir := if os() == "windows" { "mkdir -f -p" } else { "mkdir -p"} 

# PE options
c-compile-options-pe := '/GS /W3 /Zi /Od /fp:precise /WX- /std:c17  /showIncludes /MT /EHsc /nologo /diagnostics:column'
c-linker-options-pe := '/MANIFEST:NO /NXCOMPAT /HEAP:131072,131072 /STACK:65536,65536 /DEBUG /RELEASE /ENTRY:"entrypoint" /ALIGN:4096 /FILEALIGN:4096 /NODEFAULTLIB /SAFESEH:NO /driver /SUBSYSTEM:NATIVE /MACHINE:x64 /DYNAMICBASE /TSAWARE:no /section:.text,ERP /section:.rdata,RP /section:.data,RWP /section:.pdata,RP'
c-include-flags-pe := "/I " + root / "src/hyperlight_guest_capi/include/"  + " /I " + root / "src/hyperlight_guest/third_party/musl/include/" + " /I " + root / "src/hyperlight_guest/third_party/musl/arch/x86_64" + " /I " + root / "src/hyperlight_guest/third_party/printf"
c-flags-debug-pe := '/Od /Ob0 /Z7'
c-flags-release-pe := '/O2 /Gy'

# Elf options
# We don't support stack protectors at the moment, but Arch Linux clang auto-enables them for -linux platforms, so explicitly disable them.
c-compile-options-elf := '-nobuiltininc -H --target=x86_64-unknown-linux-none -fno-stack-protector -fstack-clash-protection -mstack-probe-size=4096'
c-include-flags-elf := replace(c-include-flags-pe, '/I ', '-I ')
c-linker-options-elf := '--entry "entrypoint" --nostdlib -pie'
c-flags-debug-elf := '-O0'
c-flags-release-elf := '-O3'

build-c-guests target=default-target: (build-rust-capi target) (compile-c-guest target) (link-c-guest target)

build-rust-capi target=default-target:
    cd src/hyperlight_guest_capi && cargo build --profile {{ if target == "debug" { "dev" } else { target } }}
    cd src/hyperlight_guest_capi && cargo build --profile {{ if target == "debug" { "dev" } else { target } }} --target x86_64-pc-windows-msvc

compile-c-guest target=default-target:
    cd src/tests/c_guests/c_simpleguest   && {{ mkdir }} "./out/{{target}}" && clang-cl /c main.c {{ c-compile-options-pe }} {{ if target == "debug" { c-flags-debug-pe } else { c-flags-release-pe } }} {{c-include-flags-pe}} /Fo"out/{{ target }}/main.obj"
    cd src/tests/c_guests/c_callbackguest && {{ mkdir }} "./out/{{target}}" && clang-cl /c main.c {{ c-compile-options-pe }} {{ if target == "debug" { c-flags-debug-pe } else { c-flags-release-pe } }} {{c-include-flags-pe}} /Fo"out/{{ target }}/main.obj"
    # elf
    cd src/tests/c_guests/c_simpleguest && clang -c {{ c-compile-options-elf }} {{ if target == "debug" { c-flags-debug-elf } else { c-flags-release-elf } }} main.c {{c-include-flags-elf}} -o "out/{{ target }}/main.o"
    cd src/tests/c_guests/c_callbackguest && clang -c {{ c-compile-options-elf }} {{ if target == "debug" { c-flags-debug-elf } else { c-flags-release-elf } }} main.c {{c-include-flags-elf}} -o "out/{{ target }}/main.o"

link-c-guest target=default-target:
    cd src/tests/c_guests/c_simpleguest   && lld-link /OUT:./out/{{ target }}/simpleguest.exe   /PDB:./out/{{ target }}/simpleguest.pdb   {{c-linker-options-pe}} out/{{ target }}/main.obj {{justfile_directory()}}/target/x86_64-pc-windows-msvc/{{ target }}/hyperlight_guest_capi.lib
    cd src/tests/c_guests/c_callbackguest && lld-link /OUT:./out/{{ target }}/callbackguest.exe /PDB:./out/{{ target }}/callbackguest.pdb {{c-linker-options-pe}} out/{{ target }}/main.obj {{justfile_directory()}}/target/x86_64-pc-windows-msvc/{{ target }}/hyperlight_guest_capi.lib
    # elf
    cd src/tests/c_guests/c_simpleguest && ld.lld -o out/{{target}}/simpleguest {{c-linker-options-elf}} out/{{target}}/main.o -l hyperlight_guest_capi -L "{{justfile_directory()}}/target/x86_64-unknown-none/{{target}}"
    cd src/tests/c_guests/c_callbackguest && ld.lld -o out/{{target}}/callbackguest {{c-linker-options-elf}} out/{{target}}/main.o -l hyperlight_guest_capi -L "{{justfile_directory()}}/target/x86_64-unknown-none/{{target}}"

move-c-guests target=default-target:
    cp src/tests/c_guests/c_simpleguest/out/{{target}}/simpleguest.exe src/tests/c_guests/bin/{{target}}/
    cp src/tests/c_guests/c_callbackguest/out/{{target}}/callbackguest.exe src/tests/c_guests/bin/{{target}}/
    # elf
    cp src/tests/c_guests/c_simpleguest/out/{{target}}/simpleguest src/tests/c_guests/bin/{{target}}/
    cp src/tests/c_guests/c_callbackguest/out/{{target}}/callbackguest src/tests/c_guests/bin/{{target}}/
