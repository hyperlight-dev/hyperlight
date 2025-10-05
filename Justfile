import 'c.just'

set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]
set dotenv-load := true

set-env-command := if os() == "windows" { "$env:" } else { "export " }
bin-suffix := if os() == "windows" { ".bat" } else { ".sh" }

################
### cross-rs ###
################
target-triple := env('TARGET_TRIPLE', "")
docker := if target-triple != "" { require("docker") } else { "" }
# this command is only used host side not for guests
# include the --target-dir for the cross builds.  This ensures that the builds are separated and avoid any conflicts with the guest builds
cargo-cmd := if target-triple != "" { require("cross") } else { "cargo" } 
target-triple-flag := if target-triple != "" { "--target " + target-triple + " --target-dir ./target/host"} else { "" }
# set up cross to use the devices
kvm-gid := if path_exists("/dev/kvm") == "true" { `getent group kvm | cut -d: -f3` } else { "" }
export CROSS_CONTAINER_OPTS := if path_exists("/dev/kvm") == "true" { "--device=/dev/kvm" } else if path_exists("/dev/mshv") == "true" { "--device=/dev/mshv" } else { "" }
export CROSS_CONTAINER_GID := if path_exists("/dev/kvm") == "true" { kvm-gid } else {"1000"} # required to have ownership of the mapped in device on kvm

root := justfile_directory()

default-target := "debug"
simpleguest_source := "src/tests/rust_guests/simpleguest/target/x86_64-unknown-none"
dummyguest_source := "src/tests/rust_guests/dummyguest/target/x86_64-unknown-none"
witguest_source := "src/tests/rust_guests/witguest/target/x86_64-unknown-none"
rust_guests_bin_dir := "src/tests/rust_guests/bin"

################
### BUILDING ###
################
alias b := build
alias rg := build-and-move-rust-guests
alias cg := build-and-move-c-guests

# build host library
build target=default-target:
    {{ cargo-cmd }} build --profile={{ if target == "debug" { "dev" } else { target } }} {{ target-triple-flag }}

# build testing guest binaries
guests: build-and-move-rust-guests build-and-move-c-guests

witguest-wit:
    cargo install --locked wasm-tools
    cd src/tests/rust_guests/witguest && wasm-tools component wit guest.wit -w -o interface.wasm

build-rust-guests target=default-target features="": (witguest-wit)
    cd src/tests/rust_guests/simpleguest && cargo build {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} 
    cd src/tests/rust_guests/dummyguest && cargo build {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} 
    cd src/tests/rust_guests/witguest && cargo build {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }}

@move-rust-guests target=default-target:
    cp {{ simpleguest_source }}/{{ target }}/simpleguest* {{ rust_guests_bin_dir }}/{{ target }}/
    cp {{ dummyguest_source }}/{{ target }}/dummyguest* {{ rust_guests_bin_dir }}/{{ target }}/
    cp {{ witguest_source }}/{{ target }}/witguest* {{ rust_guests_bin_dir }}/{{ target }}/

build-and-move-rust-guests: (build-rust-guests "debug") (move-rust-guests "debug") (build-rust-guests "release") (move-rust-guests "release")
build-and-move-c-guests: (build-c-guests "debug") (move-c-guests "debug") (build-c-guests "release") (move-c-guests "release")

clean: clean-rust

clean-rust: 
    cargo clean
    cd src/tests/rust_guests/simpleguest && cargo clean
    cd src/tests/rust_guests/dummyguest && cargo clean
    {{ if os() == "windows" { "cd src/tests/rust_guests/witguest -ErrorAction SilentlyContinue; cargo clean" } else { "[ -d src/tests/rust_guests/witguest ] && cd src/tests/rust_guests/witguest && cargo clean || true" } }}
    {{ if os() == "windows" { "Remove-Item src/tests/rust_guests/witguest/interface.wasm -Force -ErrorAction SilentlyContinue" } else { "rm -f src/tests/rust_guests/witguest/interface.wasm" } }}
    git clean -fdx src/tests/c_guests/bin src/tests/rust_guests/bin

################
### TESTING ####
################

# Note: most testing recipes take an optional "features" comma separated list argument. If provided, these will be passed to cargo as **THE ONLY FEATURES**, i.e. default features will be disabled.

# convenience recipe to run all tests with the given target and features (similar to CI)
test-like-ci config=default-target hypervisor="kvm":
    @# with default features
    just test {{config}} {{ if hypervisor == "mshv" {"mshv2"} else {""} }}

    @# with only one driver enabled + seccomp + build-metadata + init-paging
    just test {{config}} seccomp,build-metadata,init-paging,{{ if hypervisor == "mshv" {"mshv2"} else if hypervisor == "mshv3" {"mshv3"} else {"kvm"} }}

    @# make sure certain cargo features compile
    just check

    @# without any driver (should fail to compile)
    just test-compilation-no-default-features {{config}}

    @# test the crashdump feature
    just test-rust-crashdump {{config}}

    @# test the tracing related features
    {{ if os() == "linux" { "just test-rust-tracing " + config + " " + if hypervisor == "mshv" { "mshv2" } else if hypervisor == "mshv3" { "mshv3" } else { "kvm" } } else { "" } }}

like-ci config=default-target hypervisor="kvm":
    @# Ensure up-to-date Cargo.lock
    cargo fetch --locked

    @# fmt
    just fmt-check

    @# clippy
    {{ if os() == "windows" { "just clippy " + config } else { "" } }}
    {{ if os() == "windows" { "just clippy-guests " + config } else { "" } }}

    @# clippy exhaustive check
    {{ if os() == "linux" { "just clippy-exhaustive " + config } else { "" } }}

    @# Verify MSRV
    ./dev/verify-msrv.sh hyperlight-common hyperlight-guest hyperlight-guest-bin hyperlight-host hyperlight-component-util hyperlight-component-macro hyperlight-guest-tracing-macro hyperlight-guest-tracing

    @# Build and move Rust guests
    just build-rust-guests {{config}}
    just move-rust-guests {{config}}

    @# Build c guests
    just build-c-guests {{config}}
    just move-c-guests {{config}}

    @# Build
    just build {{config}}

    @# Run Rust tests
    just test-like-ci {{config}} {{hypervisor}}

    @# Run Rust examples - Windows
    {{ if os() == "windows" { "just run-rust-examples " + config } else { "" } }}

    @# Run Rust examples - linux
    {{ if os() == "linux" { "just run-rust-examples-linux " + config + " " + if hypervisor == "mshv" { "mshv2" } else if hypervisor == "mshv3" { "mshv3" } else { "kvm" } } else { "" } }}

    @# Run Rust Gdb tests
    just test-rust-gdb-debugging {{ config }} {{ if hypervisor == "mshv" { "mshv2" } else if hypervisor == "mshv3" { "mshv3" } else { "kvm" } }} 

    @# Run Rust Crashdump tests
    just test-rust-crashdump {{config}} {{ if hypervisor == "mshv" { "mshv2" } else if hypervisor == "mshv3" { "mshv3" } else { "kvm" } }}

    @# Run Rust Tracing tests - linux
    {{ if os() == "linux" { "just test-rust-tracing " + config + " " + if hypervisor == "mshv" { "mshv2" } else if hypervisor == "mshv3" { "mshv3" } else { "kvm" } } else { "" } }}

    @# Run benchmarks
    {{ if config == "release" { "just bench-ci main " + if hypervisor == "mshv" { "mshv2" } else if hypervisor == "mshv3" { "mshv3" } else { "kvm" } } else { "" } }}

# runs all tests
test target=default-target features="": (test-unit target features) (test-isolated target features) (test-integration "rust" target features) (test-integration "c" target features) (test-seccomp target features) (test-doc target features)

# runs unit tests
test-unit target=default-target features="":
    {{ cargo-cmd }} test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F init-paging," + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} {{ target-triple-flag }} --lib

# runs tests that requires being run separately, for example due to global state
test-isolated target=default-target features="" :
    {{ cargo-cmd }} test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F init-paging," + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} {{ target-triple-flag }} -p hyperlight-host --lib -- sandbox::uninitialized::tests::test_trace_trace --exact --ignored
    {{ cargo-cmd }} test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F init-paging," + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} {{ target-triple-flag }} -p hyperlight-host --lib -- sandbox::uninitialized::tests::test_log_trace --exact --ignored
    {{ cargo-cmd }} test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F init-paging," + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} {{ target-triple-flag }} -p hyperlight-host --lib -- sandbox::initialized_multi_use::tests::create_1000_sandboxes --exact --ignored
    {{ cargo-cmd }} test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F init-paging," + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} {{ target-triple-flag }} -p hyperlight-host --lib -- sandbox::outb::tests::test_log_outb_log --exact --ignored
    {{ cargo-cmd }} test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F init-paging," + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} {{ target-triple-flag }} -p hyperlight-host --lib -- mem::shared_mem::tests::test_drop --exact --ignored
    {{ cargo-cmd }} test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F init-paging," + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} {{ target-triple-flag }} -p hyperlight-host --test integration_test -- log_message --exact --ignored
    @# metrics tests
    {{ cargo-cmd }} test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F function_call_metrics,init-paging," + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} {{ target-triple-flag }} -p hyperlight-host --lib -- metrics::tests::test_metrics_are_emitted --exact 
# runs integration tests. Guest can either be "rust" or "c"
test-integration guest target=default-target features="":
    @# run execute_on_heap test with feature "executable_heap" on and off
    {{if os() == "windows" { "$env:" } else { "" } }}GUEST="{{guest}}"{{if os() == "windows" { ";" } else { "" } }} {{ cargo-cmd }} test --profile={{ if target == "debug" { "dev" } else { target } }} {{ target-triple-flag }} --test integration_test execute_on_heap {{ if features =="" {" --features executable_heap"} else {"--features executable_heap," + features} }} -- --ignored
    {{if os() == "windows" { "$env:" } else { "" } }}GUEST="{{guest}}"{{if os() == "windows" { ";" } else { "" } }} {{ cargo-cmd }} test --profile={{ if target == "debug" { "dev" } else { target } }} {{ target-triple-flag }} --test integration_test execute_on_heap {{ if features =="" {""} else {"--features " + features} }} -- --ignored
    
    @# run the rest of the integration tests
    {{if os() == "windows" { "$env:" } else { "" } }}GUEST="{{guest}}"{{if os() == "windows" { ";" } else { "" } }} {{ cargo-cmd }} test -p hyperlight-host {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F init-paging," + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} {{ target-triple-flag }} --test '*'

# runs seccomp tests
test-seccomp target=default-target features="":
    @# run seccomp test with feature "seccomp" on and off
    {{ cargo-cmd }} test --profile={{ if target == "debug" { "dev" } else { target } }}  {{ target-triple-flag }} -p hyperlight-host test_violate_seccomp_filters --lib {{ if features =="" {''} else { "--features " + features } }} -- --ignored
    {{ cargo-cmd }} test --profile={{ if target == "debug" { "dev" } else { target } }}  {{ target-triple-flag }} -p hyperlight-host test_violate_seccomp_filters --no-default-features {{ if features =~"mshv2" {"--features init-paging,mshv2"} else {"--features mshv3,init-paging,kvm" } }} --lib -- --ignored

# tests compilation with no default features on different platforms
test-compilation-no-default-features target=default-target:
    @# Linux should fail without a hypervisor feature (kvm, mshv, or mshv3)
    {{ if os() == "linux" { "! " + cargo-cmd + " check -p hyperlight-host --no-default-features "+target-triple-flag+" 2> /dev/null" } else { "" } }}
    @# Windows should succeed even without default features
    {{ if os() == "windows" { cargo-cmd + " check -p hyperlight-host --no-default-features" } else { "" } }}
    @# Linux should succeed with a hypervisor driver but without init-paging
    {{ if os() == "linux" { cargo-cmd + " check -p hyperlight-host --no-default-features --features kvm" } else { "" } }}  {{ target-triple-flag }}
    {{ if os() == "linux" { cargo-cmd + " check -p hyperlight-host --no-default-features --features mshv2" } else { "" } }}  {{ target-triple-flag }}
    {{ if os() == "linux" { cargo-cmd + " check -p hyperlight-host --no-default-features --features mshv3" } else { "" } }}  {{ target-triple-flag }}

# runs tests that exercise gdb debugging
test-rust-gdb-debugging target=default-target features="":
    {{ cargo-cmd }} test --profile={{ if target == "debug" { "dev" } else { target } }}  {{ target-triple-flag }} --example guest-debugging {{ if features =="" {'--features gdb'} else { "--features gdb," + features } }}
    {{ cargo-cmd }} test --profile={{ if target == "debug" { "dev" } else { target } }}  {{ target-triple-flag }} {{ if features =="" {'--features gdb'} else { "--features gdb," + features } }} -- test_gdb

# rust test for crashdump
test-rust-crashdump target=default-target features="":
    {{ cargo-cmd }} test --profile={{ if target == "debug" { "dev" } else { target } }}  {{ target-triple-flag }} {{ if features =="" {'--features crashdump'} else { "--features crashdump," + features } }} -- test_crashdump

# rust test for tracing
test-rust-tracing target=default-target features="":
    # Run tests for the tracing guest and macro
    {{ cargo-cmd }} test -p hyperlight-guest-tracing --profile={{ if target == "debug" { "dev" } else { target } }}  {{ target-triple-flag }}
    {{ cargo-cmd }} test -p hyperlight-guest-tracing-macro --profile={{ if target == "debug" { "dev" } else { target } }}  {{ target-triple-flag }}

    # Prepare the tracing guest for testing
    just build-rust-guests {{ target }} trace_guest
    just move-rust-guests {{ target }}
    # Run hello-world example with tracing enabled to get the trace output
    # note that trace-dump doesn't run on MUSL target as of now
    TRACE_OUTPUT="$({{ cargo-cmd }} run --profile={{ if target == "debug" { "dev" } else { target } }} {{ target-triple-flag }} --example hello-world --features {{ if features =="" {"trace_guest"} else { "trace_guest," + features } }})" && \
        TRACE_FILE="$(echo "$TRACE_OUTPUT" | grep -oE 'Creating trace file at: [^ ]+' | awk -F': ' '{print $2}')" && \
        echo "$TRACE_OUTPUT" && \
        if [ -z "$TRACE_FILE" ]; then \
            echo "Error: Could not extract trace file path from output." >&2 ; \
            exit 1 ; \
        fi && \
        cargo run -p trace_dump ./{{ simpleguest_source }}/{{ target }}/simpleguest "$TRACE_FILE" list_frames

    # Rebuild the tracing guests without the tracing feature
    # This is to ensure that the tracing feature does not affect the other tests
    just build-rust-guests {{ target }}
    just move-rust-guests {{ target }}

test-doc target=default-target features="":
    {{ cargo-cmd }} test --profile={{ if target == "debug" { "dev" } else { target } }} {{ target-triple-flag }} {{ if features =="" {''} else { "--features " + features } }} --doc

################
### LINTING ####
################

check:
    {{ cargo-cmd }} check  {{ target-triple-flag }}
    {{ cargo-cmd }} check -p hyperlight-host --features crashdump  {{ target-triple-flag }}
    {{ cargo-cmd }} check -p hyperlight-host --features print_debug  {{ target-triple-flag }}
    {{ cargo-cmd }} check -p hyperlight-host --features gdb  {{ target-triple-flag }}
    {{ cargo-cmd }} check -p hyperlight-host --features trace_guest,unwind_guest,mem_profile  {{ target-triple-flag }}

fmt-check:
    cargo +nightly fmt --all -- --check
    cargo +nightly fmt --manifest-path src/tests/rust_guests/simpleguest/Cargo.toml -- --check
    cargo +nightly fmt --manifest-path src/tests/rust_guests/dummyguest/Cargo.toml -- --check
    cargo +nightly fmt --manifest-path src/tests/rust_guests/witguest/Cargo.toml -- --check
    cargo +nightly fmt --manifest-path src/hyperlight_guest_capi/Cargo.toml -- --check

check-license-headers:
    ./dev/check-license-headers.sh

fmt-apply:
    cargo +nightly fmt --all
    cargo +nightly fmt --manifest-path src/tests/rust_guests/simpleguest/Cargo.toml
    cargo +nightly fmt --manifest-path src/tests/rust_guests/dummyguest/Cargo.toml
    cargo +nightly fmt --manifest-path src/tests/rust_guests/witguest/Cargo.toml
    cargo +nightly fmt --manifest-path src/hyperlight_guest_capi/Cargo.toml

clippy target=default-target: (witguest-wit)
    {{ cargo-cmd }} clippy --all-targets --all-features --profile={{ if target == "debug" { "dev" } else { target } }}  {{ target-triple-flag }} -- -D warnings

clippy-guests target=default-target: (witguest-wit)
    cd src/tests/rust_guests/simpleguest && cargo clippy --profile={{ if target == "debug" { "dev" } else { target } }} -- -D warnings
    cd src/tests/rust_guests/witguest && cargo clippy --profile={{ if target == "debug" { "dev" } else { target } }} -- -D warnings

clippy-apply-fix-unix:
    cargo clippy --fix --all 

clippy-apply-fix-windows:
    cargo clippy --target x86_64-pc-windows-msvc --fix --all 

# Run clippy with feature combinations for all packages
clippy-exhaustive target=default-target: (witguest-wit)
    ./hack/clippy-package-features.sh hyperlight-host {{ target }} {{ target-triple }}
    ./hack/clippy-package-features.sh hyperlight-guest {{ target }} 
    ./hack/clippy-package-features.sh hyperlight-guest-bin {{ target }}
    ./hack/clippy-package-features.sh hyperlight-common {{ target }} {{ target-triple }}
    ./hack/clippy-package-features.sh hyperlight-testing {{ target }} {{ target-triple }}
    ./hack/clippy-package-features.sh hyperlight-component-macro  {{ target }} {{ target-triple }}
    ./hack/clippy-package-features.sh hyperlight-component-util {{ target }} {{ target-triple }}
    ./hack/clippy-package-features.sh hyperlight-guest-tracing-macro {{ target }}
    ./hack/clippy-package-features.sh hyperlight-guest-tracing {{ target }}
    just clippy-guests {{ target }}

# Test a specific package with all feature combinations
clippy-package package target=default-target: (witguest-wit)
    ./hack/clippy-package-features.sh {{ package }} {{ target }}

# Verify Minimum Supported Rust Version
verify-msrv:
    ./dev/verify-msrv.sh hyperlight-common hyperlight-guest hyperlight-guest-bin hyperlight-host hyperlight-component-util hyperlight-component-macro hyperlight-guest-tracing-macro hyperlight-guest-tracing

#####################
### RUST EXAMPLES ###
#####################

run-rust-examples target=default-target features="":
    {{ cargo-cmd }} run --profile={{ if target == "debug" { "dev" } else { target } }}  {{ target-triple-flag }} --example metrics {{ if features =="" {''} else { "--features " + features } }}
    {{ cargo-cmd }} run --profile={{ if target == "debug" { "dev" } else { target } }}  {{ target-triple-flag }} --example metrics {{ if features =="" {"--features function_call_metrics"} else {"--features function_call_metrics," + features} }}
    {{ cargo-cmd }} run --profile={{ if target == "debug" { "dev" } else { target } }}  {{ target-triple-flag }} --example logging {{ if features =="" {''} else { "--features " + features } }}

# The two tracing examples are flaky on windows so we run them on linux only for now, need to figure out why as they run fine locally on windows
run-rust-examples-linux target=default-target features="": (run-rust-examples target features)
    {{ cargo-cmd }} run --profile={{ if target == "debug" { "dev" } else { target } }}   {{ target-triple-flag }} --example tracing {{ if features =="" {''} else { "--features " + features } }}
    {{ cargo-cmd }} run --profile={{ if target == "debug" { "dev" } else { target } }}   {{ target-triple-flag }}  --example tracing {{ if features =="" {"--features function_call_metrics" } else {"--features function_call_metrics," + features} }}


#########################
### ARTIFACT CREATION ###
#########################

tar-headers: (build-rust-capi) # build-rust-capi is a dependency because we need the hyperlight_guest.h to be built
    tar -zcvf include.tar.gz -C {{root}}/src/hyperlight_guest_bin/third_party/ musl/include musl/arch/x86_64 printf/printf.h -C {{root}}/src/hyperlight_guest_capi include

tar-static-lib: (build-rust-capi "release") (build-rust-capi "debug")
    tar -zcvf hyperlight-guest-c-api-linux.tar.gz -C {{root}}/target/x86_64-unknown-none/ release/libhyperlight_guest_capi.a -C {{root}}/target/x86_64-unknown-none/ debug/libhyperlight_guest_capi.a

# Create release notes for the given tag. The expected format is a v-prefixed version number, e.g. v0.2.0
# For prereleases, the version should be "dev-latest"
@create-release-notes tag:
    echo "## What's Changed"
    ./dev/extract-changelog.sh {{ if tag == "dev-latest" { "Prerelease" } else { tag } }}
    gh api repos/{owner}/{repo}/releases/generate-notes -f tag_name={{ tag }} | jq -r '.body' | sed '1,/## What'"'"'s Changed/d'

####################
### BENCHMARKING ###
####################

# Warning: can overwrite previous local benchmarks, so run this before running benchmarks
# Downloads the benchmarks result from the given release tag.
# If tag is not given, defaults to latest release
# Options for os: "Windows", or "Linux"
# Options for Linux hypervisor: "kvm", "mshv", "mshv3"
# Options for Windows hypervisor: "hyperv"
# Options for cpu: "amd", "intel"
bench-download os hypervisor cpu tag="":
    gh release download {{ tag }} -D ./target/ -p benchmarks_{{ os }}_{{ hypervisor }}_{{ cpu }}.tar.gz
    mkdir -p target/criterion {{ if os() == "windows" { "-Force" } else { "" } }}
    tar -zxvf target/benchmarks_{{ os }}_{{ hypervisor }}_{{ cpu }}.tar.gz -C target/criterion/ --strip-components=1

# Warning: compares to and then OVERWRITES the given baseline
bench-ci baseline features="":
    @# Benchmarks are always run with release builds for meaningful results
    cargo bench --profile=release {{ if features =="" {''} else { "--features " + features } }} -- --verbose --save-baseline {{ baseline }}

bench features="":
    @# Benchmarks are always run with release builds for meaningful results
    cargo bench --profile=release {{ if features =="" {''} else { "--features " + features } }} -- --verbose

###############
### FUZZING ###
###############

# Enough memory (4GB) for the fuzzer to run for 5 hours, with address sanitizer turned on
fuzz_memory_limit := "4096"

# Fuzzes the given target
fuzz fuzz-target:
    cargo +nightly fuzz run {{ fuzz-target }} --release -- -rss_limit_mb={{ fuzz_memory_limit }}

# Fuzzes the given target. Stops after `max_time` seconds
fuzz-timed fuzz-target max_time:
    cargo +nightly fuzz run {{ fuzz-target }} --release -- -rss_limit_mb={{ fuzz_memory_limit }} -max_total_time={{ max_time }}

# Builds fuzzers for submission to external fuzzing services
build-fuzzers: (build-fuzzer "fuzz_guest_call") (build-fuzzer "fuzz_host_call") (build-fuzzer "fuzz_host_print")

# Builds the given fuzzer
build-fuzzer fuzz-target:
    cargo +nightly fuzz build {{ fuzz-target }}


###################
### FLATBUFFERS ###
###################

gen-all-fbs-rust-code:
    for fbs in `find src -name "*.fbs"`; do flatc -r --rust-module-root-file --gen-all -o ./src/hyperlight_common/src/flatbuffers/ $fbs; done
    just fmt-apply

install-vcpkg:
    cd .. && git clone https://github.com/Microsoft/vcpkg.git || cd -
    cd ../vcpkg && ./bootstrap-vcpkg{{ bin-suffix }} && ./vcpkg integrate install || cd -

install-flatbuffers-with-vcpkg: install-vcpkg
    cd ../vcpkg && ./vcpkg install flatbuffers || cd -
