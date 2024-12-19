import 'c.just'
alias build-rust-debug := build-rust

set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]
set dotenv-load := true

set-trace-env-vars := if os() == "windows" { "$env:RUST_LOG='none,hyperlight-host=info';" } else { "RUST_LOG=none,hyperlight-host=info" }
set-env-command := if os() == "windows" { "$env:" } else { "export " }
bin-suffix := if os() == "windows" { ".bat" } else { ".sh" }

root := justfile_directory()

default-target := "debug"
simpleguest_source := "src/tests/rust_guests/simpleguest/target/x86_64-unknown-none"
simpleguest_msvc_source := "src/tests/rust_guests/simpleguest/target/x86_64-pc-windows-msvc"
dummyguest_source := "src/tests/rust_guests/dummyguest/target/x86_64-unknown-none"
callbackguest_source := "src/tests/rust_guests/callbackguest/target/x86_64-unknown-none"
callbackguest_msvc_source := "src/tests/rust_guests/callbackguest/target/x86_64-pc-windows-msvc"
rust_guests_bin_dir := "src/tests/rust_guests/bin"

install-vcpkg:
    cd .. && git clone https://github.com/Microsoft/vcpkg.git || cd -
    cd ../vcpkg && ./bootstrap-vcpkg{{ bin-suffix }} && ./vcpkg integrate install || cd -

install-flatbuffers-with-vcpkg: install-vcpkg
    cd ../vcpkg && ./vcpkg install flatbuffers || cd -

tar-headers: (build-rust-capi) # build-rust-capi is a dependency because we need the hyperlight_guest.h to be built
    tar -zcvf include.tar.gz -C {{root}}/src/hyperlight_guest/third_party/ musl/include musl/arch/x86_64 printf/printf.h -C {{root}}/src/hyperlight_guest_capi include

tar-static-lib: (build-rust-capi "release") (build-rust-capi "debug")
    tar -zcvf hyperlight-guest-c-api-windows.tar.gz -C {{root}}/target/x86_64-pc-windows-msvc/ release/hyperlight_guest_capi.lib -C {{root}}/target/x86_64-pc-windows-msvc/ debug/hyperlight_guest_capi.lib
    tar -zcvf hyperlight-guest-c-api-linux.tar.gz -C {{root}}/target/x86_64-unknown-none/ release/libhyperlight_guest_capi.a -C {{root}}/target/x86_64-unknown-none/ debug/libhyperlight_guest_capi.a


# BUILDING
build-rust-guests target=default-target:
    cd src/tests/rust_guests/callbackguest && cargo build --profile={{ if target == "debug" { "dev" } else { target } }}
    cd src/tests/rust_guests/callbackguest && cargo build --profile={{ if target == "debug" { "dev" } else { target } }}  --target=x86_64-pc-windows-msvc
    cd src/tests/rust_guests/simpleguest && cargo build --profile={{ if target == "debug" { "dev" } else { target } }} 
    cd src/tests/rust_guests/simpleguest && cargo build --profile={{ if target == "debug" { "dev" } else { target } }} --target=x86_64-pc-windows-msvc
    cd src/tests/rust_guests/dummyguest && cargo build --profile={{ if target == "debug" { "dev" } else { target } }} 

@move-rust-guests target=default-target:
    cp {{ callbackguest_source }}/{{ target }}/callbackguest* {{ rust_guests_bin_dir }}/{{ target }}/
    cp {{ callbackguest_msvc_source }}/{{ target }}/callbackguest* {{ rust_guests_bin_dir }}/{{ target }}/
    cp {{ simpleguest_source }}/{{ target }}/simpleguest* {{ rust_guests_bin_dir }}/{{ target }}/
    cp {{ simpleguest_msvc_source }}/{{ target }}/simpleguest* {{ rust_guests_bin_dir }}/{{ target }}/
    cp {{ dummyguest_source }}/{{ target }}/dummyguest* {{ rust_guests_bin_dir }}/{{ target }}/

build-and-move-rust-guests: (build-rust-guests "debug") (move-rust-guests "debug") (build-rust-guests "release") (move-rust-guests "release")
build-and-move-c-guests: (build-c-guests "debug") (move-c-guests "debug") (build-c-guests "release") (move-c-guests "release")

# short aliases rg "rust guests", cg "c guests" for less typing
rg: build-and-move-rust-guests
cg: build-and-move-c-guests
guests: rg cg


build-rust target=default-target:
    cargo build --profile={{ if target == "debug" { "dev" } else { target } }}

build: build-rust

# CLEANING
clean: clean-rust

clean-rust: 
    cargo clean
    cd src/tests/rust_guests/simpleguest && cargo clean
    cd src/tests/rust_guests/dummyguest && cargo clean
    cd src/tests/rust_guests/callbackguest && cargo clean
    git clean -fdx src/tests/c_guests/bin src/tests/rust_guests/bin

# TESTING
# Some tests cannot run with other tests, they are marked as ignored so that cargo test works
# there may be tests that we really want to ignore so we cant just use --ignored and we have to
# Specify the test name of the ignored tests that we want to run
test-rust target=default-target features="": (test-rust-int "rust" target features) (test-rust-int "c" target features) (test-seccomp target)
    # unit tests
    cargo test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }}  --lib
    
    # ignored tests - these tests need to run serially or with specific properties
    cargo test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} test_trace -p hyperlight-host --lib  -- --ignored
    cargo test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} test_drop  -p hyperlight-host --lib -- --ignored
    cargo test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} hypervisor::metrics::tests::test_gather_metrics -p hyperlight-host --lib -- --ignored
    cargo test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} sandbox::metrics::tests::test_gather_metrics -p hyperlight-host --lib -- --ignored
    cargo test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} test_metrics -p hyperlight-host --lib -- --ignored
    cargo test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} --test integration_test log_message -- --ignored
    cargo test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} sandbox::uninitialized::tests::test_log_trace -p hyperlight-host --lib -- --ignored
    cargo test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} hypervisor::hypervisor_handler::tests::create_1000_sandboxes -p hyperlight-host --lib -- --ignored
    {{ set-trace-env-vars }} cargo test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} --lib sandbox::outb::tests::test_log_outb_log -- --ignored

test-seccomp target=default-target:
    # run seccomp test with feature "seccomp" on and off
    cargo test --profile={{ if target == "debug" { "dev" } else { target } }} -p hyperlight-host test_violate_seccomp_filters --lib -- --ignored
    cargo test --profile={{ if target == "debug" { "dev" } else { target } }} -p hyperlight-host test_violate_seccomp_filters --no-default-features --features mshv2,kvm --lib -- --ignored

# rust integration tests. guest can either be "rust" or "c"
test-rust-int guest target=default-target features="":
    # integration tests

    # run execute_on_heap test with feature "executable_heap" on and off
    {{if os() == "windows" { "$env:" } else { "" } }}GUEST="{{guest}}"{{if os() == "windows" { ";" } else { "" } }} cargo test --profile={{ if target == "debug" { "dev" } else { target } }} --test integration_test execute_on_heap --features executable_heap -- --ignored
    {{if os() == "windows" { "$env:" } else { "" } }}GUEST="{{guest}}"{{if os() == "windows" { ";" } else { "" } }} cargo test --profile={{ if target == "debug" { "dev" } else { target } }} --test integration_test execute_on_heap -- --ignored
    # run the rest of the integration tests
    {{if os() == "windows" { "$env:" } else { "" } }}GUEST="{{guest}}"{{if os() == "windows" { ";" } else { "" } }} cargo test -p hyperlight-host {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} --test '*'

test-rust-feature-compilation-fail target=default-target:
    @# the following should fail on linux because either kvm or msh feature must be specified, which is why the exit code is inverted with an !.
    {{ if os() == "linux" { "! cargo check -p hyperlight-host --no-default-features 2> /dev/null"} else { "" } }}

test target=default-target: (test-rust target)

# RUST LINTING
check:
    cargo check

fmt-check:
    cargo +nightly fmt --all -- --check
    cargo +nightly fmt --manifest-path src/tests/rust_guests/callbackguest/Cargo.toml -- --check
    cargo +nightly fmt --manifest-path src/tests/rust_guests/simpleguest/Cargo.toml -- --check
    cargo +nightly fmt --manifest-path src/tests/rust_guests/dummyguest/Cargo.toml -- --check
    cargo +nightly fmt --manifest-path src/hyperlight_guest_capi/Cargo.toml -- --check

fmt-apply:
    cargo +nightly fmt --all
    cargo +nightly fmt --manifest-path src/tests/rust_guests/callbackguest/Cargo.toml
    cargo +nightly fmt --manifest-path src/tests/rust_guests/simpleguest/Cargo.toml
    cargo +nightly fmt --manifest-path src/tests/rust_guests/dummyguest/Cargo.toml
    cargo +nightly fmt --manifest-path src/hyperlight_guest_capi/Cargo.toml

clippy target=default-target:
    cargo clippy --all-targets --all-features --profile={{ if target == "debug" { "dev" } else { target } }} -- -D warnings

clippy-apply-fix-unix:
    cargo clippy --fix --all 

clippy-apply-fix-windows:
    cargo clippy --target x86_64-pc-windows-msvc --fix --all 

# Verify Minimum Supported Rust Version
verify-msrv:
    ./dev/verify-msrv.sh hyperlight-host hyperlight-guest hyperlight-common

# GEN FLATBUFFERS
gen-all-fbs-rust-code:
    for fbs in `find src -name "*.fbs"`; do flatc -r --rust-module-root-file --gen-all -o ./src/hyperlight_common/src/flatbuffers/ $fbs; done
    just fmt-apply

# RUST EXAMPLES
run-rust-examples target=default-target: (build-rust target)
    cargo run --profile={{ if target == "debug" { "dev" } else { target } }} --example metrics
    cargo run --profile={{ if target == "debug" { "dev" } else { target } }} --example metrics --features "function_call_metrics"
    {{ set-trace-env-vars }} cargo run --profile={{ if target == "debug" { "dev" } else { target } }} --example logging

# The two tracing examples are flaky on windows so we run them on linux only for now, need to figure out why as they run fine locally on windows
run-rust-examples-linux target=default-target: (build-rust target) (run-rust-examples target)
    {{ set-trace-env-vars }} cargo run --profile={{ if target == "debug" { "dev" } else { target } }} --example tracing
    {{ set-trace-env-vars }} cargo run --profile={{ if target == "debug" { "dev" } else { target } }} --example tracing --features "function_call_metrics"

# BENCHMARKING

# Warning: can overwrite previous local benchmarks, so run this before running benchmarks
# Downloads the benchmarks result from the given release tag.
# If tag is not given, defaults to latest release
# Options for os: "Windows", or "Linux"
# Options for Linux hypervisor: "kvm", "mshv"
# Options for Windows hypervisor: "hyperv"
# Options for cpu: "amd", "intel"
bench-download os hypervisor cpu tag="":
    gh release download {{ tag }} -D ./target/ -p benchmarks_{{ os }}_{{ hypervisor }}_{{ cpu }}.tar.gz
    mkdir -p target/criterion {{ if os() == "windows" { "-Force" } else { "" } }}
    tar -zxvf target/benchmarks_{{ os }}_{{ hypervisor }}_{{ cpu }}.tar.gz -C target/criterion/ --strip-components=1

# Warning: compares to and then OVERWRITES the given baseline
bench-ci baseline target=default-target:
    cargo bench --profile={{ if target == "debug" { "dev" } else { target } }} -- --verbose --save-baseline {{ baseline }}

bench target=default-target:
    cargo bench --profile={{ if target == "debug" { "dev" } else { target } }} -- --verbose

# FUZZING
fuzz:
    cd src/hyperlight_host && cargo +nightly fuzz run fuzz_target_1

fuzz-timed:
    cd src/hyperlight_host && cargo +nightly fuzz run fuzz_target_1 -- -max_total_time=300
