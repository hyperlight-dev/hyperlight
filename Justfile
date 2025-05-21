import 'c.just'

set windows-shell := ["pwsh.exe", "-NoLogo", "-Command"]
set dotenv-load := true

set-env-command := if os() == "windows" { "$env:" } else { "export " }
bin-suffix := if os() == "windows" { ".bat" } else { ".sh" }

root := justfile_directory()

default-target := "debug"
simpleguest_source := "src/tests/rust_guests/simpleguest/target/x86_64-unknown-none"
dummyguest_source := "src/tests/rust_guests/dummyguest/target/x86_64-unknown-none"
callbackguest_source := "src/tests/rust_guests/callbackguest/target/x86_64-unknown-none"
rust_guests_bin_dir := "src/tests/rust_guests/bin"

################
### BUILDING ###
################
alias b := build
alias rg := build-and-move-rust-guests
alias cg := build-and-move-c-guests

# build host library
build target=default-target:
    cargo build --profile={{ if target == "debug" { "dev" } else { target } }}

# build testing guest binaries
guests: build-and-move-rust-guests build-and-move-c-guests

build-rust-guests target=default-target:
    cd src/tests/rust_guests/callbackguest && cargo build --profile={{ if target == "debug" { "dev" } else { target } }}
    cd src/tests/rust_guests/simpleguest && cargo build --profile={{ if target == "debug" { "dev" } else { target } }} 
    cd src/tests/rust_guests/dummyguest && cargo build --profile={{ if target == "debug" { "dev" } else { target } }} 

@move-rust-guests target=default-target:
    cp {{ callbackguest_source }}/{{ target }}/callbackguest* {{ rust_guests_bin_dir }}/{{ target }}/
    cp {{ simpleguest_source }}/{{ target }}/simpleguest* {{ rust_guests_bin_dir }}/{{ target }}/
    cp {{ dummyguest_source }}/{{ target }}/dummyguest* {{ rust_guests_bin_dir }}/{{ target }}/

build-and-move-rust-guests: (build-rust-guests "debug") (move-rust-guests "debug") (build-rust-guests "release") (move-rust-guests "release")
build-and-move-c-guests: (build-c-guests "debug") (move-c-guests "debug") (build-c-guests "release") (move-c-guests "release")

clean: clean-rust

clean-rust: 
    cargo clean
    cd src/tests/rust_guests/simpleguest && cargo clean
    cd src/tests/rust_guests/dummyguest && cargo clean
    cd src/tests/rust_guests/callbackguest && cargo clean
    git clean -fdx src/tests/c_guests/bin src/tests/rust_guests/bin

################
### TESTING ####
################

# Note: most testing recipes take an optional "features" comma separated list argument. If provided, these will be passed to cargo as **THE ONLY FEATURES**, i.e. default features will be disabled.

# convenience recipe to run all tests with the given target and features (similar to CI)
test-like-ci config=default-target hypervisor="kvm":
    @# with default features
    just test {{config}} {{ if hypervisor == "mshv3" {"mshv3"} else {""} }}

    @# with only one driver enabled + seccomp
    just test {{config}} seccomp,build-metadata,{{ if hypervisor == "mshv" {"mshv2"} else if hypervisor == "mshv3" {"mshv3"} else {"kvm"} }}

    @# make sure certain cargo features compile
    cargo check -p hyperlight-host --features crashdump
    cargo check -p hyperlight-host --features print_debug
    cargo check -p hyperlight-host --features gdb

    @# without any driver (should fail to compile)
    just test-compilation-fail {{config}}

# runs all tests
test target=default-target features="": (test-unit target features) (test-isolated target features) (test-integration "rust" target features) (test-integration "c" target features) (test-seccomp target features)

# runs unit tests
test-unit target=default-target features="":
    cargo test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} --lib

# runs tests that requires being run separately, for example due to global state
test-isolated target=default-target features="":
    cargo test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} -p hyperlight-host --lib -- sandbox::uninitialized::tests::test_trace_trace --exact --ignored
    cargo test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} -p hyperlight-host --lib -- sandbox::uninitialized::tests::test_log_trace --exact --ignored
    cargo test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} -p hyperlight-host --lib -- hypervisor::hypervisor_handler::tests::create_1000_sandboxes --exact --ignored
    cargo test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} -p hyperlight-host --lib -- sandbox::outb::tests::test_log_outb_log --exact --ignored
    cargo test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} -p hyperlight-host --lib -- mem::shared_mem::tests::test_drop --exact --ignored
    cargo test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} -p hyperlight-host --test integration_test -- log_message --exact --ignored
    @# metrics tests
    cargo test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} -p hyperlight-host --lib -- metrics::tests::test_metrics_are_emitted --exact --ignored
    cargo test {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F function_call_metrics," + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} -p hyperlight-host --lib -- metrics::tests::test_metrics_are_emitted --exact --ignored
    
# runs integration tests. Guest can either be "rust" or "c"
test-integration guest target=default-target features="":
    @# run execute_on_heap test with feature "executable_heap" on and off
    {{if os() == "windows" { "$env:" } else { "" } }}GUEST="{{guest}}"{{if os() == "windows" { ";" } else { "" } }} cargo test --profile={{ if target == "debug" { "dev" } else { target } }} --test integration_test execute_on_heap {{ if features =="" {" --features executable_heap"} else {"--features executable_heap," + features} }} -- --ignored
    {{if os() == "windows" { "$env:" } else { "" } }}GUEST="{{guest}}"{{if os() == "windows" { ";" } else { "" } }} cargo test --profile={{ if target == "debug" { "dev" } else { target } }} --test integration_test execute_on_heap {{ if features =="" {""} else {"--features " + features} }} -- --ignored
    
    @# run the rest of the integration tests
    {{if os() == "windows" { "$env:" } else { "" } }}GUEST="{{guest}}"{{if os() == "windows" { ";" } else { "" } }} cargo test -p hyperlight-host {{ if features =="" {''} else if features=="no-default-features" {"--no-default-features" } else {"--no-default-features -F " + features } }} --profile={{ if target == "debug" { "dev" } else { target } }} --test '*'

# runs seccomp tests
test-seccomp target=default-target features="":
    @# run seccomp test with feature "seccomp" on and off
    cargo test --profile={{ if target == "debug" { "dev" } else { target } }} -p hyperlight-host test_violate_seccomp_filters --lib {{ if features =="" {''} else { "--features " + features } }} -- --ignored
    cargo test --profile={{ if target == "debug" { "dev" } else { target } }} -p hyperlight-host test_violate_seccomp_filters --no-default-features {{ if features =~"mshv3" {"--features mshv3"} else {"--features mshv2,kvm" } }} --lib -- --ignored

# runs tests that ensure compilation fails when it should
test-compilation-fail target=default-target:
    @# the following should fail on linux because one of kvm, mshv, or mshv3 feature must be specified, which is why the exit code is inverted with an !.
    {{ if os() == "linux" { "! cargo check -p hyperlight-host --no-default-features 2> /dev/null"} else { "" } }}

# runs tests that exercise gdb debugging
test-rust-gdb-debugging target=default-target features="":
    cargo test --profile={{ if target == "debug" { "dev" } else { target } }} --example guest-debugging {{ if features =="" {'--features gdb'} else { "--features gdb," + features } }}
    cargo test --profile={{ if target == "debug" { "dev" } else { target } }} {{ if features =="" {'--features gdb'} else { "--features gdb," + features } }} -- test_gdb


################
### LINTING ####
################

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

clippy-guests target=default-target:
    cd src/tests/rust_guests/simpleguest && cargo clippy --profile={{ if target == "debug" { "dev" } else { target } }} -- -D warnings
    cd src/tests/rust_guests/callbackguest && cargo clippy --profile={{ if target == "debug" { "dev" } else { target } }} -- -D warnings

clippy-apply-fix-unix:
    cargo clippy --fix --all 

clippy-apply-fix-windows:
    cargo clippy --target x86_64-pc-windows-msvc --fix --all 

# Verify Minimum Supported Rust Version
verify-msrv:
    ./dev/verify-msrv.sh hyperlight-host hyperlight-guest hyperlight-common

#####################
### RUST EXAMPLES ###
#####################

run-rust-examples target=default-target features="":
    cargo run --profile={{ if target == "debug" { "dev" } else { target } }} --example metrics {{ if features =="" {''} else { "--features " + features } }}
    cargo run --profile={{ if target == "debug" { "dev" } else { target } }} --example metrics {{ if features =="" {"--features function_call_metrics"} else {"--features function_call_metrics," + features} }}
    cargo run --profile={{ if target == "debug" { "dev" } else { target } }} --example logging {{ if features =="" {''} else { "--features " + features } }}

# The two tracing examples are flaky on windows so we run them on linux only for now, need to figure out why as they run fine locally on windows
run-rust-examples-linux target=default-target features="": (run-rust-examples target features)
    cargo run --profile={{ if target == "debug" { "dev" } else { target } }} --example tracing {{ if features =="" {''} else { "--features " + features } }}
    cargo run --profile={{ if target == "debug" { "dev" } else { target } }} --example tracing {{ if features =="" {"--features function_call_metrics" } else {"--features function_call_metrics," + features} }}


#########################
### ARTIFACT CREATION ###
#########################

tar-headers: (build-rust-capi) # build-rust-capi is a dependency because we need the hyperlight_guest.h to be built
    tar -zcvf include.tar.gz -C {{root}}/src/hyperlight_guest/third_party/ musl/include musl/arch/x86_64 printf/printf.h -C {{root}}/src/hyperlight_guest_capi include

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
# Options for Linux hypervisor: "kvm", "mshv"
# Options for Windows hypervisor: "hyperv"
# Options for cpu: "amd", "intel"
bench-download os hypervisor cpu tag="":
    gh release download {{ tag }} -D ./target/ -p benchmarks_{{ os }}_{{ hypervisor }}_{{ cpu }}.tar.gz
    mkdir -p target/criterion {{ if os() == "windows" { "-Force" } else { "" } }}
    tar -zxvf target/benchmarks_{{ os }}_{{ hypervisor }}_{{ cpu }}.tar.gz -C target/criterion/ --strip-components=1

# Warning: compares to and then OVERWRITES the given baseline
bench-ci baseline target=default-target features="":
    cargo bench --profile={{ if target == "debug" { "dev" } else { target } }} {{ if features =="" {''} else { "--features " + features } }} -- --verbose --save-baseline {{ baseline }}

bench target=default-target features="":
    cargo bench --profile={{ if target == "debug" { "dev" } else { target } }} {{ if features =="" {''} else { "--features " + features } }} -- --verbose

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
