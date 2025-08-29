#!/usr/bin/env bash

set -euo pipefail

# Check for required arguments
if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <package> <target> [target_triple]" >&2
    echo "Example: $0 hyperlight-host debug x86_64-unknown-linux-musl" >&2
    exit 1
fi

PACKAGE="$1"
TARGET="$2"
TARGET_TRIPLE="${3:-}"

CARGO="cargo"

# Cargo target argument to append to cargo calls (empty if not provided)
TRIPLE_ARG=""
if [[ -n "${TARGET_TRIPLE}" ]]; then
    TRIPLE_ARG="--target ${TARGET_TRIPLE} --target-dir ./target/host"
    CARGO="cross"
fi

# Convert target for cargo profile
PROFILE=$([ "$TARGET" = "debug" ] && echo "dev" || echo "$TARGET")

# Required features needed so the rust packages can compile
if [[ "$PACKAGE" == "hyperlight-host" ]]; then
    REQUIRED_FEATURES=("kvm" "mshv3")
elif [[ "$PACKAGE" == "hyperlight-guest-bin" ]]; then
    REQUIRED_FEATURES=("printf")
else 
    REQUIRED_FEATURES=()
fi

# Get all features for the package (excluding default and required features)
# Always exclude "default", and exclude any required features using jq
features=$(cargo metadata --format-version 1 --no-deps | jq -r --arg pkg "$PACKAGE" '.packages[] | select(.name == $pkg) | .features | keys[] | select(. != "default" and (IN($ARGS.positional[])|not))' --args "${REQUIRED_FEATURES[@]}" || true)

# Convert required features array to comma-separated string for cargo
if [[ ${#REQUIRED_FEATURES[@]} -gt 0 ]]; then
    required_features_str=$(IFS=,; echo "${REQUIRED_FEATURES[*]}")
else
    required_features_str=""
fi

# Test with minimal features
if [[ ${#REQUIRED_FEATURES[@]} -gt 0 ]]; then
    echo "Testing $PACKAGE with required features only ($required_features_str)..."
    (set -x; "$CARGO" clippy -p "$PACKAGE" --all-targets --no-default-features --features "$required_features_str" --profile="$PROFILE" ${TRIPLE_ARG} -- -D warnings)
else
    echo "Testing $PACKAGE with no features..."
    (set -x; "$CARGO" clippy -p "$PACKAGE" --all-targets --no-default-features --profile="$PROFILE" ${TRIPLE_ARG} -- -D warnings)
fi

echo "Testing $PACKAGE with default features..."
(set -x; "$CARGO" clippy -p "$PACKAGE" --all-targets --profile="$PROFILE" ${TRIPLE_ARG} -- -D warnings)

# Test each additional feature individually
for feature in $features; do
    if [[ ${#REQUIRED_FEATURES[@]} -gt 0 ]]; then
        echo "Testing $PACKAGE with feature: $required_features_str,$feature"
        (set -x; "$CARGO" clippy -p "$PACKAGE" --all-targets --no-default-features --features "$required_features_str,$feature" --profile="$PROFILE" ${TRIPLE_ARG} -- -D warnings)
    else
        echo "Testing $PACKAGE with feature: $feature"
        (set -x; "$CARGO" clippy -p "$PACKAGE" --all-targets --no-default-features --features "$feature" --profile="$PROFILE" ${TRIPLE_ARG} -- -D warnings)
    fi
done

# Test all features together
if [[ -n "$features" ]]; then
    all_features=$(echo $features | tr '\n' ',' | sed 's/,$//')
    if [[ ${#REQUIRED_FEATURES[@]} -gt 0 ]]; then
        echo "Testing $PACKAGE with all features: $required_features_str,$all_features"
        (set -x; "$CARGO" clippy -p "$PACKAGE" --all-targets --no-default-features --features "$required_features_str,$all_features" --profile="$PROFILE" ${TRIPLE_ARG} -- -D warnings)
    else
        echo "Testing $PACKAGE with all features: $all_features"
        (set -x; "$CARGO" clippy -p "$PACKAGE" --all-targets --no-default-features --features "$all_features" --profile="$PROFILE" ${TRIPLE_ARG} -- -D warnings)
    fi
fi