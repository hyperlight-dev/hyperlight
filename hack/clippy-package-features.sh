#!/usr/bin/env bash

set -euo pipefail

# Check for required arguments
if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <package> <target>" >&2
    echo "Example: $0 hyperlight-host debug" >&2
    exit 1
fi

PACKAGE="$1"
TARGET="$2"

# Convert target for cargo profile
PROFILE=$([ "$TARGET" = "debug" ] && echo "dev" || echo "$TARGET")

# Required features for compilation (only for hyperlight-host)
if [[ "$PACKAGE" == "hyperlight-host" ]]; then
    REQUIRED_FEATURES="kvm,mshv3"
    # Get all features for the package (excluding default and required features)
    features=$(cargo metadata --format-version 1 --no-deps | jq -r ".packages[] | select(.name == \"$PACKAGE\") | .features | keys[]" | grep -v -E "^(default|kvm|mshv3)$" || true)
elif [[ "$PACKAGE" == "hyperlight-guest-bin" ]]; then
    REQUIRED_FEATURES="printf"
    # Get all features for the package (excluding default and required features)
    features=$(cargo metadata --format-version 1 --no-deps | jq -r ".packages[] | select(.name == \"$PACKAGE\") | .features | keys[]" | grep -v -E "^(default|printf)$" || true)
else 
    REQUIRED_FEATURES=""
    # Get all features for the package (excluding default)
    features=$(cargo metadata --format-version 1 --no-deps | jq -r ".packages[] | select(.name == \"$PACKAGE\") | .features | keys[]" | grep -v "^default$" || true)
fi

# Test with minimal features
if [[ -n "$REQUIRED_FEATURES" ]]; then
    echo "Testing $PACKAGE with required features only ($REQUIRED_FEATURES)..."
    (set -x; cargo clippy -p "$PACKAGE" --all-targets --no-default-features --features "$REQUIRED_FEATURES" --profile="$PROFILE" -- -D warnings)
else
    echo "Testing $PACKAGE with no features..."
    (set -x; cargo clippy -p "$PACKAGE" --all-targets --no-default-features --profile="$PROFILE" -- -D warnings)
fi

echo "Testing $PACKAGE with default features..."
(set -x; cargo clippy -p "$PACKAGE" --all-targets --profile="$PROFILE" -- -D warnings)

# Test each additional feature individually
for feature in $features; do
    if [[ -n "$REQUIRED_FEATURES" ]]; then
        echo "Testing $PACKAGE with feature: $REQUIRED_FEATURES,$feature"
        (set -x; cargo clippy -p "$PACKAGE" --all-targets --no-default-features --features "$REQUIRED_FEATURES,$feature" --profile="$PROFILE" -- -D warnings)
    else
        echo "Testing $PACKAGE with feature: $feature"
        (set -x; cargo clippy -p "$PACKAGE" --all-targets --no-default-features --features "$feature" --profile="$PROFILE" -- -D warnings)
    fi
done

# Test all features together
if [[ -n "$features" ]]; then
    all_features=$(echo $features | tr '\n' ',' | sed 's/,$//')
    if [[ -n "$REQUIRED_FEATURES" ]]; then
        echo "Testing $PACKAGE with all features: $REQUIRED_FEATURES,$all_features"
        (set -x; cargo clippy -p "$PACKAGE" --all-targets --no-default-features --features "$REQUIRED_FEATURES,$all_features" --profile="$PROFILE" -- -D warnings)
    else
        echo "Testing $PACKAGE with all features: $all_features"
        (set -x; cargo clippy -p "$PACKAGE" --all-targets --no-default-features --features "$all_features" --profile="$PROFILE" -- -D warnings)
    fi
fi