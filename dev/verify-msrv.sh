#!/bin/bash
set -Eeuo pipefail
cargo install -q jaq
for CRATE in "$@"; do
    VERSION=$(cargo metadata --format-version=1 2>/dev/null | jaq --raw-output '.packages[] | select(.name == "'$CRATE'").rust_version')
    if ! rustup toolchain list | grep -q "$VERSION"; then
        rustup --quiet toolchain install "$VERSION" --no-self-update --profile minimal
    fi
    if [[ "$CRATE" == "hyperlight-guest"  || "$CRATE" == "hyperlight-guest-bin" ]]; then
        TARGET="x86_64-unknown-none"
        rustup target add "$TARGET" --toolchain "$VERSION" >/dev/null
        if cargo +"$VERSION" check --quiet -p "$CRATE" --target "$TARGET"; then
            echo -e " \u001b[1;32m✓\u001b[0m Crate \u001b[1m$CRATE\u001b[0m builds with rust \u001b[1m$VERSION\u001b[0m and target \u001b[1m$TARGET\u001b[0m"
        else
            echo -e " \u001b[1;31m✗\u001b[0m Crate \u001b[1m$CRATE\u001b[0m fails with rust \u001b[1m$VERSION\u001b[0m and target \u001b[1m$TARGET\u001b[0m"
            exit 1
        fi
    else
        if cargo +"$VERSION" check --quiet -p "$CRATE"; then
            echo -e " \u001b[1;32m✓\u001b[0m Crate \u001b[1m$CRATE\u001b[0m builds with rust \u001b[1m$VERSION\u001b[0m"
        else
            echo -e " \u001b[1;31m✗\u001b[0m Crate \u001b[1m$CRATE\u001b[0m fails with rust \u001b[1m$VERSION\u001b[0m"
            exit 1
        fi
    fi
done
