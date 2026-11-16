#!/bin/bash
set -Eeuo pipefail
cargo install -q --locked --version 3.1.1 jaq

EXPECTED="$1"
EXPECTED="${EXPECTED#refs/heads/release/}"
EXPECTED="${EXPECTED#v}"
shift

for CRATE in "$@"; do
    VERSION=$(cargo metadata --format-version=1 2>/dev/null | jaq --raw-output '.packages[] | select(.name == "'$CRATE'").version')
    if [ "$VERSION" == "$EXPECTED" ] || [ "" == "$EXPECTED" ]; then
        echo -e " \u001b[1;32m✓\u001b[0m Crate \u001b[1m$CRATE\u001b[0m version is \u001b[1m$VERSION\u001b[0m"
    else
        echo -e " \u001b[1;31m✗\u001b[0m Crate \u001b[1m$CRATE\u001b[0m version is \u001b[1m$VERSION\u001b[0m, expected \u001b[1m$EXPECTED\u001b[0m"
        exit 1
    fi
done
