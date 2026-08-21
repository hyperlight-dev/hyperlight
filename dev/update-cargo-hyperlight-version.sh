#!/usr/bin/env bash
set -Eeuo pipefail

## DESCRIPTION:
##
## Pins the latest published cargo-hyperlight in the Justfile and in
## flake.nix. The Justfile only needs the version, flake.nix also needs
## the SRI hash of the .crate tarball. Both come from the crates.io
## sparse index, so no download and no Nix are needed.
##
## PRE-REQS:
##
## curl, jq, and sed.

CRATE=cargo-hyperlight
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

for tool in curl jq sed; do
    command -v "$tool" >/dev/null || { echo "error: $tool is required" >&2; exit 1; }
done

# `sed -i` takes different arguments on GNU and BSD, so edit via a temp file.
sedi() {
    local file=$1
    shift
    if ! sed "$@" "$file" > "$file.tmp"; then
        rm -f "$file.tmp"
        exit 1
    fi
    mv "$file.tmp" "$file"
}

check() {
    grep -qF "$2" "$1" || { echo "error: failed to update $1 with: $2" >&2; exit 1; }
}

# Index paths are bucketed by the first four characters of the crate name.
INDEX="https://index.crates.io/${CRATE:0:2}/${CRATE:2:2}/$CRATE"

# Entries are in publication order, so the last released one is the latest.
read -r VERSION CKSUM < <(curl -fsSL "$INDEX" |
    jq -rs 'map(select((.yanked | not) and (.vers | contains("-") | not))) | last | "\(.vers) \(.cksum)"')

# The index gives the checksum in hex, Nix wants it base64 encoded.
# shellcheck disable=SC2001 # no parameter expansion pairs up hex digits
HASH="sha256-$(printf %b "$(sed 's/../\\x&/g' <<< "$CKSUM")" | base64 | tr -d '\n')"
echo "latest release: $VERSION ($HASH)"

sedi Justfile "s|^cargo-hyperlight-version := \".*\"|cargo-hyperlight-version := \"$VERSION\"|"

# Both fields are matched inside the fetchurl block, where they are unique.
BLOCK='/cargo-hyperlight = let/,/^ *};$/'
sedi flake.nix \
    -e "$BLOCK s|version = \"[^\"]*\"|version = \"$VERSION\"|" \
    -e "$BLOCK s|hash = \"[^\"]*\"|hash = \"$HASH\"|"

check Justfile "cargo-hyperlight-version := \"$VERSION\""
check flake.nix "version = \"$VERSION\""
check flake.nix "hash = \"$HASH\""

echo "pinned cargo-hyperlight $VERSION in Justfile and flake.nix"
