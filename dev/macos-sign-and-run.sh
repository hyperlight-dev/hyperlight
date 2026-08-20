#!/usr/bin/env bash
set -Eeuo pipefail


codesign -f -s - --entitlements "$(dirname "$0")/macos-entitlements.plist" "$1"
exec "$@"
