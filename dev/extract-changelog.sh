#!/bin/bash
set -Eeuo pipefail

# Inspired by https://stackoverflow.com/questions/40450238/parse-a-changelog-and-extract-changes-for-a-version
# This script will extract the changelog for a specific version from the CHANGELOG.md file
# Usage: ./extract-changelog.sh <version>, for example ./extract-changelog.sh v0.2.0

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <version>"
  echo "  Example: $0 v0.2.0"
  echo "  Example: $0 Prerelease"
  exit 1
fi

version=$1

awk -v ver="$version" '
/^## \[.*\]/ {
  if (p) exit
  if ($0 ~ "^## \\[" ver "\\]") { p=1; next }
}
p' CHANGELOG.md