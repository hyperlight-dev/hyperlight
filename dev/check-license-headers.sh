#!/usr/bin/env bash
# This script checks for the presence of the required license header in Rust source files.

# Get the repository root
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT" || exit 1

# Define the license patterns to look for
SPDX_PATTERN="^// SPDX-License-Identifier: Apache-2\.0$"
COPYRIGHT_PATTERN="^// Copyright .* The Hyperlight Authors\.$"

# Define the full license header for files that need it
YEAR="$(date +"%Y")"
LICENSE_HEADER="// SPDX-License-Identifier: Apache-2.0
// Copyright $YEAR The Hyperlight Authors.
"

# Initialize a variable to track missing headers
MISSING_HEADERS=0
MISSING_FILES=""

# Find all Rust files, excluding target directory
while IFS= read -r -d $'\0' file; do
    # Skip some files which appear when the guests are build
    if grep -q '^src/tests/rust_guests/target/' <<< "$file"; then
        continue
    fi

    # Skip auto-generated files
    if grep -q "@generated" "$file" || grep -q "Automatically generated" "$file"; then
        continue
    fi

    header="$(head -2 "$file")"
    if ! grep -q "$SPDX_PATTERN" <<< "$header" || ! grep -q "$COPYRIGHT_PATTERN" <<< "$header"; then
        echo "Missing or invalid license header in $file"
        MISSING_FILES="$MISSING_FILES\n  $file"
        MISSING_HEADERS=$((MISSING_HEADERS + 1))
    fi
done < <(find src -name "*.rs" -type f -print0)

if [ $MISSING_HEADERS -gt 0 ]; then
    echo "Found $MISSING_HEADERS files with missing or invalid license headers:"
    echo -e "$MISSING_FILES"
    echo ""
    echo "Please add the following license header to these files:"
    echo "$LICENSE_HEADER"
    echo "You can also run: just check-license-headers to verify your changes."
    exit 1
else
    echo "All Rust files have the required license header"
    exit 0
fi
