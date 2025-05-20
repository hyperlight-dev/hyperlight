#!/bin/bash
# This script checks for the presence of the required license header in Rust source files.

# Get the repository root
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT" || exit 1

# Define the license header pattern to look for
LICENSE_PATTERN="Copyright .* The Hyperlight Authors..*Licensed under the Apache License, Version 2.0"

# Initialize a variable to track missing headers
MISSING_HEADERS=0
MISSING_FILES=""

# Find all Rust files, excluding target directory
while IFS= read -r file; do
    # Skip auto-generated files
    if grep -q "@generated" "$file" || grep -q "Automatically generated" "$file"; then
        continue
    fi

    # Check if the file has the license header (allowing for multi-line matching)
    if ! grep -q -z "$LICENSE_PATTERN" "$file"; then
        echo "Missing or invalid license header in $file"
        MISSING_FILES="$MISSING_FILES\n  $file"
        MISSING_HEADERS=$((MISSING_HEADERS + 1))
    fi
done < <(find src -name "*.rs" -type f)

if [ $MISSING_HEADERS -gt 0 ]; then
    echo "Found $MISSING_HEADERS files with missing or invalid license headers:"
    echo -e "$MISSING_FILES"
    exit 1
else
    echo "All Rust files have the required license header"
    exit 0
fi