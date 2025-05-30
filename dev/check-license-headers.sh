#!/bin/bash
# This script checks for the presence of the required license header in Rust source files.

# Get the repository root
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT" || exit 1

# Define the license header pattern to look for
LICENSE_PATTERN="Copyright .* The Hyperlight Authors..*Licensed under the Apache License, Version 2.0"

# Define the full license header for files that need it
LICENSE_HEADER='/*
Copyright 2025 The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

'

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
    echo ""
    echo "Please add the following license header to these files:"
    echo "$LICENSE_HEADER"
    echo "You can also run: just check-license-headers to verify your changes."
    exit 1
else
    echo "All Rust files have the required license header"
    exit 0
fi