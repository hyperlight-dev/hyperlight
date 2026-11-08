#!/bin/bash

LABEL_ALIASES="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/label-aliases.json"

# Prefer the structured name, or an existing alias during rollout.
resolve_label() {
    local label="$1"
    jq -er --arg label "$label" --argjson available "$AVAILABLE_LABELS" '
        ([$label] + (.[$label] // [])) as $candidates |
        [$candidates[] | select(. as $name | $available | index($name))][0] //
        error("No available label for " + $label)
    ' "$LABEL_ALIASES"
}

load_available_labels() {
    AVAILABLE_LABELS="$(gh api "repos/$REPO/labels" --paginate --slurp |
        jq -e '[.[][] | .name]')"
}
