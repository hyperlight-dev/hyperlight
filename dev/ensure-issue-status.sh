#!/bin/bash
set -euo pipefail

source "$(dirname "$0")/label-utils.sh"
REPO="${GITHUB_REPOSITORY:?}"
ISSUE_NUMBER="${1:?}"
LABELS="$(gh issue view "$ISSUE_NUMBER" --repo "$REPO" --json labels)"
HAS_STATUS="$(jq -r 'any(.labels[].name; startswith("S-") or startswith("lifecycle/"))' <<<"$LABELS")"
if [ "$HAS_STATUS" = true ]; then
    exit 0
fi
load_available_labels
STATUS="$(resolve_label S-needs-triage)"
gh issue edit "$ISSUE_NUMBER" --repo "$REPO" --add-label "$STATUS"
