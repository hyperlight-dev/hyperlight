#!/bin/bash
set -e
set -u
set -o pipefail

## DESCRIPTION:
##
# Generic notifier for CI job failures that can create or update GitHub issues.
## This script creates or updates GitHub issues when a jobs fail.
## It checks for existing open failure issues and either creates
## a new one or adds a comment to an existing one.
##
## PRE-REQS:
##
## This script assumes that the gh cli is installed and in the PATH
## and that there is a GitHub PAT in the GITHUB_TOKEN env var
## with the following permissions:
##   - issues (read/write)
## or that the user is logged into the gh cli with an account with those permissions
## 
## Usage examples:
##   ./dev/notify-ci-failure.sh
##   ./dev/notify-ci-failure.sh --title="Nightly Failure" --labels="A-testing,C-bug"
##   ./dev/notify-ci-failure.sh --test
## Run this script locally like:
##   GITHUB_REPOSITORY="fork/hyperlight" GITHUB_RUN_ID=1 ./dev/notify-ci-failure.sh --title="Nightly Failure" --labels="A-testing,C-bug"

REPO="${GITHUB_REPOSITORY:-hyperlight-dev/hyperlight}"
WORKFLOW_RUN_URL="${GITHUB_SERVER_URL:-https://github.com}/${REPO}/actions/runs/${GITHUB_RUN_ID:-unknown}"
TEST_MODE=false
ISSUE_TITLE=""
LABELS="A-testing,C-bug,A-fuzzing,S-needs-triage"
source "$(dirname "$0")/label-utils.sh"

for arg in "$@"; do
    case $arg in
        --test)
            TEST_MODE=true
            shift
            ;;
        --title=*)
            ISSUE_TITLE="${arg#*=}"
            shift
            ;;
        --labels=*)
            LABELS="${arg#*=}"
            shift
            ;;
        *)
    esac
done

# Normalize labels into an array
IFS=',' read -r -a LABEL_ARRAY <<< "$LABELS"
if [ "${#LABEL_ARRAY[@]}" -eq 0 ]; then
    echo "At least one CI failure label is required" >&2
    exit 1
fi

# Choose a label to search existing issues for; prefer the first label if present
SEARCH_LABEL="${LABEL_ARRAY[0]:-A-fuzzing}"

# Build issue title if not provided
if [ -z "$ISSUE_TITLE" ]; then
    ISSUE_TITLE="Job Failure - $(date '+%Y-%m-%d')"
fi


if [ "$TEST_MODE" = true ]; then
    echo "✅ Running in test mode - script structure is valid"
    echo "Would check for issues in $REPO"
    echo "Workflow URL would be: $WORKFLOW_RUN_URL"
    echo "Issue Title would be: $ISSUE_TITLE"
    echo "Labels would be: $LABELS"
    echo "Search Label would be: $SEARCH_LABEL"
    exit 0
fi

# Extract owner and repo name from the repository
OWNER=$(echo "$REPO" | cut -d'/' -f1)
REPO_NAME=$(echo "$REPO" | cut -d'/' -f2)

load_available_labels
LABEL_ARGS=()
for lbl in "${LABEL_ARRAY[@]}"; do
    RESOLVED_LABEL="$(resolve_label "$lbl")"
    LABEL_ARGS+=("--label" "$RESOLVED_LABEL")
done

# Search aliases independently. A multi-label GraphQL filter requires all labels.
SEARCH_LABELS="$(jq -r --arg label "$SEARCH_LABEL" '[$label] + (.[$label] // []) | .[]' "$LABEL_ALIASES")"
EXISTING_ISSUES='[]'
while IFS= read -r label; do
    echo "Checking for existing issues in $REPO with label '$label'..."
    MATCHES=$(gh api graphql -f query='
  query($owner: String!, $repo: String!, $label: String!) {
    repository(owner: $owner, name: $repo) {
      issues(first: 10, states: OPEN, labels: [$label]) {
        totalCount
        nodes {
          number
          title
          url
          labels(first: 20) {
            nodes {
              name
            }
          }
        }
      }
    }
  }' -f owner="$OWNER" -f repo="$REPO_NAME" -f label="$label" --jq '.data.repository.issues.nodes')
    EXISTING_ISSUES="$(jq -en --argjson existing "$EXISTING_ISSUES" --argjson matches "$MATCHES" '
        if ($matches | type) != "array" then error("Invalid issue search response")
        else $existing + $matches | unique_by(.number) end')"
done <<<"$SEARCH_LABELS"

FUZZING_ISSUE_COUNT=$(echo "$EXISTING_ISSUES" | jq 'length')

echo "Found $FUZZING_ISSUE_COUNT existing issue(s) matching label '$SEARCH_LABEL'"

if [ "$FUZZING_ISSUE_COUNT" -gt 0 ]; then
    ISSUE_NUMBER=$(echo "$EXISTING_ISSUES" | jq -r '.[0].number')
    ISSUE_URL=$(echo "$EXISTING_ISSUES" | jq -r '.[0].url')
    if [[ ! "$ISSUE_NUMBER" =~ ^[0-9]+$ ]]; then
        echo "Could not parse issue number from search results" >&2
        exit 1
    else
        EDIT_LABEL_ARGS=()
        for lbl in "${LABEL_ARRAY[@]}"; do
            if [ "$lbl" = "P-release-blocker" ]; then
                RESOLVED_LABEL="$(resolve_label "$lbl")"
                EDIT_LABEL_ARGS+=("--add-label" "$RESOLVED_LABEL")
            fi
        done
        if [ "${#EDIT_LABEL_ARGS[@]}" -gt 0 ]; then
            gh issue edit "$ISSUE_NUMBER" --repo "$REPO" "${EDIT_LABEL_ARGS[@]}"
        fi
        echo "Adding comment to existing issue #$ISSUE_NUMBER"
        COMMENT_BODY="## Job Failed Again

**Date:** $(date '+%Y-%m-%d %H:%M:%S UTC')
**Workflow Run:** [$WORKFLOW_RUN_URL]($WORKFLOW_RUN_URL)

The scheduled job has failed again. Please check the workflow logs and artifacts for details."

        gh issue comment "$ISSUE_NUMBER" --body "$COMMENT_BODY" --repo "$REPO"
        echo "✅ Added comment to existing issue #$ISSUE_NUMBER: $ISSUE_URL"
        exit 0
    fi
fi

if [ "$FUZZING_ISSUE_COUNT" -eq 0 ]; then
    echo "No existing matching issues found. Creating a new issue..."

    ISSUE_BODY="## Job Failure Report

**Date:** $(date '+%Y-%m-%d %H:%M:%S UTC')
**Workflow Run:** [$WORKFLOW_RUN_URL]($WORKFLOW_RUN_URL)

### Details
The scheduled job failed during execution. This issue was automatically created to track the failure. Please check the workflow logs and any uploaded artifacts for more details.

### Next Steps
- [ ] Review the workflow logs for error details
- [ ] Download and analyze any crash artifacts if available
- [ ] Determine the root cause of the failure
- [ ] Fix the underlying issue

---
*This issue was automatically created by the CI failure notification system.*"

    if ISSUE_URL=$(gh issue create \
        --title "$ISSUE_TITLE" \
        --body "$ISSUE_BODY" \
        "${LABEL_ARGS[@]}" \
        --repo "$REPO"); then
        echo "✅ Created new issue: $ISSUE_URL"
    else
        echo "❌ Failed to create new issue"
        exit 1
    fi
fi

echo "Notification script completed successfully"