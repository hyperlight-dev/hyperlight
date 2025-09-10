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
##   ./dev/notify-fuzzing-failure.sh
##   ./dev/notify-fuzzing-failure.sh --title="Nightly Failure" --labels="area/testing,kind/bug"
##   ./dev/notify-fuzzing-failure.sh --test
## Run this script locally like:
##   GITHUB_REPOSITORY="fork/hyperlight" GITHUB_RUN_ID=1 ./dev/notify-fuzzing-failure.sh --title="Nightly Failure" --labels="area/testing,kind/bug"

REPO="${GITHUB_REPOSITORY:-hyperlight-dev/hyperlight}"
WORKFLOW_RUN_URL="${GITHUB_SERVER_URL:-https://github.com}/${REPO}/actions/runs/${GITHUB_RUN_ID:-unknown}"
TEST_MODE=false
ISSUE_TITLE=""
LABELS="area/testing,kind/bug,area/fuzzing,lifecycle/needs-review"

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

# Choose a label to search existing issues for; prefer the first label if present
SEARCH_LABEL="${LABEL_ARRAY[0]:-area/fuzzing}"

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

echo "Checking for existing issues in $REPO with label '$SEARCH_LABEL'..."
EXISTING_ISSUES=$(gh api graphql -f query='
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
  }' -f owner="$OWNER" -f repo="$REPO_NAME" -f label="$SEARCH_LABEL" --jq '.data.repository.issues') || EXISTING_ISSUES=""

FUZZING_ISSUES=$(echo "$EXISTING_ISSUES" | jq '.nodes[]' 2>/dev/null || echo "")
FUZZING_ISSUE_COUNT=0
if [ -n "$FUZZING_ISSUES" ]; then
    FUZZING_ISSUE_COUNT=$(echo "$FUZZING_ISSUES" | jq -s 'length' 2>/dev/null || echo "0")
fi

echo "Found $FUZZING_ISSUE_COUNT existing issue(s) matching label '$SEARCH_LABEL'"

if [ "$FUZZING_ISSUE_COUNT" -gt 0 ]; then
    ISSUE_NUMBER=$(echo "$FUZZING_ISSUES" | jq -r '.number' | head -1)
    ISSUE_URL=$(echo "$FUZZING_ISSUES" | jq -r '.url' | head -1)
    if [ "$ISSUE_NUMBER" = "null" ] || [ -z "$ISSUE_NUMBER" ]; then
        echo "⚠️  Could not parse issue number from search results; will create a new issue"
        FUZZING_ISSUE_COUNT=0
    else
        echo "Adding comment to existing issue #$ISSUE_NUMBER"
        COMMENT_BODY="## Job Failed Again

**Date:** $(date '+%Y-%m-%d %H:%M:%S UTC')
**Workflow Run:** [$WORKFLOW_RUN_URL]($WORKFLOW_RUN_URL)

The scheduled job has failed again. Please check the workflow logs and artifacts for details."

        if gh issue comment "$ISSUE_NUMBER" --body "$COMMENT_BODY" --repo "$REPO"; then
            echo "✅ Added comment to existing issue #$ISSUE_NUMBER: $ISSUE_URL"
            exit 0
        else
            echo "❌ Failed to add comment to existing issue. Will attempt to create a new issue instead."
            FUZZING_ISSUE_COUNT=0
        fi
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

    # Build label args for gh issue create
    LABEL_ARGS=()
    for lbl in "${LABEL_ARRAY[@]}"; do
        LABEL_ARGS+=("--label" "$lbl")
    done

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