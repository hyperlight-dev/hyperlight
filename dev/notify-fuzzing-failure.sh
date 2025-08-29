#!/bin/bash
set -e
set -u
set -o pipefail

## DESCRIPTION:
##
## This script creates or updates GitHub issues when fuzzing jobs fail.
## It checks for existing open fuzzing failure issues and either creates
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
## Run this script locally like:
##   GITHUB_REPOSITORY="fork/hyperlight" GITHUB_RUN_ID=1 ./dev/notify-fuzzing-failure.sh "fuzz_host_print,fuzz_guest_call,fuzz_host_call"

REPO="${GITHUB_REPOSITORY:-hyperlight-dev/hyperlight}"
WORKFLOW_RUN_URL="${GITHUB_SERVER_URL:-https://github.com}/${REPO}/actions/runs/${GITHUB_RUN_ID:-unknown}"
FUZZING_TARGETS="${1:-unknown}"

# Check if running in test mode (handle both first and second arguments)
if [ "${1:-}" = "--test" ] || [ "${2:-}" = "--test" ]; then
    echo "✅ Running in test mode - script structure is valid"
    echo "Would check for fuzzing failure issues in $REPO"
    echo "Would create issue or comment for fuzzing targets: ${1:-unknown}"
    echo "Workflow URL would be: $WORKFLOW_RUN_URL"
    exit 0
fi

echo "Checking for existing fuzzing failure issues in $REPO..."

# Extract owner and repo name from the repository
OWNER=$(echo "$REPO" | cut -d'/' -f1)
REPO_NAME=$(echo "$REPO" | cut -d'/' -f2)

# Define the issue title and labels
ISSUE_TITLE="Fuzzing Job Failure - $(date '+%Y-%m-%d')"
FUZZING_LABEL="area/testing"
FAILURE_LABEL="kind/bug"
FUZZING_KIND_LABEL="area/fuzzing"
LIFECYCLE_LABEL="lifecycle/needs-review"

# Search for existing open fuzzing failure issues
echo "Searching for existing open fuzzing failure issues..."
EXISTING_ISSUES=$(gh api graphql -f query='
  query($owner: String!, $repo: String!) {
    repository(owner: $owner, name: $repo) {
      issues(first: 10, states: OPEN, labels: ["area/fuzzing"]) {
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
  }' -f owner="$OWNER" -f repo="$REPO_NAME" --jq '.data.repository.issues')

# Filter for fuzzing-related issues (now all results should be fuzzing issues due to label filter)
FUZZING_ISSUES=$(echo "$EXISTING_ISSUES" | jq '.nodes[]' 2>/dev/null || echo "")
FUZZING_ISSUE_COUNT=0
if [ -n "$FUZZING_ISSUES" ]; then
    FUZZING_ISSUE_COUNT=$(echo "$FUZZING_ISSUES" | jq -s 'length' 2>/dev/null || echo "0")
fi

echo "Found $FUZZING_ISSUE_COUNT existing fuzzing failure issue(s)"

if [ "$FUZZING_ISSUE_COUNT" -gt 0 ]; then
    # Get the most recent fuzzing failure issue
    ISSUE_NUMBER=$(echo "$FUZZING_ISSUES" | jq -r '.number' | head -1)
    ISSUE_URL=$(echo "$FUZZING_ISSUES" | jq -r '.url' | head -1)
    
    if [ "$ISSUE_NUMBER" = "null" ] || [ -z "$ISSUE_NUMBER" ]; then
        echo "⚠️  Could not parse issue number from fuzzing issues, creating new issue instead"
        FUZZING_ISSUE_COUNT=0
    else
        echo "Adding comment to existing issue #$ISSUE_NUMBER"
        
        # Create comment body
        COMMENT_BODY="## Fuzzing Job Failed Again

**Date:** $(date '+%Y-%m-%d %H:%M:%S UTC')
**Workflow Run:** [$WORKFLOW_RUN_URL]($WORKFLOW_RUN_URL)
**Fuzzing Targets:** $FUZZING_TARGETS

The scheduled fuzzing job has failed again. Please check the workflow logs and artifacts for details."

        # Add comment to the existing issue
        if gh issue comment "$ISSUE_NUMBER" --body "$COMMENT_BODY" --repo "$REPO"; then
            echo "✅ Added comment to existing issue #$ISSUE_NUMBER: $ISSUE_URL"
        else
            echo "❌ Failed to add comment to existing issue. Creating new issue instead."
            FUZZING_ISSUE_COUNT=0
        fi
    fi
fi

if [ "$FUZZING_ISSUE_COUNT" -eq 0 ]; then
    echo "No existing fuzzing failure issues found. Creating new issue..."
    
    # Create issue body
    ISSUE_BODY="## Fuzzing Job Failure Report

**Date:** $(date '+%Y-%m-%d %H:%M:%S UTC')
**Workflow Run:** [$WORKFLOW_RUN_URL]($WORKFLOW_RUN_URL)
**Fuzzing Targets:** $FUZZING_TARGETS

The scheduled fuzzing job has failed. This issue was automatically created to track the failure.

### Details
The fuzzing workflow failed during execution. Please check the workflow logs and any uploaded artifacts for more details.

### Next Steps
- [ ] Review the workflow logs for error details
- [ ] Download and analyze any crash artifacts if available
- [ ] Determine the root cause of the failure
- [ ] Fix the underlying issue

### Related Documentation
- [Fuzzing README](https://github.com/$REPO/blob/main/fuzz/README.md)
- [Security Guidance](https://github.com/$REPO/blob/main/docs/security-guidance-for-developers.md)

---
*This issue was automatically created by the fuzzing failure notification system.*"

    # Create the new issue
    if ISSUE_URL=$(gh issue create \
        --title "$ISSUE_TITLE" \
        --body "$ISSUE_BODY" \
        --label "$FUZZING_LABEL" \
        --label "$FAILURE_LABEL" \
        --label "$FUZZING_KIND_LABEL" \
        --label "$LIFECYCLE_LABEL" \
        --repo "$REPO"); then
        echo "✅ Created new fuzzing failure issue: $ISSUE_URL"
    else
        echo "❌ Failed to create new fuzzing failure issue"
        exit 1
    fi
fi

echo "Fuzzing failure notification completed successfully"