#!/bin/bash
set -e
set -u
set -o pipefail

## DESCRIPTION:
##
## This script checks for open issues with P-release-blocker or release-blocker
## in a given GitHub repository. It exits with code 1 if any blocking
## issues are found, or 0 if none are found.
##
## PRE-REQS:
##
## This script assumes that the gh cli is installed and in the PATH
## and that there is a GitHub PAT in the GITHUB_TOKEN env var
## with the following permissions:
##   - repo (read)
##   - issues (read)
## or that the user is logged into the gh cli with an account with those permissions


# Check if repository argument is provided
if [ -z "${1:-}" ]; then
    echo "Error: Repository name not provided."
    echo "Usage: $0 <owner/repo>"
    echo "Example: $0 hyperlight-dev/hyperlight"
    exit 1
fi

REPO="$1"
echo "Checking for open issues with P-release-blocker or release-blocker in $REPO..."

# Extract owner and repo name from the argument
OWNER=$(echo "$REPO" | cut -d'/' -f1)
REPO_NAME=$(echo "$REPO" | cut -d'/' -f2)

BLOCKING_ISSUES=$(gh api graphql -f query='
  query($owner: String!, $repo: String!) {
    repository(owner: $owner, name: $repo) {
      legacy: issues(first: 100, states: OPEN, labels: ["release-blocker"]) {
        totalCount
        nodes {
          number
          title
          url
        }
      }
      structured: issues(first: 100, states: OPEN, labels: ["P-release-blocker"]) {
        totalCount
        nodes {
          number
          title
          url
        }
      }
    }
  }' -f owner="$OWNER" -f repo="$REPO_NAME" --jq '.data.repository')

BLOCKER_COUNT=$(echo "$BLOCKING_ISSUES" | jq -e '.legacy.totalCount + .structured.totalCount')

if [ "$BLOCKER_COUNT" -gt 0 ]; then
    echo "❌ Found open release-blocking issues ($BLOCKER_COUNT label matches):"
    echo "$BLOCKING_ISSUES" | jq -r '[.legacy.nodes[], .structured.nodes[]] | unique_by(.number)[] | "  - #\(.number): \(.title) (\(.url))"'
    echo ""
    echo "Release blocked by P-release-blocker or release-blocker issues"
    exit 1
else
    echo "✅ No open release blocking issues found"
    exit 0
fi
