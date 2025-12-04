#!/bin/bash
set -e
set -o pipefail

# This script checks for open PRs from dependabot that have all checks passing and have not been
# modified by another user, and approves+merges them automatically.
# To be run as a GitHub action.

# Check if repository argument is provided
if [ -z "$1" ]; then
    echo "Error: Repository name not provided."
    echo "Usage: $0 <owner/repo>"
    echo "Example: $0 hyperlight-dev/hyperlight"
    exit 1
fi

REPO="$1"
echo "Checking for open Dependabot PRs to approve and merge in $REPO..."

# Get all open PRs from dependabot
# We filter so that only PRs that are not from forks and are in branches starting with "dependabot/cargo" are included.
dependabot_prs=$(gh pr list -R "$REPO" --author "dependabot[bot]" --state open --json number,title,reviews,headRepositoryOwner,headRefName | jq --arg repo_owner "$(echo "$REPO" | cut -d'/' -f1)" '[.[] | select(.headRepositoryOwner.login == $repo_owner and (.headRefName | startswith("dependabot/cargo")))]')
# Exit early if no PRs found
if [ -z "$dependabot_prs" ] || [ "$dependabot_prs" = "[]" ]; then
    echo "No open Dependabot PRs found in $REPO"
    exit 0
fi

# Count how many PRs we found
pr_count=$(echo "$dependabot_prs" | jq 'length')
echo "Found $pr_count open Dependabot PRs in $REPO"

# Process each PR
echo "$dependabot_prs" | jq -c '.[]' | while read -r pr; do
    pr_number=$(echo "$pr" | jq -r '.number')
    pr_title=$(echo "$pr" | jq -r '.title')
    
    echo "Processing PR #$pr_number: $pr_title"
    
    # Check if PR only modifies allowed files
    pr_files=$(gh pr view "$pr_number" -R "$REPO" --json files)
    invalid_files=$(echo "$pr_files" | jq -r '.files[].path' | grep -v -E '(Cargo\.toml|Cargo\.lock)' || true)
    
    if [ -n "$invalid_files" ]; then
        echo "  ❌ PR #$pr_number modifies files that are not allowed for auto-merge:"
        echo ${invalid_files/#/    - }
        echo "  ℹ️ Only changes to Cargo.toml and Cargo.lock are allowed"
        continue
    fi

    echo "  ✅ PR #$pr_number only modifies allowed files (Cargo.toml and Cargo.lock)"

    # First, get detailed PR information including all checks
    pr_details=$(gh pr view "$pr_number" -R "$REPO" --json statusCheckRollup,state)
    
    # Check if all status checks have passed (regardless of required or not)
    all_checks_pass=true
    has_pending_checks=false
    failed_checks=""
    
        # First identify checks that are still in progress
    pending_checks=$(echo "$pr_details" | jq -r '.statusCheckRollup[] | select(.status == "IN_PROGRESS" or .status == "QUEUED" or .status == "PENDING") | .name')
    
    # Check for permission-required checks
    permission_required_checks=$(echo "$pr_details" | jq -r '.statusCheckRollup[] | select(.status == "WAITING" or .status == "ACTION_REQUIRED" or (.status == "QUEUED" and .conclusion == null and .detailsUrl != null and (.detailsUrl | contains("waiting-for-approval")))) | .name')
    
    # Dont approve if there are checks required that need permission to run 
    if [ -n "$permission_required_checks" ]; then
        echo "  🔐 PR #$pr_number has checks waiting for permission:"
        echo "$permission_required_checks" | sed 's/^/    - /'
        echo "  ❌ Skipping auto-approval due to permission-required checks"
        continue
    fi
    
    if [ -n "$pending_checks" ]; then
        echo "  ⏳ PR #$pr_number has pending checks:"
        echo "$pending_checks" | sed 's/^/    - /'
        echo "  ℹ️ We will still approve the PR so it can merge automatically once all checks pass"
        has_pending_checks=true
    fi

    # Check for failed checks - only include checks that have a conclusion and are not still running
    # Explicitly exclude checks with status IN_PROGRESS, QUEUED, or PENDING
    failed_checks=$(echo "$pr_details" | jq -r '.statusCheckRollup[] | 
        select(.conclusion != null and 
               .conclusion != "SUCCESS" and 
               .conclusion != "NEUTRAL" and 
               .conclusion != "SKIPPED" and
               .status != "IN_PROGRESS" and 
               .status != "QUEUED" and 
               .status != "PENDING") | .name')
    
    if [ -n "$failed_checks" ]; then
        echo "  ❌ PR #$pr_number has failed checks:"
        echo "$failed_checks" | sed 's/^/    - /'
        all_checks_pass=false
        continue
    fi
    
    # If we've reached here, either all checks have passed or some are pending
    if [ "$has_pending_checks" = false ]; then
        echo "  ✅ All status checks passed for PR #$pr_number"
    fi
    
    # Check if PR has been modified by someone other than dependabot
    pr_commits=$(gh pr view "$pr_number" -R "$REPO" --json commits)
    non_dependabot_authors=$(echo "$pr_commits" | jq -r '.commits[].authors[].login' | grep -v -e "dependabot\[bot\]" -e "^$" || true)
    
    if [ -n "$non_dependabot_authors" ]; then
        echo "  ❌ PR #$pr_number has been modified by users other than dependabot: $non_dependabot_authors"
        continue
    fi
    
    # Check if PR needs approval (i.e., hasn't been approved already)
    already_approved=$(echo "$pr" | jq -r '.reviews[] | select(.state == "APPROVED") | .state' | grep -c "APPROVED" || true)
    
    if [ "$already_approved" -eq 0 ]; then
        echo "  ✅ Approving PR #$pr_number"
        gh pr review "$pr_number" -R "$REPO" --approve -b "Automatically approved by dependabot auto-approve workflow"
    else
        echo "  ℹ️ PR #$pr_number is already approved"
    fi
    
    if [ "$has_pending_checks" = true ] || [ "$all_checks_pass" = true ]; then
        # Check if PR is up-to-date with base branch
        merge_status=$(gh pr view "$pr_number" -R "$REPO" --json mergeStateStatus -q '.mergeStateStatus')
        
        if [ "$merge_status" != "CLEAN" ]; then
            echo "  ⚠️ PR #$pr_number is not up to date (status: $merge_status)"
            # Enable auto-merge to merge once checks pass
            echo "  ✅ Enabling auto-merge (squash strategy) for PR #$pr_number"
            gh pr merge "$pr_number" -R "$REPO" --auto --squash
            echo "  ✅ Auto-merge enabled for PR #$pr_number"
        else
            echo "  ✅ PR #$pr_number is up to date with base branch"
            # PR is already clean/mergeable - merge directly instead of enabling auto-merge
            echo "  ✅ Merging PR #$pr_number directly (squash strategy)"
            gh pr merge "$pr_number" -R "$REPO" --squash
            echo "  ✅ PR #$pr_number merged successfully"
        fi
    fi
    
done

echo "Finished processing Dependabot PRs for $REPO"
