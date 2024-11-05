#!/bin/bash
set -e
set -u
set -o pipefail

## DESCRIPTION:
##
## This script queries all repos in a given github org and adds 
## all issues to a specified project board.
##
## PRE-REQS:
##
## This script assumes there is a github PAT in the GITHUB_TOKEN env var
## that was created with the following permissions:
##   - repo (all)
##   - read:org
##   - user (all)
##   - read:enterprise
##   - project (all)

GH_ORG=${GH_ORG:-'hyperlight-dev'}
ISSUES_PROJECT_NUMBER=${ISSUES_PROJECT_NUMBER:-'11'}

echo "GH_ORG=${GH_ORG}"

function get_project_id_from_number() {
    project_id="$(gh api graphql -f query='
    query($org: String!, $number: Int!) {
        organization(login: $org) {
            projectV2(number: $number) {
                id
            }
        }
    }' -f org="${GH_ORG}" -F number="$1" --jq '.data.organization.projectV2.id')"
    echo "$project_id"
}

# Get project ID
issues_project_id=$( get_project_id_from_number "$ISSUES_PROJECT_NUMBER" )
echo "project id for issues (number $ISSUES_PROJECT_NUMBER): ${issues_project_id}"

# Get list of repos in the org
repos_json="$(gh api graphql --paginate -f query='
    query($org: String!, $endCursor: String) {
        viewer {
            organization(login: $org) {
                repositories(first:100, after: $endCursor) {
                    nodes {
                        name
                    }
                    pageInfo {
                        hasNextPage
                        endCursor
                    }
                }
            }
        }
    }' -f org="${GH_ORG}")"

repos="$(jq ".data.viewer.organization.repositories.nodes[].name" <<< "$repos_json" |  tr -d '"' )"
#echo $repos

for repo in $repos
do
    # Check if repo has 'hyperlight' in the name
    if [[ $repo != *"hyperlight"* ]]; then
        continue
    fi
    
    echo "Looking for issues in ${GH_ORG}/${repo}"

    # TODO: paginate this query
    issues_json="$(gh api graphql -f query='
        query($org: String!, $repo: String!) {
            repository(owner: $org, name: $repo) {
                issues(last: 100, states: OPEN) {
                    totalCount
                    nodes {
                        id
                        number
                        title
                    }
                }
            }
        }' -f org="${GH_ORG}" -f repo="${repo}")"

    num_issues=$(jq ".data.repository.issues.nodes | length" <<< "$issues_json")
    echo "  found ${num_issues} in repo"

    if [ "$num_issues" -gt 0 ]; then
        range=$((num_issues - 1))
        for i in $(seq 0 $range)
        do
            issue_id=$(jq ".data.repository.issues.nodes[$i].id" <<< "$issues_json")
            issue_title=$(jq ".data.repository.issues.nodes[$i].title" <<< "$issues_json")
            issue_number=$(jq ".data.repository.issues.nodes[$i].number" <<< "$issues_json")
            echo "    adding ${issue_number} - ${issue_title}"

            gh api graphql -f query='
                mutation($project:ID!, $issue:ID!) {
                    addProjectV2ItemById(input: {projectId: $project, contentId: $issue}) {
                        item {
                            id
                        }
                    }
                }' -f project="${issues_project_id}" -f issue="${issue_id}" --jq .data.addProjectV2ItemById.item.id > /dev/null
        done
    fi
done
