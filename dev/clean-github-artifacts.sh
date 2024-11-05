#!/usr/bin/env bash

# Cleans up artifacts older than 7 days, except for release artifacts.

set -o errexit
set -o nounset
set -o pipefail

CUTOFF_DATE=$(date --date='7 days ago' +%s) # the cutoff up to which we delete artifacts
echo "Querying for artifacts older than $(date --date="@$CUTOFF_DATE")..."

# gets artifacts and writes them to a file in the format <artifact_id>,<size_in_bytes>
gh api repos/hyperlight-dev/hyperlight/actions/artifacts?per_page=100 --paginate |
	jq -crs --arg date "$CUTOFF_DATE" 'map(.artifacts) |
		flatten | .[] |
		select((.created_at | fromdate) < ($date | tonumber) and (.workflow_run.head_branch | test("(release/)?v\\d+\\.\\d+\\.\\d+") | not)) |
		"\(.id),\(.size_in_bytes)"' > HYPERLIGHT_ARTIFACTS_TO_DELETE.txt
awk -F',' '{ sum += $2 }END{ printf "Deleting %d artifacts taking up %d bytes.\n", NR, sum }' HYPERLIGHT_ARTIFACTS_TO_DELETE.txt
# deletes each artifact in the file
cut -d "," -f 1 < HYPERLIGHT_ARTIFACTS_TO_DELETE.txt | xargs -I{} gh api --method DELETE /repos/hyperlight-dev/hyperlight/actions/artifacts/{}
rm -f HYPERLIGHT_ARTIFACTS_TO_DELETE.txt
echo "Deletion complete."
