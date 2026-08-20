#!/usr/bin/env bash
# Scans workflow files for GitHub Actions, resolves the latest release,
# and prints the pinned hash reference.
#
# Usage: ./hack/update-actions.sh [--update]
#   --update   Apply the pinned hashes to the workflow files in-place
# Requires: gh (GitHub CLI), authenticated

set -euo pipefail

do_update=false
if [[ "${1:-}" == "--update" ]]; then
    do_update=true
fi

if ! command -v gh &>/dev/null; then
    echo "Error: gh (GitHub CLI) is required. Install from https://cli.github.com" >&2
    exit 1
fi

workflow_dir="$(git rev-parse --show-toplevel)/.github/workflows"

# Extract unique action references (owner/repo@version) from all workflow files
mapfile -t actions < <(
    grep -rhoP 'uses:\s*\K[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+@\S+' "$workflow_dir" \
    | sort -u
)

if [[ ${#actions[@]} -eq 0 ]]; then
    echo "No actions found in $workflow_dir"
    exit 0
fi

# Resolve latest release + commit hash for each action
declare -A latest_tag latest_hash

sed_escape_regex() {
    printf '%s' "$1" | sed -E 's/[][\\.^$*+?{}()|]/\\&/g'
}

resolve_tag_sha() {
    local repo=$1 tag=$2
    local ref_data obj_type obj_sha

    ref_data=$(gh api "repos/$repo/git/ref/tags/$tag" \
        --jq '[.object.type // "", .object.sha // ""] | @tsv' 2>/dev/null) || true
    read -r obj_type obj_sha <<< "$ref_data"

    # Dereference annotated tags to get the commit
    if [[ "$obj_type" == "tag" ]]; then
        obj_sha=$(gh api "repos/$repo/git/tags/$obj_sha" \
            --jq '.object.sha' 2>/dev/null) || true
    fi

    echo "${obj_sha:-(not found)}"
}

for entry in "${actions[@]}"; do
    repo="${entry%%@*}"
    current="${entry##*@}"

    # Get the newest release (any major version)
    release=$(gh release list --repo "$repo" --limit 100 --json tagName \
        --jq '.[].tagName' 2>/dev/null \
        | grep -E '^v[0-9]' \
        | sort -V \
        | tail -1) || true

    if [[ -z "$release" ]]; then
        release="$current"
    fi

    latest_tag["$entry"]="$release"
    latest_hash["$entry"]=$(resolve_tag_sha "$repo" "$release")
done

markdown_escape() {
    local value=$1
    value=${value//\\/\\\\}
    value=${value//|/\\|}
    printf '%s' "$value"
}

# Print summary table
echo "| ACTION | CURRENT | LATEST | LATEST HASH | UPDATE? | URL |"
echo "| --- | --- | --- | --- | --- | --- |"

for entry in "${actions[@]}"; do
    repo="${entry%%@*}"
    current="${entry##*@}"
    if [[ "$current" != "${latest_hash[$entry]}" ]]; then
        needs_update="YES"
    else
        needs_update="no"
    fi

    printf '| %s | %s | %s | %s | %s | %s |\n' \
        "$(markdown_escape "$repo")" \
        "$(markdown_escape "$current")" \
        "$(markdown_escape "${latest_tag[$entry]}")" \
        "$(markdown_escape "${latest_hash[$entry]}")" \
        "$needs_update" \
        "$(markdown_escape "https://github.com/$repo/releases")"
done

# Print pinned references
echo ""
echo "# Pinned references (copy into workflows):"
for entry in "${actions[@]}"; do
    repo="${entry%%@*}"
    hash="${latest_hash[$entry]}"
    tag="${latest_tag[$entry]}"
    if [[ "$hash" != "(not found)" ]]; then
        echo "  $repo@$hash  # $tag"
    fi
done

# Apply updates to workflow files
if [[ "$do_update" == true ]]; then
    echo ""
    updated=0
    for entry in "${actions[@]}"; do
        repo="${entry%%@*}"
        current="${entry##*@}"
        hash="${latest_hash[$entry]}"
        tag="${latest_tag[$entry]}"
        escaped_repo=$(sed_escape_regex "$repo")
        escaped_current=$(sed_escape_regex "$current")

        if [[ "$hash" == "(not found)" || "$current" == "$hash" ]]; then
            continue
        fi

        # Replace repo@current with repo@hash # tag in all workflow files
        while IFS= read -r file; do
            if grep -q "${repo}@${current}" "$file"; then
                sed -i -E "s|${escaped_repo}@${escaped_current}([[:space:]]*#.*)?|${repo}@${hash}  # ${tag}|g" "$file"
                echo "Updated $repo in $(basename "$file"): ${current} -> ${hash} (${tag})"
                updated=$((updated + 1))
            fi
        done < <(find "$workflow_dir" -name '*.yml' -o -name '*.yaml')
    done

    if [[ $updated -eq 0 ]]; then
        echo "No updates needed."
    else
        echo ""
        echo "Updated $updated action reference(s). Review changes with: git diff"
    fi
fi
