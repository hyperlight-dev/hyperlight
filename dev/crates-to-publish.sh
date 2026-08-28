#!/bin/bash
set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 VERSION CRATE..." >&2
    exit 1
fi

VERSION=$1
shift

response_file=$(mktemp)
trap 'rm -f "$response_file"' EXIT

for crate in "$@"; do
    crate_env_var=${crate^^}
    crate_env_var=${crate_env_var//-/_}

    if [ -z "$VERSION" ]; then
        echo "No version set (dry run?), skipping crates.io existence checks." >&2
        echo "PUBLISH_${crate_env_var}=true"
        continue
    fi

    if ! http_status=$(
        curl --silent --show-error \
            --user-agent 'hyperlight-release-workflow (https://github.com/hyperlight-dev/hyperlight)' \
            --retry 3 \
            --retry-all-errors \
            --connect-timeout 10 \
            --max-time 30 \
            --output "$response_file" \
            --write-out '%{http_code}' \
            "https://crates.io/api/v1/crates/$crate/$VERSION"
    ); then
        echo "Failed to query crates.io for $crate@$VERSION." >&2
        exit 1
    fi

    case "$http_status" in
        200)
            if ! jq -e --arg version "$VERSION" '.version.num == $version' "$response_file" > /dev/null; then
                echo "crates.io returned malformed or mismatched version data for $crate@$VERSION." >&2
                exit 1
            fi
            echo "PUBLISH_${crate_env_var}=false"
            echo "$crate@$VERSION already exists." >&2
            ;;
        404)
            echo "PUBLISH_${crate_env_var}=true"
            echo "$crate@$VERSION will be published." >&2
            ;;
        *)
            echo "crates.io returned HTTP $http_status for $crate@$VERSION." >&2
            exit 1
            ;;
    esac
done
