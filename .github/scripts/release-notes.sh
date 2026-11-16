#!/bin/sh
# Print the CHANGELOG.md section of one version, without its heading.
# Usage: release-notes.sh VERSION [CHANGELOG]
# Fails when the version has no (or an empty) section, so a release cannot be
# published with blank notes.
set -eu

version="${1:?usage: release-notes.sh VERSION [CHANGELOG]}"
changelog="${2:-CHANGELOG.md}"

notes=$(awk -v v="$version" '
  index($0, "## [" v "]") == 1 { found = 1; next }
  found && /^## \[/ { exit }
  found && /^\[[^]]+\]: / { exit }
  found { print }
' "$changelog")

if ! printf '%s' "$notes" | grep -q '[^[:space:]]'; then
  echo "$changelog has no section for ${version}; add '## [${version}] - <date>' before tagging" >&2
  exit 1
fi
printf '%s\n' "$notes"
