#!/usr/bin/env bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
set -e

LABEL_NAME="well-shaped"
STALE_LABEL_NAME="stale"

echo "Fetching open pull requests..."
# Get open PRs, filter out drafts and PRs with the "stale" label using jq
prs=$(gh pr list --limit 1000 --json number,isDraft,labels | jq -c --arg stale_label "${STALE_LABEL_NAME}" '
  [.[] | select((.isDraft | not) and (any(.labels[]?; .name == $stale_label) | not))]
')

count=$(echo "${prs}" | jq '. | length')
echo "Found ${count} open, ready-to-review pull requests (excluding stale ones) to analyze."

if [ "${count}" -eq 0 ]; then
  exit 0
fi

# Loop through each pull request
echo "${prs}" | jq -c '.[]' | while read -r row; do
  number=$(echo "${row}" | jq -r '.number')
  echo ""
  echo "Analyzing PR #${number}..."

  # Fetch PR details including existing labels, reviews and commits
  detail=$(gh pr view "${number}" --json title,mergeable,labels,reviews,commits)
  title=$(echo "${detail}" | jq -r '.title')
  mergeable=$(echo "${detail}" | jq -r '.mergeable')

  # Check if the well-shaped label is currently applied
  has_label=$(echo "${detail}" | jq -r --arg label "${LABEL_NAME}" '.labels[]?.name | select(. == $label)' | wc -l)

  reasons=()

  # Check for merge conflicts
  if [ "${mergeable}" = "CONFLICTING" ]; then
    reasons+=("Merge conflict detected")
  fi

  # Check CI status using gh pr checks CLI command directly
  set +e
  gh pr checks "${number}" > /dev/null 2>&1
  checks_status=$?
  set -e

  if [ "${checks_status}" -ne 0 ]; then
    reasons+=("CI checks have not passed successfully (status: ${checks_status})")
  fi

  # Check if changes were requested and not addressed by a subsequent commit
  unaddressed_changes_requested=$(echo "${detail}" | jq -r '
    ([(.reviews // [])[] | select(.state == "CHANGES_REQUESTED") | .submittedAt] | max) as $latest_cr
    | ([(.commits // [])[] | .authoredDate] | max) as $latest_commit
    | if ($latest_cr != null) and ($latest_cr > $latest_commit) then
        "true"
      else
        "false"
      end
  ')

  if [ "${unaddressed_changes_requested}" = "true" ]; then
    reasons+=("Changes were requested by a reviewer and no new commits have been pushed since")
  fi

  if [ ${#reasons[@]} -ne 0 ]; then
    echo "PR #${number} ('${title}') has problems:"
    for reason in "${reasons[@]}"; do
      echo "  - ${reason}"
    done

    if [ "${has_label}" -gt 0 ]; then
      echo "Removing label '${LABEL_NAME}' from PR #${number}..."
      if gh pr edit "${number}" --remove-label "${LABEL_NAME}"; then
        echo "Successfully removed label '${LABEL_NAME}'."
      else
        echo "Failed to remove label '${LABEL_NAME}'."
      fi
    else
      echo "PR #${number} does not have label '${LABEL_NAME}'. No action needed."
    fi
  else
    echo "PR #${number} ('${title}') is ready (no conflicts, no failing checks)."
    if [ "${has_label}" -eq 0 ]; then
      echo "Adding label '${LABEL_NAME}' to PR #${number}..."
      if gh pr edit "${number}" --add-label "${LABEL_NAME}"; then
        echo "Successfully added label '${LABEL_NAME}'."
      else
        echo "Failed to add label '${LABEL_NAME}'."
      fi
    else
      echo "PR #${number} already has label '${LABEL_NAME}'. No action needed."
    fi
  fi
done
