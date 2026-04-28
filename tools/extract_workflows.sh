#!/usr/bin/env bash
# Copyright 2026 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

set -e

URL="$1"
COMMIT="$2"
OUTPUT_DIR="$3"

if [ -z "$URL" ] || [ -z "$COMMIT" ]; then
  echo "Usage: $0 <dashboard_ai_url> <commit> [output_dir]"
  exit 1
fi

if [ -z "$OUTPUT_DIR" ]; then
  OUTPUT_DIR="extracted_workflows"
fi

# Get commit date timestamp
COMMIT_DATE=$(git log -1 --format=%ct "$COMMIT")

CURL_OPTS=(-s -A "")
if [ -n "$ACCESS_TOKEN" ]; then
  CURL_OPTS+=(-H "Authorization: Bearer $ACCESS_TOKEN")
fi

echo "Fetching job list from $URL..."
if [[ "$URL" == *"?"* ]]; then
  LIST_URL="${URL}&json=1"
else
  LIST_URL="${URL}?json=1"
fi

DATA=$(curl "${CURL_OPTS[@]}" "$LIST_URL")

BASE_URL=$(echo "$URL" | grep -oE '^https?://[^/]+')

echo "Processing jobs..."

# Extract jobs info in TSV format: ID, Workflow, Created, CodeRevision
# Filter to only include finished workflows (Finished time is not the zero value)
printf "%s\n" "$DATA" | jq -r '.Jobs[] | select(.Finished != "0001-01-01T00:00:00Z") | "\(.ID)\t\(.Workflow)\t\(.Created)\t\(.CodeRevision)"' | while IFS=$'\t' read -r ID WORKFLOW CREATED REVISION; do
  if [ -z "$ID" ] || [ "$ID" == "null" ]; then
    continue
  fi

  # Convert created time to timestamp
  JOB_DATE=$(date -d "$CREATED" +%s)

  # Filter by date or exact commit match
  if [ "$JOB_DATE" -lt "$COMMIT_DATE" ] && [ "$REVISION" != "$COMMIT" ]; then
    continue
  fi

  echo "Fetching details for job $ID..."
  DETAIL_URL="${BASE_URL}/ai_job?id=${ID}&json=1"

  TARGET_DIR="${OUTPUT_DIR}/${WORKFLOW}"
  mkdir -p "$TARGET_DIR"

  FILE_PATH="${TARGET_DIR}/${ID}.json"

  # Fetch and save
  curl "${CURL_OPTS[@]}" "$DETAIL_URL" > "$FILE_PATH"
done

echo "Extraction complete."
