#!/usr/bin/env bash
# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

set -e # exit on any problem
set -o pipefail

while getopts w:d:t:n:r:b: option
do
    case "${option}"
        in
        w)workdir=${OPTARG};;
        d)duration=${OPTARG};;
        t)to_date=${OPTARG};;
        n)namespace=${OPTARG};;
        r)repo=${OPTARG};;
        b)branch=${OPTARG};;
    esac
done

if [ -z "$workdir" ]
then
  echo "-w is requires to specify workdir"
  exit
fi
if [ -z "$to_date" ]
then
  echo "-t is required to specify to_date"
  exit
fi
if [ -z "$duration" ]
then
  echo "-d is required to specify duration"
  exit
fi
if [ -z "$namespace" ]
then
  echo "-n is required to specify namespace"
  exit
fi
if [ -z "$repo" ]
then
  echo "-r is required to specify the merging repo base"
  exit
fi
if [ -z "$branch" ]
then
  echo "-b is required to specify the merging branch base"
  exit
fi

# it also allows to early check gcloud credentials
echo "making sure spanner table 'files' exists"
create_table=$( echo -n '
CREATE TABLE IF NOT EXISTS
  files (
    "namespace" text,
    "repo" text,
    "commit" text,
    "filepath" text,
    "duration" bigint,
    "dateto" date,
    "instrumented" bigint,
    "covered" bigint,
  PRIMARY KEY
    (duration, dateto, commit, filepath) );')
gcloud spanner databases ddl update coverage --instance=syzbot --project=syzkaller \
 --ddl="$create_table"

echo "making sure spanner table 'merge_history' exists"
create_table=$( echo -n '
CREATE TABLE IF NOT EXISTS
  merge_history (
    "namespace" text,
    "repo" text,
    "commit" text,
    "duration" bigint,
    "dateto" date,
    "totalrows" bigint,
  PRIMARY KEY
    (duration, dateto, commit) );')
gcloud spanner databases ddl update coverage --instance=syzbot --project=syzkaller \
 --ddl="$create_table"

echo "Workdir: $workdir"
base_dir="${workdir}repos/linux_kernels"
if [ ! -d $base_dir ]; then
  echo "base dir doesn't exist, cloning"
  git clone $repo $base_dir
fi
cd $base_dir
remote=$(git remote -v | grep $repo | head -n1 | awk '{print $1;}')
git checkout $remote/$branch
cd -

# get the last merged commit at to_date
# sometimes many commits have same time and are shuffled
base_commit=$(git --git-dir=${base_dir}/.git log --date=iso-local --before ${to_date}T23:59:59 --pretty=format:"%cd %H" -1000 | \
  sort -rn | { head -1; cat >/dev/null; } | rev | cut -d' ' -f1 | rev)
if [ -z "$base_commit" ]
then
  echo FAILED to get the base merging commit.
  exit
fi
echo The latest commit as of $to_date is $base_commit.

from_date=$(date -d "$to_date - $duration days" +%Y-%m-%d)
# every partition covers 1 day
query=$(cat <<-END
SELECT
  sum(total_rows) as total_rows,
FROM
  syzkaller.syzbot_coverage.INFORMATION_SCHEMA.PARTITIONS
WHERE
  table_name = '${namespace}' AND
  PARSE_DATE('%Y%m%d', partition_id) >= '${from_date}' AND
  PARSE_DATE('%Y%m%d', partition_id) <= '${to_date}';
END
)

total_rows=$(bq query --format=csv --use_legacy_sql=false "$query" | tail -n +2)
if (( total_rows <= 0 ))
then
  echo error: no source rows in bigquery available
  exit
else
  echo $total_rows rows are available for processing
fi

sessionID=$(cat /proc/sys/kernel/random/uuid)
gsURI=$(echo gs://syzbot-temp/bq-exports/${sessionID}/*.csv.gz)
echo fetching data from bigquery
query=$( echo -n '
EXPORT DATA
  OPTIONS (
    uri = "'$gsURI'",
    format = "CSV",
    overwrite = true,
    header = true,
    compression = "GZIP")
AS (
  SELECT
    kernel_repo, kernel_branch, kernel_commit, file_path, sl, SUM(hit_count) as hit_count
  FROM syzkaller.syzbot_coverage.'$namespace'
  WHERE
    TIMESTAMP_TRUNC(timestamp, DAY) >= "'$from_date'" AND
    TIMESTAMP_TRUNC(timestamp, DAY) <= "'$to_date'" AND
    version = 1
  GROUP BY file_path, kernel_commit, kernel_repo, kernel_branch, sl
  ORDER BY file_path
);
')

bq query --format=csv --use_legacy_sql=false "$query"
sessionDir="$workdir/sessions/$sessionID"
mkdir -p $sessionDir
gsutil -m cp $gsURI $sessionDir
cat $sessionDir/*.csv.gz | gunzip | \
go run ./tools/syz-covermerger/ -workdir $workdir \
  -repo $repo \
  -branch $branch \
  -commit $base_commit \
  -save-to-spanner true \
  -namespace $namespace \
  -duration $duration \
  -date-to $to_date \
  -total-rows $total_rows

echo Cleanup
rm -rf $sessionDir
