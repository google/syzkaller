#!/usr/bin/env bash
# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

set -e # exit on any problem
set -o pipefail

db="coverage"
echo "making sure spanner table 'files' exists"
create_table=$( echo -n '
CREATE TABLE IF NOT EXISTS
  files (
    "session" text,
    "filepath" text,
    "instrumented" bigint,
    "covered" bigint,
  PRIMARY KEY
    (session, filepath) );')
gcloud spanner databases ddl update $db --instance=syzbot --project=syzkaller \
 --ddl="$create_table"

echo "making sure spanner table 'merge_history' exists"
create_table=$( echo -n '
CREATE TABLE IF NOT EXISTS
  merge_history (
    "namespace" text,
    "repo" text,
    "duration" bigint,
    "dateto" date,
    "session" text,
    "time" timestamptz,
    "commit" text,
    "totalrows" bigint,
  PRIMARY KEY
    (namespace, repo, duration, dateto) );')
gcloud spanner databases ddl update $db --instance=syzbot --project=syzkaller \
 --ddl="$create_table"

echo "making sure spanner table 'file_subsystems' exists"
create_table=$( echo -n '
CREATE TABLE IF NOT EXISTS
  file_subsystems (
    "namespace" text,
    "filepath" text,
    "subsystems" text[],
  PRIMARY KEY
    (namespace, filepath) );')
gcloud spanner databases ddl update $db --instance=syzbot --project=syzkaller \
 --ddl="$create_table"
