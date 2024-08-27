#!/usr/bin/env bash
# Copyright 2024 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

set -e # exit on any problem
set -o pipefail

db="coverage"
echo "drop table 'files' if exists"
gcloud spanner databases ddl update $db --instance=syzbot --project=syzkaller \
--ddl="DROP TABLE IF EXISTS files"
echo "create table 'files'"
create_table=$( echo -n '
CREATE TABLE
  files (
    "session" text,
    "filepath" text,
    "instrumented" bigint,
    "covered" bigint,
  PRIMARY KEY
    (session, filepath) );')
gcloud spanner databases ddl update $db --instance=syzbot --project=syzkaller \
 --ddl="$create_table"

echo "drop table 'merge_history' if exists"
gcloud spanner databases ddl update $db --instance=syzbot --project=syzkaller \
--ddl="DROP TABLE IF EXISTS merge_history"
echo "create table 'merge_history'"
create_table=$( echo -n '
CREATE TABLE
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

echo "drop table 'file_subsystems' if exists"
gcloud spanner databases ddl update $db --instance=syzbot --project=syzkaller \
--ddl="DROP TABLE IF EXISTS file_subsystems"
echo "create table 'file_subsystems'"
create_table=$( echo -n '
CREATE TABLE
  file_subsystems (
    "namespace" text,
    "filepath" text,
    "subsystems" text[],
  PRIMARY KEY
    (namespace, filepath) );')
gcloud spanner databases ddl update $db --instance=syzbot --project=syzkaller \
 --ddl="$create_table"
