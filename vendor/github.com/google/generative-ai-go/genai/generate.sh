#!/bin/sh
# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

version=$(awk '$1 == "cloud.google.com/go/ai" {print $2}' ../go.mod)

if [[ $version = '' ]]; then
  echo >&2 "could not get version of cloud.google.com/go/ai from ../go.mod"
  exit 1
fi

dir=~/go/pkg/mod/cloud.google.com/go/ai@$version/generativelanguage/apiv1beta/generativelanguagepb

if [[ ! -d $dir ]]; then
  echo >&2 "$dir does not exist or is not a directory"
  exit 1
fi

echo "generating from $dir"
protoveneer -license license.txt config.yaml $dir

