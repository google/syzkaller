#!/bin/bash
# Copyright 2019 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# Helper script for working with fuzzit.dev
# https://github.com/fuzzitdev/example-go

set -eux

function target {
	go-fuzz-build -libfuzzer -func $3 -o fuzzer.a $2
	clang -fsanitize=fuzzer fuzzer.a -o fuzzer
	./fuzzit create job --type fuzzing --branch $TRAVIS_BRANCH --revision $TRAVIS_COMMIT $1 ./fuzzer
}

go get -u github.com/dvyukov/go-fuzz/go-fuzz-build
wget -q -O fuzzit https://github.com/fuzzitdev/fuzzit/releases/download/v1.2.7/fuzzit_Linux_x86_64
chmod a+x fuzzit
./fuzzit auth ${FUZZIT_API_KEY}

target QOmcj5QL4FVtUWV2UmhG ./prog/test FuzzDeserialize
target ddurE2yrDlqpklLYgNc6 ./prog/test FuzzParseLog
target 4A7DVc22Gni7tUtZBc19 ./pkg/compiler Fuzz
target YMCIxz61XkKWaB4jmiS5 ./pkg/report Fuzz
target 1d75bUDf9zNQz1HgHyM0 ./tools/syz-trace2syz/proggen Fuzz
