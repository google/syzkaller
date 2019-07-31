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

target gD3t0a6kniec9zst4eqU ./prog/test FuzzDeserialize
target aWERkQry8i44A4gToF5W ./prog/test FuzzParseLog
target UJuwHm2dT3YWlWH88yyA ./pkg/compiler Fuzz
target ZkAE6RkbUOP7V3cCbQ74 ./pkg/report Fuzz
target s4Mxhb8MBZaWZkGS40SF ./tools/syz-trace2syz/proggen Fuzz
