#!/bin/bash
# Copyright 2019 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.


# Helper script for working with fuzzit.dev
# https://github.com/fuzzitdev/example-go

set -eux
export TYPE="${1}"

function target {
	go-fuzz-build -libfuzzer -func $3 -o fuzzer.a $2
	clang -fsanitize=fuzzer fuzzer.a -o fuzzer
	./fuzzit create job --type "${TYPE}" --branch $TRAVIS_BRANCH --revision $TRAVIS_COMMIT syzkaller/$1 ./fuzzer
}

go get -u github.com/dvyukov/go-fuzz/go-fuzz-build
wget -q -O fuzzit https://github.com/fuzzitdev/fuzzit/releases/download/v2.4.46/fuzzit_Linux_x86_64
chmod a+x fuzzit

target syzkaller-prog-deserialize ./prog/test FuzzDeserialize
target syzkaller-prog-parselog ./prog/test FuzzParseLog
target syzkaller-compiler ./pkg/compiler Fuzz
target syzkaller-report ./pkg/report Fuzz
target syzkaller-trace2syz ./tools/syz-trace2syz/proggen Fuzz
