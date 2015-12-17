# Copyright 2015 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

.PHONY: all format clean master manager fuzzer executor

all: manager fuzzer executor

manager:
	go build -o ./bin/syz-manager github.com/google/syzkaller/syz-manager

fuzzer:
	go build -o ./bin/syz-fuzzer github.com/google/syzkaller/syz-fuzzer

executor:
	gcc -o ./bin/syz-executor executor/executor.cc -lpthread -static -Wall -O1 -g

format:
	go fmt ./...
	clang-format --style=file -i executor/executor.cc

clean:
	rm -rf ./bin/
