# Copyright 2015 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

.PHONY: all bin format clean master manager fuzzer executor

all: master manager fuzzer executor

bin:
	mkdir -p bin

master: bin
	go build -o ./bin/master github.com/google/syzkaller/master

manager: bin
	go build -o ./bin/manager github.com/google/syzkaller/manager

fuzzer: bin
	go build -o ./bin/fuzzer github.com/google/syzkaller/fuzzer

executor: bin
	gcc executor/executor.cc -o ./bin/executor -lpthread -static -Wall -O1 -g

format:
	find . -name "*.go" | xargs -n 1 go fmt
	clang-format --style=file -i executor/executor.cc

clean:
	rm -rf ./bin/
