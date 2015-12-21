# Copyright 2015 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

.PHONY: all format clean manager fuzzer executor execprog mutate prog2c stress

all: manager fuzzer executor

all-tools: execprog mutate prog2c stress

manager:
	go build -o ./bin/syz-manager github.com/google/syzkaller/syz-manager

fuzzer:
	go build -o ./bin/syz-fuzzer github.com/google/syzkaller/syz-fuzzer

executor:
	gcc -o ./bin/syz-executor executor/executor.cc -lpthread -static -Wall -O1 -g

execprog:
	go build -o ./bin/syz-execprog github.com/google/syzkaller/tools/syz-execprog

mutate:
	go build -o ./bin/syz-mutate github.com/google/syzkaller/tools/syz-mutate

prog2c:
	go build -o ./bin/syz-prog2c github.com/google/syzkaller/tools/syz-prog2c

stress:
	go build -o ./bin/syz-stress github.com/google/syzkaller/tools/syz-stress

format:
	go fmt ./...
	clang-format --style=file -i executor/executor.cc

clean:
	rm -rf ./bin/
