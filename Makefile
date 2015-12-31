# Copyright 2015 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

.PHONY: all format clean manager fuzzer executor execprog mutate prog2c stress generate

all: manager fuzzer executor

all-tools: execprog mutate prog2c stress repro upgrade

manager:
	go build -o ./bin/syz-manager github.com/google/syzkaller/syz-manager

fuzzer:
	go build -o ./bin/syz-fuzzer github.com/google/syzkaller/syz-fuzzer

executor:
	$(CC) -o ./bin/syz-executor executor/executor.cc -lpthread -static -Wall -O1 -g $(CFLAGS)

execprog:
	go build -o ./bin/syz-execprog github.com/google/syzkaller/tools/syz-execprog

repro:
	go build -o ./bin/syz-repro github.com/google/syzkaller/tools/syz-repro

mutate:
	go build -o ./bin/syz-mutate github.com/google/syzkaller/tools/syz-mutate

prog2c:
	go build -o ./bin/syz-prog2c github.com/google/syzkaller/tools/syz-prog2c

stress:
	go build -o ./bin/syz-stress github.com/google/syzkaller/tools/syz-stress

upgrade:
	go build -o ./bin/syz-upgrade github.com/google/syzkaller/tools/syz-upgrade

generate:
	go run sysgen/*.go -linux=$(LINUX) sys/sys.txt sys/socket.txt sys/tty.txt sys/perf.txt \
		sys/key.txt sys/bpf.txt sys/fuse.txt sys/dri.txt sys/kdbus.txt sys/sctp.txt

format:
	go fmt ./...
	clang-format --style=file -i executor/executor.cc

clean:
	rm -rf ./bin/
