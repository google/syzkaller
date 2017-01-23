# Copyright 2015 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

NOSTATIC ?= 0
ifeq ($(NOSTATIC), 0)
	STATIC_FLAG=-static
endif

.PHONY: all format clean manager fuzzer executor execprog mutate prog2c stress extract generate repro

all:
	$(MAKE) generate
	go install ./syz-manager ./syz-fuzzer
	$(MAKE) manager
	$(MAKE) fuzzer
	$(MAKE) execprog
	$(MAKE) executor

all-tools: execprog mutate prog2c stress repro upgrade

executor:
	$(CC) -o ./bin/syz-executor executor/executor.cc -pthread -Wall -O1 -g $(STATIC_FLAG) $(CFLAGS)

manager:
	go build -o ./bin/syz-manager github.com/google/syzkaller/syz-manager

fuzzer:
	go build -o ./bin/syz-fuzzer github.com/google/syzkaller/syz-fuzzer

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

extract: bin/syz-extract
	LINUX=$(LINUX) LINUXBLD=$(LINUXBLD) ./extract.sh
bin/syz-extract: syz-extract/*.go sysparser/*.go
	go build -o $@ ./syz-extract

generate: bin/syz-sysgen
	bin/syz-sysgen
bin/syz-sysgen: sysgen/*.go sysparser/*.go
	go build -o $@ ./sysgen

format:
	go fmt ./...
	clang-format --style=file -i executor/*.cc executor/*.h tools/kcovtrace/*.c

presubmit:
	$(MAKE) generate
	go generate ./...
	$(MAKE) format
	$(MAKE) executor
	ARCH=amd64 go install ./...
	ARCH=arm64 go install ./...
	ARCH=ppc64le go install ./...
	go test -short ./...
	echo LGTM

clean:
	rm -rf ./bin/
