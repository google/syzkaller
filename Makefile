# Copyright 2017 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

NOSTATIC ?= 0
ifeq ($(NOSTATIC), 0)
	STATIC_FLAG=-static
endif

.PHONY: all main tools \
	manager fuzzer executor \
	ci hub \
	execprog mutate prog2c stress repro upgrade db \
	bin/syz-sysgen bin/syz-extract bin/syz-fmt \
	extract generate \
	android \
	format tidy test arch cross-compile presubmit clean

all:
	$(MAKE) main
	$(MAKE) tools

main:
	go install ./syz-manager ./syz-fuzzer
	$(MAKE) manager
	$(MAKE) fuzzer
	$(MAKE) executor

tools: execprog mutate prog2c stress repro upgrade db

# executor uses stacks of limited size, so no jumbo frames.
executor:
	$(CC) -o ./bin/syz-executor executor/executor.cc -pthread -Wall -Wframe-larger-than=8192 -Wparentheses -Werror -O1 -g $(STATIC_FLAG) $(CFLAGS)

# Don't generate symbol table and DWARF debug info.
# Reduces build time and binary sizes considerably.
# That's only needed if you use gdb or nm.
# If you need that, build manually without these flags.
GOFLAGS="-ldflags=-s -w"

manager:
	go build $(GOFLAGS) -o ./bin/syz-manager github.com/google/syzkaller/syz-manager

fuzzer:
	go build $(GOFLAGS) -o ./bin/syz-fuzzer github.com/google/syzkaller/syz-fuzzer

execprog:
	go build $(GOFLAGS) -o ./bin/syz-execprog github.com/google/syzkaller/tools/syz-execprog

ci:
	go build $(GOFLAGS) -o ./bin/syz-ci github.com/google/syzkaller/syz-ci

hub:
	go build $(GOFLAGS) -o ./bin/syz-hub github.com/google/syzkaller/syz-hub

repro:
	go build $(GOFLAGS) -o ./bin/syz-repro github.com/google/syzkaller/tools/syz-repro

mutate:
	go build $(GOFLAGS) -o ./bin/syz-mutate github.com/google/syzkaller/tools/syz-mutate

prog2c:
	go build $(GOFLAGS) -o ./bin/syz-prog2c github.com/google/syzkaller/tools/syz-prog2c

stress:
	go build $(GOFLAGS) -o ./bin/syz-stress github.com/google/syzkaller/tools/syz-stress

db:
	go build $(GOFLAGS) -o ./bin/syz-db github.com/google/syzkaller/tools/syz-db

upgrade:
	go build $(GOFLAGS) -o ./bin/syz-upgrade github.com/google/syzkaller/tools/syz-upgrade

extract: bin/syz-extract
	LINUX=$(LINUX) LINUXBLD=$(LINUXBLD) ./sys/extract.sh
bin/syz-extract:
	go build $(GOFLAGS) -o $@ ./sys/syz-extract

generate: bin/syz-sysgen
	bin/syz-sysgen
	go generate ./pkg/csource ./executor ./pkg/ifuzz ./pkg/kernel
	$(MAKE) format
bin/syz-sysgen:
	go build $(GOFLAGS) -o $@ ./sys/syz-sysgen

format: bin/syz-fmt
	go fmt ./...
	clang-format --style=file -i executor/*.cc executor/*.h tools/kcovtrace/*.c
	bin/syz-fmt sys
bin/syz-fmt:
	go build $(GOFLAGS) -o $@ ./tools/syz-fmt

tidy:
	# A single check is enabled for now. But it's always fixable and proved to be useful.
	clang-tidy -quiet -header-filter=.* -checks=-*,misc-definitions-in-headers -warnings-as-errors=* executor/*.cc
	# Just check for compiler warnings.
	$(CC) executor/test_executor.cc -c -o /dev/null -Wparentheses -Wno-unused -Wall

test:
	go test -short ./...
	go test -short -race ./...

arch:
	GOOS=linux GOARCH=amd64 go install ./...
	GOOS=linux GOARCH=arm64 go install ./...
	GOOS=linux GOARCH=386 go install ./...
	GOOS=linux GOARCH=arm go install ./...
	GOOS=linux GOARCH=ppc64le go install ./...
	GOOS=darwin GOARCH=amd64 go build -o /dev/null ./syz-manager

presubmit:
	$(MAKE) generate
	$(MAKE) all
	$(MAKE) arch
	$(MAKE) test
	echo LGTM

clean:
	rm -rf ./bin/

cross-compile:
	# We could use arm-linux-gnueabihf-gcc from  g++-arm-linux-gnueabihf package,
	# but it is broken with "Error: alignment too large: 15 assumed"
	env CC="clang" CFLAGS="--target=linux-armv6 -mfloat-abi=hard" $(MAKE) executor

android: UNAME=$(shell uname | tr '[:upper:]' '[:lower:]')
android: ANDROID_ARCH=arm64
android: ANDROID_API=24
android: TOOLCHAIN=aarch64-linux-android
android:
	test -d $(NDK)
	$(MAKE) manager
	env GOOS=linux GOARCH=arm64 $(MAKE) execprog fuzzer
	env CC="$(NDK)/toolchains/$(TOOLCHAIN)-4.9/prebuilt/$(UNAME)-x86_64/bin/$(TOOLCHAIN)-g++" \
		CFLAGS="-I $(NDK)/sources/cxx-stl/llvm-libc++/include --sysroot=$(NDK)/platforms/android-$(ANDROID_API)/arch-$(ANDROID_ARCH) -O1 -g -Wall -static" \
		$(MAKE) executor
