# Copyright 2017 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# There are 4 OS/arch pairs:
#  - BUILDOS/BUILDARCH: the current machine's pair used for build.
#  - HOSTOS/HOSTARCH: pair where syz-manager will run.
#  - TARGETOS/TARGETVMARCH: pair of the target OS under test.
#  - TARGETOS/TARGETARCH: pair of the target test process.
#
# The last 2 differ for e.g. amd64 OS and 386 test processes (compat syscall testing).
# All pairs default to the current machine. All but BUILD can be overriden.
#
# For example, to test linux/amd64 on linux/amd64, you just run:
#    make
# To test linux/arm64 from darwin/amd64 host, run:
#    make HOSTOS=darwin HOSTARCH=amd64 TARGETOS=linux TARGETARCH=arm64
# To test x86 compat syscalls, run:
#    make TARGETVMARCH=amd64 TARGETARCH=386
#
# There is a special case for Android builds:
#    NDK=/path/to/android/ndk make TARGETOS=android TARGETARCH=arm64
# But you still need to specify "target": "linux/arm64" in syz-manager config.

BUILDOS := $(shell go env GOOS)
BUILDARCH := $(shell go env GOARCH)
HOSTOS ?= $(BUILDOS)
HOSTARCH ?= $(BUILDARCH)
TARGETOS ?= $(HOSTOS)
TARGETARCH ?= $(HOSTARCH)
TARGETVMARCH ?= $(TARGETARCH)
EXTRACTOS := $(TARGETOS)
GO := go
EXE :=

ifeq ("$(TARGETARCH)", "amd64")
	CC = "x86_64-linux-gnu-gcc"
else ifeq ("$(TARGETARCH)", "386")
	CC = "x86_64-linux-gnu-gcc"
	ADDCFLAGS = "-m32"
else ifeq ("$(TARGETARCH)", "arm64")
	CC = "aarch64-linux-gnu-gcc"
else ifeq ("$(TARGETARCH)", "arm")
	CC = "arm-linux-gnueabihf-gcc"
	ADDCFLAGS = "-march=armv6t2"
else ifeq ("$(TARGETARCH)", "ppc64le")
	CC = "powerpc64le-linux-gnu-gcc"
endif

ifeq ("$(TARGETOS)", "android")
	EXTRACTOS = android
	override TARGETOS = linux
	ANDROID_API = 24
	BUILDGCCARCH = ""
	ANDROIDARCH = ""
	TOOLCHAIN = ""
	GCCBIN = ""
	ifeq ("$(TARGETARCH)", "amd64")
		ANDROIDARCH = "x86_64"
		TOOLCHAIN = "x86_64-4.9"
		GCCBIN = "x86_64-linux-android-g++"
	else ifeq ("$(TARGETARCH)", "386")
		ANDROIDARCH = "x86"
		TOOLCHAIN = "x86-4.9"
		GCCBIN = "i686-linux-android-g++"
	else ifeq ("$(TARGETARCH)", "arm64")
		ANDROIDARCH = "arm64"
		TOOLCHAIN = "aarch64-linux-android-4.9"
		GCCBIN = "aarch64-linux-android-g++"
	else ifeq ("$(TARGETARCH)", "arm")
		ANDROIDARCH = "arm"
		TOOLCHAIN = "arm-linux-androideabi-4.9"
		GCCBIN = "arm-linux-androideabi-g++"
	endif
	ifeq ("$(BUILDARCH)", "amd64")
		BUILDGCCARCH = "x86_64"
	else ifeq ("$(BUILDARCH)", "arm64")
		BUILDGCCARCH = "aarch64"
	endif
	CC = $(NDK)/toolchains/$(TOOLCHAIN)/prebuilt/$(BUILDOS)-$(BUILDGCCARCH)/bin/$(GCCBIN)
	CFLAGS = -I $(NDK)/sources/cxx-stl/llvm-libc++/include --sysroot=$(NDK)/platforms/android-$(ANDROID_API)/arch-$(ANDROIDARCH) -static
endif

ifeq ("$(TARGETOS)", "fuchsia")
	# SOURCEDIR should point to fuchsia checkout.
	GO = $(SOURCEDIR)/buildtools/go
	CC = $(SOURCEDIR)/buildtools/linux-x64/clang/bin/clang++
	export CGO_ENABLED=1
	NOSTATIC = 1
	ifeq ("$(TARGETARCH)", "amd64")
		ADDCFLAGS = --target=x86_64-fuchsia -lfdio -lzircon --sysroot $(SOURCEDIR)/out/build-zircon/build-zircon-pc-x86-64/sysroot -I $(SOURCEDIR)/out/build-zircon/build-zircon-pc-x86-64
	else ifeq ("$(TARGETARCH)", "arm64")
		ADDCFLAGS = --target=aarch64-fuchsia -lfdio -lzircon --sysroot $(SOURCEDIR)/out/build-zircon/build-zircon-pc-arm64/sysroot -I $(SOURCEDIR)/out/build-zircon/build-zircon-pc-arm64
	endif
endif

ifeq ("$(TARGETOS)", "akaros")
	# SOURCEDIR should point to bootstrapped akaros checkout.
	# There is no up-to-date Go for akaros, so building Go will fail.
	CC = $(SOURCEDIR)/install/x86_64-ucb-akaros-gcc/bin/x86_64-ucb-akaros-g++
	# Most likely this is incorrect (why doesn't it know own sysroot?), but worked for me.
	ADDCFLAGS = -I $(SOURCEDIR)/tools/compilers/gcc-glibc/x86_64-ucb-akaros-gcc-stage3-builddir/x86_64-ucb-akaros/libstdc++-v3/include/x86_64-ucb-akaros -I $(SOURCEDIR)/tools/compilers/gcc-glibc/x86_64-ucb-akaros-gcc-stage3-builddir/x86_64-ucb-akaros/libstdc++-v3/include -I $(SOURCEDIR)/tools/compilers/gcc-glibc/gcc-4.9.2/libstdc++-v3/libsupc++ -L $(SOURCEDIR)/tools/compilers/gcc-glibc/x86_64-ucb-akaros-gcc-stage3-builddir/x86_64-ucb-akaros/libstdc++-v3/src/.libs
endif

ifeq ("$(TARGETOS)", "windows")
	EXE = .exe
endif

GITREV=$(shell git rev-parse HEAD)
ifeq ($(`git diff --shortstat`), "")
	REV=$(GITREV)
else
	REV=$(GITREV)+
endif

NOSTATIC ?= 0
ifeq ($(NOSTATIC), 0)
	ADDCFLAGS += -static
endif

# Don't generate symbol table and DWARF debug info.
# Reduces build time and binary sizes considerably.
# That's only needed if you use gdb or nm.
# If you need that, build manually without these flags.
GOFLAGS := "-ldflags=-s -w -X github.com/google/syzkaller/sys.GitRevision=$(REV)"
ifneq ("$(GOTAGS)", "")
	GOFLAGS += "-tags=$(GOTAGS)"
endif

.PHONY: all host target \
	manager fuzzer executor \
	ci hub \
	execprog mutate prog2c stress repro upgrade db \
	bin/syz-sysgen bin/syz-extract bin/syz-fmt \
	extract generate \
	format tidy test check_links arch presubmit clean

all: host target

host:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) install ./syz-manager
	$(MAKE) manager repro mutate prog2c db upgrade

target:
	GOOS=$(TARGETOS) GOARCH=$(TARGETVMARCH) $(GO) install ./syz-fuzzer
	$(MAKE) fuzzer execprog stress executor

# executor uses stacks of limited size, so no jumbo frames.
executor:
	mkdir -p ./bin/$(TARGETOS)_$(TARGETARCH)
	$(CC) -o ./bin/$(TARGETOS)_$(TARGETARCH)/syz-executor$(EXE) executor/executor_$(TARGETOS).cc \
		-pthread -Wall -Wframe-larger-than=8192 -Wparentheses -Werror -O1 \
		$(ADDCFLAGS) $(CFLAGS) -DGOOS=\"$(TARGETOS)\" -DGIT_REVISION=\"$(REV)\"

manager:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) build $(GOFLAGS) -o ./bin/syz-manager github.com/google/syzkaller/syz-manager

fuzzer:
	GOOS=$(TARGETOS) GOARCH=$(TARGETVMARCH) $(GO) build $(GOFLAGS) -o ./bin/$(TARGETOS)_$(TARGETVMARCH)/syz-fuzzer$(EXE) github.com/google/syzkaller/syz-fuzzer

execprog:
	GOOS=$(TARGETOS) GOARCH=$(TARGETVMARCH) $(GO) build $(GOFLAGS) -o ./bin/$(TARGETOS)_$(TARGETVMARCH)/syz-execprog$(EXE) github.com/google/syzkaller/tools/syz-execprog

ci:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) build $(GOFLAGS) -o ./bin/syz-ci github.com/google/syzkaller/syz-ci

hub:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) build $(GOFLAGS) -o ./bin/syz-hub github.com/google/syzkaller/syz-hub

repro:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) build $(GOFLAGS) -o ./bin/syz-repro github.com/google/syzkaller/tools/syz-repro

mutate:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) build $(GOFLAGS) -o ./bin/syz-mutate github.com/google/syzkaller/tools/syz-mutate

prog2c:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) build $(GOFLAGS) -o ./bin/syz-prog2c github.com/google/syzkaller/tools/syz-prog2c

stress:
	GOOS=$(TARGETOS) GOARCH=$(TARGETVMARCH) $(GO) build $(GOFLAGS) -o ./bin/$(TARGETOS)_$(TARGETVMARCH)/syz-stress$(EXE) github.com/google/syzkaller/tools/syz-stress

db:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) build $(GOFLAGS) -o ./bin/syz-db github.com/google/syzkaller/tools/syz-db

upgrade:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) build $(GOFLAGS) -o ./bin/syz-upgrade github.com/google/syzkaller/tools/syz-upgrade

extract: bin/syz-extract
	bin/syz-extract -build -os=$(EXTRACTOS) -sourcedir=$(SOURCEDIR)
bin/syz-extract:
	$(GO) build $(GOFLAGS) -o $@ ./sys/syz-extract

generate: bin/syz-sysgen
	bin/syz-sysgen
	$(GO) generate ./pkg/csource ./executor ./pkg/ifuzz ./pkg/kernel
	$(MAKE) format
bin/syz-sysgen:
	$(GO) build $(GOFLAGS) -o $@ ./sys/syz-sysgen

format: bin/syz-fmt
	$(GO) fmt ./...
	clang-format --style=file -i executor/*.cc executor/*.h tools/kcovtrace/*.c
	bin/syz-fmt sys/akaros
	bin/syz-fmt sys/freebsd
	bin/syz-fmt sys/netbsd
	bin/syz-fmt sys/linux
	bin/syz-fmt sys/fuchsia
	bin/syz-fmt sys/windows
bin/syz-fmt:
	$(GO) build $(GOFLAGS) -o $@ ./tools/syz-fmt

tidy:
	# A single check is enabled for now. But it's always fixable and proved to be useful.
	clang-tidy -quiet -header-filter=.* -checks=-*,misc-definitions-in-headers -warnings-as-errors=* executor/*.cc
	# Just check for compiler warnings.
	$(CC) executor/test_executor.cc -c -o /dev/null -Wparentheses -Wno-unused -Wall

test:
	$(GO) test -short ./...
	$(GO) test -short -race ./...

arch:
	env GOOG=darwin GOARCH=amd64 go install github.com/google/syzkaller/syz-manager
	env HOSTOS=darwin HOSTARCH=amd64 $(MAKE) host
	env GOOG=linux GOARCH=amd64 go install github.com/google/syzkaller/syz-manager
	env HOSTOS=linux HOSTARCH=amd64 $(MAKE) host
	env GOOG=linux GOARCH=amd64 go install github.com/google/syzkaller/syz-fuzzer
	env TARGETOS=linux TARGETARCH=amd64 $(MAKE) target
	env GOOG=linux GOARCH=arm64 go install github.com/google/syzkaller/syz-fuzzer
	env TARGETOS=linux TARGETARCH=arm64 $(MAKE) target
	env GOOG=linux GOARCH=ppc64le go install github.com/google/syzkaller/syz-fuzzer
	env TARGETOS=linux TARGETARCH=ppc64le $(MAKE) target
	# executor build on arm fails with:
	# Error: alignment too large: 15 assumed
	env GOOG=linux GOARCH=arm64 go install github.com/google/syzkaller/syz-fuzzer
	env TARGETOS=linux TARGETARCH=arm64 TARGETVMARCH=arm $(MAKE) target
	# executor build on 386 on travis fails with:
	# fatal error: asm/errno.h: No such file or directory
	# We install a bunch of additional packages in .travis.yml,
	# but I can't guess the right one.
	env GOOG=linux GOARCH=386 go install github.com/google/syzkaller/syz-fuzzer
	env TARGETOS=linux TARGETARCH=amd64 TARGETVMARCH=386 $(MAKE) target
	env GOOG=windows go install github.com/google/syzkaller/syz-fuzzer
	env TARGETOS=windows TARGETARCH=amd64 $(MAKE) fuzzer execprog stress
	env GOOG=freebsd go install github.com/google/syzkaller/syz-fuzzer
	env TARGETOS=freebsd TARGETARCH=amd64 $(MAKE) target
	env GOOG=netbsd go install github.com/google/syzkaller/syz-fuzzer
	env TARGETOS=netbsd TARGETARCH=amd64 $(MAKE) target

presubmit:
	$(MAKE) check_links
	$(MAKE) generate
	$(MAKE) all
	$(MAKE) arch
	$(MAKE) test
	echo LGTM

clean:
	rm -rf ./bin/

# For a tupical Ubuntu/Debian distribution, requires sudo.
install_prerequisites:
	apt-get install libc6-dev-i386 lib32stdc++-4.8-dev linux-libc-dev g++-aarch64-linux-gnu g++-powerpc64le-linux-gnu g++-arm-linux-gnueabihf

check_links:
	python ./tools/check_links.py $$(pwd) $$(ls ./*.md; find ./docs/ -name '*.md')
