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
# There is one special case for extracting constants for Android
# (you don't need this unless you update system call descriptions):
#    make extract TARGETOS=android SOURCEDIR=/path/to/android/checkout

BUILDOS := $(shell go env GOOS)
BUILDARCH := $(shell go env GOARCH)
HOSTOS ?= $(BUILDOS)
HOSTARCH ?= $(BUILDARCH)
TARGETOS ?= $(HOSTOS)
TARGETARCH ?= $(HOSTARCH)
TARGETVMARCH ?= $(TARGETARCH)
GO := go
EXE :=

ifeq ("$(BUILDOS)", "linux")
	NCORES ?= $(shell grep -c "vendor_id" /proc/cpuinfo)
	MAKEFLAGS += " -j$(NCORES) "
endif

ifeq ("$(TARGETARCH)", "amd64")
	CC = "x86_64-linux-gnu-gcc"
else ifeq ("$(TARGETARCH)", "386")
ifeq ("$(BUILDARCH)", "386")
	CC = "i686-linux-gnu-gcc"
else
	CC = "x86_64-linux-gnu-gcc"
endif
	ADDCFLAGS = "-m32"
else ifeq ("$(TARGETARCH)", "arm64")
	CC = "aarch64-linux-gnu-gcc"
else ifeq ("$(TARGETARCH)", "arm")
	CC = "arm-linux-gnueabihf-gcc"
	ADDCFLAGS = "-march=armv6t2"
else ifeq ("$(TARGETARCH)", "ppc64le")
	CC = "powerpc64le-linux-gnu-gcc"
endif

# By default, build all Go binaries as static. We don't need cgo and it is
# known to cause problems at least on Android emulator.
export CGO_ENABLED=0

ifeq ("$(TARGETOS)", "fuchsia")
	# SOURCEDIR should point to fuchsia checkout.
	GO = $(SOURCEDIR)/buildtools/go
	CC = $(SOURCEDIR)/buildtools/linux-x64/clang/bin/clang++
	export CGO_ENABLED=1
	NOSTATIC = 1
	ifeq ("$(TARGETARCH)", "amd64")
		ADDCFLAGS = --target=x86_64-fuchsia -lfdio -lzircon --sysroot $(SOURCEDIR)/out/build-zircon/build-x64/sysroot
		export GOROOT=$(SOURCEDIR)/out/debug-x64/goroot
		# Required by the goroot.
		export ZIRCON_BUILD_DIR=$(SOURCEDIR)/out/build-zircon/build-x64
	else ifeq ("$(TARGETARCH)", "arm64")
		ADDCFLAGS = --target=aarch64-fuchsia -lfdio -lzircon --sysroot $(SOURCEDIR)/out/build-zircon/build-arm64/sysroot
		export GOROOT=$(SOURCEDIR)/out/debug-arm64/goroot
		# Required by the goroot.
		export ZIRCON_BUILD_DIR=$(SOURCEDIR)/out/build-zircon/build-arm64
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
ifeq ("$(shell git diff --shortstat)", "")
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
	execprog mutate prog2c stress repro upgrade db parse \
	bin/syz-sysgen bin/syz-extract bin/syz-fmt \
	extract generate generate_go generate_sys \
	format format_go format_cpp format_sys \
	tidy test test_race check_links check_diff \
	arch arch_darwin_amd64_host arch_linux_amd64_host \
	arch_freebsd_amd64_host arch_netbsd_amd64_host \
	arch_linux_amd64_target arch_linux_386_target \
	arch_linux_arm64_target arch_linux_arm_target arch_linux_ppc64le_target \
	arch_freebsd_amd64_target arch_netbsd_amd64_target arch_windows_amd64_target \
	presubmit presubmit_parallel clean

all: host target

host:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) install ./syz-manager
	$(MAKE) manager repro mutate prog2c db parse upgrade

target:
	GOOS=$(TARGETOS) GOARCH=$(TARGETVMARCH) $(GO) install ./syz-fuzzer
	$(MAKE) fuzzer execprog stress executor

# executor uses stacks of limited size, so no jumbo frames.
executor:
	mkdir -p ./bin/$(TARGETOS)_$(TARGETARCH)
	$(CC) -o ./bin/$(TARGETOS)_$(TARGETARCH)/syz-executor$(EXE) executor/executor_$(TARGETOS).cc \
		-pthread -Wall -Wframe-larger-than=8192 -Wparentheses -Werror -O2 \
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

parse:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) build $(GOFLAGS) -o ./bin/syz-parse github.com/google/syzkaller/tools/syz-parse

upgrade:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(GO) build $(GOFLAGS) -o ./bin/syz-upgrade github.com/google/syzkaller/tools/syz-upgrade

extract: bin/syz-extract
	bin/syz-extract -build -os=$(TARGETOS) -sourcedir=$(SOURCEDIR) $(FILES)
bin/syz-extract:
	$(GO) build $(GOFLAGS) -o $@ ./sys/syz-extract

generate: generate_go generate_sys
	$(MAKE) format

generate_go: bin/syz-sysgen
	$(GO) generate ./pkg/csource ./executor ./pkg/ifuzz ./pkg/kernel

generate_sys: bin/syz-sysgen
	bin/syz-sysgen

bin/syz-sysgen:
	$(GO) build $(GOFLAGS) -o $@ ./sys/syz-sysgen

format: format_go format_cpp format_sys

format_go:
	$(GO) fmt ./...

format_cpp:
	clang-format --style=file -i executor/*.cc executor/*.h tools/kcovtrace/*.c

format_sys: bin/syz-fmt
	bin/syz-fmt sys/test
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

gometalinter:
	env CGO_ENABLED=1 gometalinter.v2 ./...

arch: arch_darwin_amd64_host arch_linux_amd64_host arch_freebsd_amd64_host arch_netbsd_amd64_host \
	arch_linux_amd64_target arch_linux_386_target \
	arch_linux_arm64_target arch_linux_arm_target arch_linux_ppc64le_target \
	arch_freebsd_amd64_target arch_netbsd_amd64_target arch_windows_amd64_target

arch_darwin_amd64_host:
	env HOSTOS=darwin HOSTARCH=amd64 $(MAKE) host

arch_linux_amd64_host:
	env HOSTOS=linux HOSTARCH=amd64 $(MAKE) host

arch_linux_amd64_target:
	env TARGETOS=linux TARGETARCH=amd64 $(MAKE) target

arch_linux_386_target:
	# executor build on 386 on travis fails with:
	# fatal error: asm/errno.h: No such file or directory
	# We install a bunch of additional packages in .travis.yml,
	# but I can't guess the right one.
	env TARGETOS=linux TARGETARCH=amd64 TARGETVMARCH=386 $(MAKE) target

arch_linux_arm64_target:
	env TARGETOS=linux TARGETARCH=arm64 $(MAKE) target

arch_linux_arm_target:
	# executor build on arm fails with:
	# Error: alignment too large: 15 assumed
	env TARGETOS=linux TARGETARCH=arm64 TARGETVMARCH=arm $(MAKE) target

arch_linux_ppc64le_target:
	env TARGETOS=linux TARGETARCH=ppc64le $(MAKE) target

arch_freebsd_amd64_host:
	env HOSTOS=freebsd HOSTARCH=amd64 $(MAKE) host

arch_freebsd_amd64_target:
	env TARGETOS=freebsd TARGETARCH=amd64 $(MAKE) target

arch_netbsd_amd64_host:
	env HOSTOS=netbsd HOSTARCH=amd64 $(MAKE) host

arch_netbsd_amd64_target:
	env TARGETOS=netbsd TARGETARCH=amd64 $(MAKE) target

arch_windows_amd64_target:
	env GOOG=windows GOARCH=amd64 $(GO) install ./syz-fuzzer
	env TARGETOS=windows TARGETARCH=amd64 $(MAKE) fuzzer execprog stress

presubmit:
	$(MAKE) generate
	$(MAKE) check_diff
	$(GO) install ./...
	$(MAKE) presubmit_parallel
	$(MAKE) gometalinter
	echo LGTM

presubmit_parallel: test test_race arch check_links

test:
	# Executor tests use cgo.
	env CGO_ENABLED=1 $(GO) test -short ./...

test_race:
	env CGO_ENABLED=1 $(GO) test -short -race -bench=.* -benchtime=.2s ./...

clean:
	rm -rf ./bin/

# For a tupical Ubuntu/Debian distribution.
# We use "|| true" for apt-get install because packages are all different on different distros,
# and we want to install at least gometalinter on Travis CI.
install_prerequisites:
	uname -a
	sudo apt-get update
	sudo apt-get install -y -q libc6-dev-i386 linux-libc-dev \
		gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf gcc-powerpc64le-linux-gnu || true
	sudo apt-get install -y -q g++-aarch64-linux-gnu || true
	sudo apt-get install -y -q g++-powerpc64le-linux-gnu || true
	sudo apt-get install -y -q g++-arm-linux-gnueabihf || true
	go get -u gopkg.in/alecthomas/gometalinter.v2
	gometalinter.v2 --install

check_links:
	python ./tools/check_links.py $$(pwd) $$(ls ./*.md; find ./docs/ -name '*.md')

# Check that the diff is empty. This is meant to be executed after generating
# and formatting the code to make sure that everything is committed.
check_diff:
	DIFF="$(shell git diff --name-only)"; test -z "$$DIFF"
