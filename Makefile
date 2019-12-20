# Copyright 2017 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

# There are 3 OS/arch pairs:
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

define newline


endef
ENV := $(subst \n,$(newline),$(shell \
	SOURCEDIR=$(SOURCEDIR) HOSTOS=$(HOSTOS) HOSTARCH=$(HOSTARCH) \
	TARGETOS=$(TARGETOS) TARGETARCH=$(TARGETARCH) TARGETVMARCH=$(TARGETVMARCH) \
	go run tools/syz-env/env.go))
# Uncomment in case of emergency.
# $(info $(ENV))
$(eval $(ENV))
ifeq ("$(NCORES)", "")
$(error syz-env failed)
endif
MAKEFLAGS += " -j$(NCORES) "
export MAKEFLAGS

GO := go
HOSTGO := go
# By default, build all Go binaries as static. We don't need cgo and it is
# known to cause problems at least on Android emulator.
CGO_ENABLED ?= 0
export CGO_ENABLED
TARGETGOOS := $(TARGETOS)
TARGETGOARCH := $(TARGETVMARCH)

GITREV=$(shell git rev-parse HEAD)
ifeq ("$(shell git diff --shortstat)", "")
	REV=$(GITREV)
else
	REV=$(GITREV)+
endif
GITREVDATE=$(shell git log -n 1 --format="%ad")

# Don't generate symbol table and DWARF debug info.
# Reduces build time and binary sizes considerably.
# That's only needed if you use gdb or nm.
# If you need that, build manually without these flags.
GOFLAGS := "-ldflags=-s -w -X github.com/google/syzkaller/sys.GitRevision=$(REV) -X 'github.com/google/syzkaller/sys.gitRevisionDate=$(GITREVDATE)'"

GOHOSTFLAGS := $(GOFLAGS)
GOTARGETFLAGS := $(GOFLAGS)
ifneq ("$(GOTAGS)", "")
	GOHOSTFLAGS += "-tags=$(GOTAGS)"
endif
GOTARGETFLAGS += "-tags=syz_target syz_os_$(TARGETOS) syz_arch_$(TARGETVMARCH) $(GOTAGS)"

ifeq ("$(TARGETOS)", "test")
	TARGETGOOS := $(HOSTOS)
	TARGETGOARCH := $(HOSTARCH)
endif

ifeq ("$(TARGETOS)", "akaros")
	TARGETGOOS := $(HOSTOS)
	TARGETGOARCH := $(HOSTARCH)
endif

ifeq ("$(TARGETOS)", "fuchsia")
	TARGETGOOS := $(HOSTOS)
	TARGETGOARCH := $(HOSTARCH)
endif

ifeq ("$(TARGETOS)", "trusty")
	TARGETGOOS := $(HOSTOS)
	TARGETGOARCH := $(HOSTARCH)
endif

.PHONY: all host target \
	manager runtest fuzzer executor \
	ci hub \
	execprog mutate prog2c trace2syz stress repro upgrade db \
	bin/syz-sysgen bin/syz-extract bin/syz-fmt \
	extract generate generate_go generate_sys \
	format format_go format_cpp format_sys \
	tidy test test_race check_links check_diff \
	arch arch_darwin_amd64_host arch_linux_amd64_host \
	arch_freebsd_amd64_host arch_netbsd_amd64_host \
	arch_linux_amd64_target arch_linux_386_target \
	arch_linux_arm64_target arch_linux_arm_target arch_linux_ppc64le_target arch_linux_mips64le_target \
	arch_freebsd_amd64_target arch_freebsd_386_target \
	arch_netbsd_amd64_target arch_windows_amd64_target \
	arch_test presubmit presubmit_parallel clean

all: host target

host:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) install ./syz-manager
	$(MAKE) manager runtest repro mutate prog2c db upgrade

target:
	GOOS=$(TARGETGOOS) GOARCH=$(TARGETGOARCH) $(GO) install ./syz-fuzzer
	$(MAKE) fuzzer execprog stress executor

# executor uses stacks of limited size, so no jumbo frames.
executor:
ifneq ("$(BUILDOS)", "$(NATIVEBUILDOS)")
	$(info ************************************************************************************)
	$(info Building executor for ${TARGETOS} is not supported on ${BUILDOS}. Executor will not be built.)
	$(info ************************************************************************************)
else
ifneq ("$(NO_CROSS_COMPILER)", "")
	$(info ************************************************************************************)
	$(info Native cross-compiler $(CC) is missing. Executor will not be built.)
	$(info ************************************************************************************)
else
	mkdir -p ./bin/$(TARGETOS)_$(TARGETARCH)
	$(CC) -o ./bin/$(TARGETOS)_$(TARGETARCH)/syz-executor$(EXE) executor/executor.cc \
		$(ADDCFLAGS) $(CFLAGS) -DGOOS_$(TARGETOS)=1 -DGOARCH_$(TARGETARCH)=1 \
		-DHOSTGOOS_$(HOSTOS)=1 -DGIT_REVISION=\"$(REV)\"
endif
endif

manager:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-manager github.com/google/syzkaller/syz-manager

runtest:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-runtest github.com/google/syzkaller/tools/syz-runtest

fuzzer:
	GOOS=$(TARGETGOOS) GOARCH=$(TARGETGOARCH) $(GO) build $(GOTARGETFLAGS) -o ./bin/$(TARGETOS)_$(TARGETVMARCH)/syz-fuzzer$(EXE) github.com/google/syzkaller/syz-fuzzer

execprog:
	GOOS=$(TARGETGOOS) GOARCH=$(TARGETGOARCH) $(GO) build $(GOTARGETFLAGS) -o ./bin/$(TARGETOS)_$(TARGETVMARCH)/syz-execprog$(EXE) github.com/google/syzkaller/tools/syz-execprog

ci:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-ci github.com/google/syzkaller/syz-ci

hub:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-hub github.com/google/syzkaller/syz-hub

repro:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-repro github.com/google/syzkaller/tools/syz-repro

mutate:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-mutate github.com/google/syzkaller/tools/syz-mutate

prog2c:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-prog2c github.com/google/syzkaller/tools/syz-prog2c

stress:
	GOOS=$(TARGETGOOS) GOARCH=$(TARGETGOARCH) $(GO) build $(GOTARGETFLAGS) -o ./bin/$(TARGETOS)_$(TARGETVMARCH)/syz-stress$(EXE) github.com/google/syzkaller/tools/syz-stress

db:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-db github.com/google/syzkaller/tools/syz-db

upgrade:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-upgrade github.com/google/syzkaller/tools/syz-upgrade

trace2syz:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-trace2syz github.com/google/syzkaller/tools/syz-trace2syz

usbgen:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-usbgen github.com/google/syzkaller/tools/syz-usbgen

expand:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-expand github.com/google/syzkaller/tools/syz-expand

# `extract` extracts const files from various kernel sources, and may only
# re-generate parts of files.
extract: bin/syz-extract
ifeq ($(TARGETOS),fuchsia)
	$(MAKE) generate_fidl TARGETARCH=amd64
	$(MAKE) generate_fidl TARGETARCH=arm64
else
endif
	bin/syz-extract -build -os=$(TARGETOS) -sourcedir=$(SOURCEDIR) $(FILES)
bin/syz-extract:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o $@ ./sys/syz-extract

# `generate` does *not* depend on any kernel sources, and generates everything
# in one pass, for all arches. It can be run on a bare syzkaller checkout.
generate: generate_go generate_sys
	$(MAKE) format

generate_go: bin/syz-sysgen format_cpp
	$(GO) generate ./pkg/csource ./executor ./pkg/ifuzz ./pkg/build ./pkg/html

generate_sys: bin/syz-sysgen
	bin/syz-sysgen

generate_fidl:
ifeq ($(TARGETOS),fuchsia)
	$(HOSTGO) generate ./sys/fuchsia
	$(MAKE) format_sys
else
endif

generate_trace2syz:
	(cd tools/syz-trace2syz/parser; ragel -Z -G2 -o lex.go straceLex.rl)
	(cd tools/syz-trace2syz/parser; goyacc -o strace.go -p Strace -v="" strace.y)

bin/syz-sysgen:
	$(GO) build $(GOHOSTFLAGS) -o $@ ./sys/syz-sysgen

format: format_go format_cpp format_sys

format_go:
	$(GO) fmt ./...

format_cpp:
	clang-format --style=file -i executor/*.cc executor/*.h \
		tools/kcovtrace/*.c tools/kcovfuzzer/*.c tools/fops_probe/*.cc

format_sys: bin/syz-fmt
	bin/syz-fmt all

bin/syz-fmt:
	$(HOSTGO) build $(GOHOSTFLAGS) -o $@ ./tools/syz-fmt

tidy:
	# A single check is enabled for now. But it's always fixable and proved to be useful.
	clang-tidy -quiet -header-filter=.* -checks=-*,misc-definitions-in-headers -warnings-as-errors=* \
		-extra-arg=-DGOOS_$(TARGETOS)=1 -extra-arg=-DGOARCH_$(TARGETARCH)=1 \
		executor/*.cc
	# Just check for compiler warnings.
	$(CC) executor/test_executor.cc -c -o /dev/null -Wparentheses -Wno-unused -Wall

lint:
	golangci-lint run ./...

arch: arch_darwin_amd64_host arch_linux_amd64_host arch_freebsd_amd64_host \
	arch_netbsd_amd64_host arch_openbsd_amd64_host \
	arch_linux_amd64_target arch_linux_386_target \
	arch_linux_arm64_target arch_linux_arm_target arch_linux_ppc64le_target arch_linux_mips64le_target \
	arch_freebsd_amd64_target arch_freebsd_386_target \
	arch_netbsd_amd64_target arch_openbsd_amd64_target \
	arch_windows_amd64_target arch_test

arch_darwin_amd64_host:
	env HOSTOS=darwin HOSTARCH=amd64 $(MAKE) host

arch_linux_amd64_host:
	env HOSTOS=linux HOSTARCH=amd64 $(MAKE) host

arch_linux_amd64_target:
	env TARGETOS=linux TARGETARCH=amd64 $(MAKE) target

arch_linux_386_target:
	env TARGETOS=linux TARGETARCH=386 $(MAKE) target

arch_linux_arm64_target:
	env TARGETOS=linux TARGETARCH=arm64 $(MAKE) target

arch_linux_arm_target:
	env TARGETOS=linux TARGETARCH=arm $(MAKE) target

arch_linux_mips64le_target:
	env TARGETOS=linux TARGETARCH=mips64le $(MAKE) target

arch_linux_ppc64le_target:
	env TARGETOS=linux TARGETARCH=ppc64le $(MAKE) target

arch_freebsd_amd64_host:
	env HOSTOS=freebsd HOSTARCH=amd64 $(MAKE) host

arch_freebsd_amd64_target:
	env TARGETOS=freebsd TARGETARCH=amd64 $(MAKE) target

arch_freebsd_386_target:
	env TARGETOS=freebsd TARGETARCH=386 $(MAKE) target

arch_netbsd_amd64_host:
	env HOSTOS=netbsd HOSTARCH=amd64 $(MAKE) host

arch_netbsd_amd64_target:
	env TARGETOS=netbsd TARGETARCH=amd64 $(MAKE) target

arch_openbsd_amd64_host:
	env HOSTOS=openbsd HOSTARCH=amd64 $(MAKE) host

arch_openbsd_amd64_target:
	env TARGETOS=openbsd TARGETARCH=amd64 $(MAKE) target

arch_windows_amd64_target:
	env GOOG=windows GOARCH=amd64 $(GO) install ./syz-fuzzer
	env TARGETOS=windows TARGETARCH=amd64 $(MAKE) target

arch_test:
	env TARGETOS=test TARGETARCH=64 $(MAKE) executor
	env TARGETOS=test TARGETARCH=64_fork $(MAKE) executor
	env TARGETOS=test TARGETARCH=32_shmem $(MAKE) executor
	env TARGETOS=test TARGETARCH=32_fork_shmem $(MAKE) executor

presubmit:
	$(MAKE) generate
	$(MAKE) check_diff
	$(GO) install ./...
	$(MAKE) presubmit_parallel
	$(MAKE) lint
	echo LGTM

presubmit_parallel: test test_race arch check_links

test:
ifeq ("$(TRAVIS)$(shell go version | grep 1.11)", "true")
	# Collect coverage report for codecov.io when testing Go 1.12 on travis (uploaded in .travis.yml).
	env CGO_ENABLED=1 $(GO) test -short -coverprofile=coverage.txt ./...
else
	# Executor tests use cgo.
	env CGO_ENABLED=1 $(GO) test -short ./...
endif

test_race:
	env CGO_ENABLED=1 $(GO) test -race; if test $$? -ne 2; then \
	env CGO_ENABLED=1 $(GO) test -race -short -bench=.* -benchtime=.2s ./... ;\
	fi

clean:
	rm -rf ./bin/

# For a tupical Ubuntu/Debian distribution.
# We use "|| true" for apt-get install because packages are all different on different distros,
# and we want to install at least golangci-lint on Travis CI.
install_prerequisites:
	uname -a
	sudo apt-get update
	sudo apt-get install -y -q libc6-dev-i386 linux-libc-dev \
		gcc-aarch64-linux-gnu gcc-arm-linux-gnueabi gcc-powerpc64le-linux-gnu gcc-mips64el-linux-gnuabi64 || true
	sudo apt-get install -y -q g++-aarch64-linux-gnu || true
	sudo apt-get install -y -q g++-powerpc64le-linux-gnu || true
	sudo apt-get install -y -q g++-arm-linux-gnueabi || true
	sudo apt-get install -y -q g++-mips64el-linux-gnuabi64 || true
	sudo apt-get install -y -q ragel clang-format
	go get -u golang.org/x/tools/cmd/goyacc \
		github.com/golangci/golangci-lint/cmd/golangci-lint \
		github.com/dvyukov/go-fuzz/go-fuzz-build

check_links:
	python ./tools/check_links.py $$(pwd) $$(ls ./*.md; find ./docs/ -name '*.md')

# Check that the diff is empty. This is meant to be executed after generating
# and formatting the code to make sure that everything is committed.
check_diff:
	DIFF="$(shell git diff --name-only)"; test -z "$$DIFF"
