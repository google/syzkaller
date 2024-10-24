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

RED := $(shell tput setaf 1)
RESET := $(shell tput sgr0)
ifndef SYZ_ENV
$(warning $(RED)run command via tools/syz-env for best compatibility, see:$(RESET))
$(warning $(RED)https://github.com/google/syzkaller/blob/master/docs/contributing.md#using-syz-env$(RESET))
endif

ENV := $(subst \n,$(newline),$(shell CI=$(CI)\
	SOURCEDIR=$(SOURCEDIR) HOSTOS=$(HOSTOS) HOSTARCH=$(HOSTARCH) \
	TARGETOS=$(TARGETOS) TARGETARCH=$(TARGETARCH) TARGETVMARCH=$(TARGETVMARCH) \
	SYZ_CLANG=$(SYZ_CLANG) \
	go run tools/syz-make/make.go))
# Uncomment in case of emergency.
# $(info $(ENV))
$(eval $(ENV))
ifneq ("$(SYZERROR)", "")
$(error $(SYZERROR))
endif
ifeq ("$(NCORES)", "")
$(error syz-make failed)
endif
ifeq ("$(MAKELEVEL)", "0")
	MAKEFLAGS += -j$(NCORES) --no-print-directory
endif

GO := go
HOSTGO := go
# By default, build all Go binaries as static. We don't need cgo and it is
# known to cause problems at least on Android emulator.
CGO_ENABLED ?= 0
export CGO_ENABLED
TARGETGOOS := $(TARGETOS)
TARGETGOARCH := $(TARGETVMARCH)
export GO111MODULE=on
export GOBIN=$(shell pwd -P)/bin

GITREV=$(shell git rev-parse HEAD)
ifeq ("$(shell git diff --shortstat)", "")
	REV=$(GITREV)
else
	REV=$(GITREV)+
endif
GITREVDATE=$(shell git log -n 1 --format="%cd" --date=format:%Y%m%d-%H%M%S)

# Don't generate symbol table and DWARF debug info.
# Reduces build time and binary sizes considerably.
# That's only needed if you use gdb or nm.
# If you need that, build manually without these flags.
GOFLAGS := "-ldflags=-s -w -X github.com/google/syzkaller/prog.GitRevision=$(REV) -X 'github.com/google/syzkaller/prog.gitRevisionDate=$(GITREVDATE)'"

GOHOSTFLAGS ?= $(GOFLAGS)
GOTARGETFLAGS ?= $(GOFLAGS)
ifneq ("$(GOTAGS)", "")
	GOHOSTFLAGS += "-tags=$(GOTAGS)"
endif
GOTARGETFLAGS += "-tags=syz_target syz_os_$(TARGETOS) syz_arch_$(TARGETVMARCH) $(GOTAGS)"

ifeq ("$(TARGETOS)", "test")
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

.PHONY: all clean host target \
	manager executor ci hub \
	execprog mutate prog2c trace2syz repro upgrade db \
	usbgen symbolize cover kconf syz-build crush \
	bin/syz-extract bin/syz-fmt \
	extract generate generate_go generate_rpc generate_sys \
	format format_go format_cpp format_sys \
	tidy test test_race \
	check_copyright check_language check_whitespace check_links check_diff check_commits check_shebang \
	presubmit presubmit_aux presubmit_build presubmit_arch_linux presubmit_arch_freebsd \
	presubmit_arch_netbsd presubmit_arch_openbsd presubmit_arch_darwin presubmit_arch_windows \
	presubmit_arch_executor presubmit_dashboard presubmit_race presubmit_race_dashboard presubmit_old

all: host target
host: manager repro mutate prog2c db upgrade
target: execprog executor

executor: descriptions
ifeq ($(TARGETOS),fuchsia)
	# Dont build syz-executor for fuchsia.
else
ifneq ("$(BUILDOS)", "$(NATIVEBUILDOS)")
	$(info ************************************************************************************)
	$(info Executor will not be built)
	$(info Building executor for ${TARGETOS} is not supported on ${BUILDOS})
	$(info ************************************************************************************)
else
ifneq ("$(NO_CROSS_COMPILER)", "")
	$(info ************************************************************************************)
	$(info Executor will not be built)
	$(info Native cross-compiler is missing/broken:)
	$(info $(NO_CROSS_COMPILER))
	$(info ************************************************************************************)
else
	mkdir -p ./bin/$(TARGETOS)_$(TARGETARCH)
	$(CXX) -o ./bin/$(TARGETOS)_$(TARGETARCH)/syz-executor$(EXE) executor/executor.cc \
		$(ADDCXXFLAGS) $(CFLAGS) -DGOOS_$(TARGETOS)=1 -DGOARCH_$(TARGETARCH)=1 \
		-DHOSTGOOS_$(HOSTOS)=1 -DGIT_REVISION=\"$(REV)\"
endif
endif
endif

# .descriptions is a stub file that serves as a substitute for all files generated by syz-sysgen:
# sys/*/gen/*.go, executor/defs.h, executor/syscalls.h
# syz-sysgen generates them all at once, so we can't make each of them an independent target.
.PHONY: descriptions
descriptions:
	go list -f '{{.Stale}}' ./sys/syz-sysgen | grep -q false || go install ./sys/syz-sysgen
	$(MAKE) .descriptions

.descriptions: sys/*/*.txt sys/*/*.const bin/syz-sysgen
	bin/syz-sysgen
	$(GO) fmt ./sys/... >/dev/null
	touch .descriptions

manager: descriptions
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-manager github.com/google/syzkaller/syz-manager

execprog: descriptions
	GOOS=$(TARGETGOOS) GOARCH=$(TARGETGOARCH) $(GO) build $(GOTARGETFLAGS) -o ./bin/$(TARGETOS)_$(TARGETVMARCH)/syz-execprog$(EXE) github.com/google/syzkaller/tools/syz-execprog

ci: descriptions
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-ci github.com/google/syzkaller/syz-ci

hub: descriptions
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-hub github.com/google/syzkaller/syz-hub

repro: descriptions
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-repro github.com/google/syzkaller/tools/syz-repro

mutate: descriptions
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-mutate github.com/google/syzkaller/tools/syz-mutate

diff: descriptions target
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-diff github.com/google/syzkaller/tools/syz-diff

prog2c: descriptions
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-prog2c github.com/google/syzkaller/tools/syz-prog2c

crush: descriptions
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-crush github.com/google/syzkaller/tools/syz-crush

reporter: descriptions
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-reporter github.com/google/syzkaller/tools/syz-reporter

db: descriptions
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-db github.com/google/syzkaller/tools/syz-db

upgrade: descriptions
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-upgrade github.com/google/syzkaller/tools/syz-upgrade

trace2syz: descriptions
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-trace2syz github.com/google/syzkaller/tools/syz-trace2syz

expand: descriptions
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-expand github.com/google/syzkaller/tools/syz-expand

usbgen:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-usbgen github.com/google/syzkaller/tools/syz-usbgen

symbolize:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-symbolize github.com/google/syzkaller/tools/syz-symbolize
cover:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-cover github.com/google/syzkaller/tools/syz-cover
kconf:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-kconf github.com/google/syzkaller/tools/syz-kconf
syz-build:
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-build github.com/google/syzkaller/tools/syz-build

bisect: descriptions
	GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-bisect github.com/google/syzkaller/tools/syz-bisect

verifier: descriptions
	# TODO: switch syz-verifier to use syz-executor.
	# GOOS=$(HOSTOS) GOARCH=$(HOSTARCH) $(HOSTGO) build $(GOHOSTFLAGS) -o ./bin/syz-verifier github.com/google/syzkaller/syz-verifier

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
generate:
	$(MAKE) descriptions
	$(MAKE) generate_go
	$(MAKE) generate_rpc
	$(MAKE) format

generate_go: format_cpp
	$(GO) generate ./executor ./pkg/ifuzz ./pkg/build ./pkg/rpcserver
	$(GO) generate ./vm/proxyapp

generate_rpc:
	flatc -o pkg/flatrpc --warnings-as-errors --gen-object-api --filename-suffix "" --go --gen-onefile --go-namespace flatrpc pkg/flatrpc/flatrpc.fbs
	flatc -o pkg/flatrpc --warnings-as-errors --gen-object-api --filename-suffix "" --cpp --scoped-enums pkg/flatrpc/flatrpc.fbs
	$(GO) fmt ./pkg/flatrpc/flatrpc.go

generate_fidl:
ifeq ($(TARGETOS),fuchsia)
	$(HOSTGO) generate ./sys/fuchsia
	$(MAKE) format_sys
else
endif

generate_trace2syz:
	(cd tools/syz-trace2syz/parser; ragel -Z -G2 -o lex.go straceLex.rl)
	(cd tools/syz-trace2syz/parser; goyacc -o strace.go -p Strace -v="" strace.y)

format: format_go format_cpp format_sys

format_go:
	$(GO) fmt ./...

format_cpp:
	clang-format --style=file -i executor/*.cc executor/*.h \
		executor/android/android_seccomp.h \
		tools/kcovtrace/*.c tools/kcovfuzzer/*.c tools/fops_probe/*.cc tools/syz-declextract/syz-declextract.cpp

format_sys: bin/syz-fmt
	bin/syz-fmt all

bin/syz-fmt:
	$(HOSTGO) build $(GOHOSTFLAGS) -o $@ ./tools/syz-fmt

configs: kconf
	bin/syz-kconf -config dashboard/config/linux/main.yml -sourcedir $(SOURCEDIR)

tidy: descriptions
	clang-tidy -quiet -header-filter=executor/[^_].* -warnings-as-errors=* \
		-checks=-*,misc-definitions-in-headers,bugprone-macro-parentheses,clang-analyzer-*,-clang-analyzer-security.insecureAPI*,-clang-analyzer-optin.performance* \
		-extra-arg=-DGOOS_$(TARGETOS)=1 -extra-arg=-DGOARCH_$(TARGETARCH)=1 \
		-extra-arg=-DHOSTGOOS_$(HOSTOS)=1 -extra-arg=-DGIT_REVISION=\"$(REV)\" \
		--extra-arg=-I. --extra-arg=-Iexecutor/_include \
		--extra-arg=-std=c++17 \
		executor/*.cc

ifdef CI
  LINT-FLAGS := --out-format github-actions
endif

lint:
	# This should install the command from our vendor dir.
	CGO_ENABLED=1 $(HOSTGO) install github.com/golangci/golangci-lint/cmd/golangci-lint
	CGO_ENABLED=1 $(HOSTGO) build -buildmode=plugin -o bin/syz-linter.so ./tools/syz-linter
	bin/golangci-lint run $(LINT-FLAGS) ./...

presubmit:
	$(MAKE) presubmit_aux
	$(MAKE) presubmit_build
	$(MAKE) presubmit_arch_linux
	$(MAKE) presubmit_arch_freebsd
	$(MAKE) presubmit_arch_netbsd
	$(MAKE) presubmit_arch_openbsd
	$(MAKE) presubmit_arch_darwin
	$(MAKE) presubmit_arch_windows
	$(MAKE) presubmit_arch_executor
	$(MAKE) presubmit_race
	$(MAKE) presubmit_race_dashboard

presubmit_aux:
	$(MAKE) generate
	$(MAKE) -j100 check_commits check_diff check_copyright check_language check_whitespace check_links check_shebang tidy
	$(GO) mod tidy

presubmit_build: descriptions
	# Run go build before lint for better error messages if build is broken.
	# This does not check build of test files, but running go test takes too long (even for building).
	$(GO) build ./...
	$(MAKE) lint
	SYZ_SKIP_DEV_APPSERVER_TESTS=1 $(MAKE) test

presubmit_arch_linux: descriptions
	HOSTOS=linux HOSTARCH=amd64 $(MAKE) host
	TARGETOS=linux TARGETARCH=amd64 TARGETVMARCH=amd64 $(MAKE) target
	TARGETOS=linux TARGETARCH=386 TARGETVMARCH=386 $(MAKE) target
	TARGETOS=linux TARGETARCH=arm64 TARGETVMARCH=arm64 $(MAKE) target
	TARGETOS=linux TARGETARCH=arm TARGETVMARCH=arm $(MAKE) target
	TARGETOS=linux TARGETARCH=mips64le TARGETVMARCH=mips64le $(MAKE) target
	TARGETOS=linux TARGETARCH=ppc64le TARGETVMARCH=ppc64le $(MAKE) target
	TARGETOS=linux TARGETARCH=riscv64 TARGETVMARCH=riscv64 $(MAKE) target
	TARGETOS=linux TARGETARCH=s390x TARGETVMARCH=s390x $(MAKE) target

presubmit_arch_freebsd: descriptions
	HOSTOS=freebsd HOSTARCH=amd64 $(MAKE) host
	TARGETOS=freebsd TARGETARCH=amd64 TARGETVMARCH=amd64 $(MAKE) target
	TARGETOS=freebsd TARGETARCH=386 TARGETVMARCH=386 $(MAKE) target
	TARGETOS=freebsd TARGETARCH=arm64 TARGETVMARCH=arm64 $(MAKE) target
	TARGETOS=freebsd TARGETARCH=riscv64 TARGETVMARCH=riscv64 $(MAKE) target

presubmit_arch_netbsd: descriptions
	HOSTOS=netbsd HOSTARCH=amd64 $(MAKE) host
	TARGETOS=netbsd TARGETARCH=amd64 TARGETVMARCH=amd64 $(MAKE) target

presubmit_arch_openbsd: descriptions
	HOSTOS=openbsd HOSTARCH=amd64 $(MAKE) host
	TARGETOS=openbsd TARGETARCH=amd64 TARGETVMARCH=amd64 $(MAKE) target

presubmit_arch_darwin: descriptions
	HOSTOS=darwin HOSTARCH=amd64 $(MAKE) host

presubmit_arch_windows: descriptions
	TARGETOS=windows TARGETARCH=amd64 TARGETVMARCH=amd64 $(MAKE) target

presubmit_arch_executor: descriptions
	TARGETOS=linux TARGETARCH=amd64 TARGETVMARCH=amd64 SYZ_CLANG=yes $(MAKE) executor
	TARGETOS=fuchsia TARGETARCH=amd64 TARGETVMARCH=amd64 $(MAKE) executor
	TARGETOS=fuchsia TARGETARCH=arm64 TARGETVMARCH=arm64 $(MAKE) executor
	TARGETOS=test TARGETARCH=64 TARGETVMARCH=64 $(MAKE) executor
	TARGETOS=test TARGETARCH=64_fork TARGETVMARCH=64_fork $(MAKE) executor
	TARGETOS=test TARGETARCH=32 TARGETVMARCH=32 $(MAKE) executor
	TARGETOS=test TARGETARCH=32_fork TARGETVMARCH=32_fork $(MAKE) executor

presubmit_dashboard: descriptions
	SYZ_CLANG=yes $(GO) test -short -vet=off -coverprofile=.coverage.txt ./dashboard/app

presubmit_race: descriptions
	# -race requires cgo
	CGO_ENABLED=1 $(GO) test -race; if test $$? -ne 2; then \
	CGO_ENABLED=1 SYZ_SKIP_DEV_APPSERVER_TESTS=1 $(GO) test -race -short -vet=off -bench=.* -benchtime=.2s ./... ;\
	fi

presubmit_race_dashboard: descriptions
	# -race requires cgo
	CGO_ENABLED=1 $(GO) test -race; if test $$? -ne 2; then \
	CGO_ENABLED=1 $(GO) test -race -short -vet=off -bench=.* -benchtime=.2s ./dashboard/app/... ;\
	fi

presubmit_old: descriptions
	# Binaries we can compile in syz-old-env. 386 is broken, riscv64 is missing.
	TARGETARCH=amd64 TARGETVMARCH=amd64 $(MAKE) target
	TARGETARCH=arm64 TARGETVMARCH=arm64 $(MAKE) target
	TARGETARCH=arm TARGETVMARCH=arm $(MAKE) target
	TARGETARCH=ppc64le TARGETVMARCH=ppc64le $(MAKE) target
	TARGETARCH=mips64le TARGETVMARCH=mips64le $(MAKE) target
	TARGETARCH=s390x TARGETVMARCH=s390x $(MAKE) target

presubmit_gvisor: host target
	./tools/gvisor-smoke-test.sh

test: descriptions
	$(GO) test -short -coverprofile=.coverage.txt ./...

clean:
	rm -rf ./bin .descriptions executor/defs.h executor/syscalls.h
	find sys/*/gen -type f -not -name empty.go -delete

# For a tupical Ubuntu/Debian distribution.
# We use "|| true" for apt-get install because packages are all different on different distros.
# Also see tools/syz-env for container approach.
install_prerequisites: act
	uname -a
	sudo apt-get update
	sudo apt-get install -y -q libc6-dev-i386 linux-libc-dev \
		gcc-aarch64-linux-gnu gcc-arm-linux-gnueabi gcc-powerpc64le-linux-gnu gcc-mips64el-linux-gnuabi64 || true
	sudo apt-get install -y -q g++-aarch64-linux-gnu || true
	sudo apt-get install -y -q g++-powerpc64le-linux-gnu || true
	sudo apt-get install -y -q g++-arm-linux-gnueabi || true
	sudo apt-get install -y -q g++-mips64el-linux-gnuabi64 || true
	sudo apt-get install -y -q g++-s390x-linux-gnu || true
	sudo apt-get install -y -q g++-riscv64-linux-gnu || true
	sudo apt-get install -y -q g++ || true
	[ -z "$(shell which python)" -a -n "$(shell which python3)" ] && sudo apt-get install -y -q python-is-python3 || true
	sudo apt-get install -y -q clang-tidy || true
	sudo apt-get install -y -q clang clang-format ragel
	sudo apt-get install -y -q flatbuffers-compiler libflatbuffers-dev
	GO111MODULE=off go get -u golang.org/x/tools/cmd/goyacc

check_copyright:
	./tools/check-copyright.sh

check_language:
	./tools/check-language.sh

check_whitespace:
	./tools/check-whitespace.sh

check_commits:
	./tools/check-commits.sh

check_links:
	python ./tools/check_links.py $$(pwd) $$(find . -name '*.md' | grep -v "./vendor/")

# Check that the diff is empty. This is meant to be executed after generating
# and formatting the code to make sure that everything is committed.
check_diff:
	@if [ "$(shell git --no-pager diff --name-only)" != "" ]; then \
		git --no-pager diff; \
		git --no-pager diff --name-only | \
			sed "s#.*#&:1:1: The file is not formatted/regenerated. Run 'make generate' and include it into the commit.#g"; \
		false; \
	fi

check_shebang:
	./tools/check-shebang.sh

act:
	curl https://raw.githubusercontent.com/nektos/act/master/install.sh | bash
