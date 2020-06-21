// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build amd64,!freebsd,!openbsd,!netbsd

//go:generate bash -c "gcc kvm_gen.cc kvm.S -o kvm_gen && ./kvm_gen > kvm.S.h && rm ./kvm_gen"

package executor
