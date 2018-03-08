// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:generate bash -c "gcc kvm_gen.cc kvm.S -o kvm_gen && ./kvm_gen > kvm.S.h && rm ./kvm_gen"

// +build linux

package executor

// int test_copyin();
// int test_csum_inet();
// int test_csum_inet_acc();
// int test_kvm();
import "C"

func testCopyin() int {
	return int(C.test_copyin())
}

func testCsumInet() int {
	return int(C.test_csum_inet())
}

func testCsumInetAcc() int {
	return int(C.test_csum_inet_acc())
}

func testKVM() int {
	return int(C.test_kvm())
}

// Prevent deadcode warnings:
var (
	_ = testCopyin
	_ = testCsumInet
	_ = testCsumInetAcc
	_ = testKVM
)
