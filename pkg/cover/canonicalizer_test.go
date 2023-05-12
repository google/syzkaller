// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Tests the translation of coverage pcs between fuzzer instances with differing module offsets.

package cover_test

import (
	"fmt"
	"reflect"
	"strconv"
	"testing"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/host"
)

type RPCServer struct {
	canonicalModules   *cover.Canonicalizer
	modulesInitialized bool
	fuzzers            map[string]*Fuzzer
}

type Fuzzer struct {
	instModules *cover.CanonicalizerInstance
	testCov     []uint32
	goalOut     []uint32
}

type canonicalizeValue int

const (
	Canonicalize canonicalizeValue = iota
	Decanonicalize
)

// Confirms there is no change to coverage if modules aren't instantiated.
func TestNilModules(t *testing.T) {
	serv := &RPCServer{
		fuzzers: make(map[string]*Fuzzer),
	}
	serv.connect("f1", nil)
	serv.connect("f2", nil)

	serv.fuzzers["f1"].testCov = []uint32{0x00010000, 0x00020000, 0x00030000, 0x00040000}
	serv.fuzzers["f1"].goalOut = []uint32{0x00010000, 0x00020000, 0x00030000, 0x00040000}

	serv.fuzzers["f2"].testCov = []uint32{0x00010000, 0x00020000, 0x00030000, 0x00040000}
	serv.fuzzers["f2"].goalOut = []uint32{0x00010000, 0x00020000, 0x00030000, 0x00040000}
	if err := serv.runTest(Canonicalize); err != "" {
		t.Fatalf("failed in canonicalization: %v", err)
	}

	serv.fuzzers["f1"].goalOut = []uint32{0x00010000, 0x00020000, 0x00030000, 0x00040000}
	serv.fuzzers["f2"].goalOut = []uint32{0x00010000, 0x00020000, 0x00030000, 0x00040000}
	if err := serv.runTest(Decanonicalize); err != "" {
		t.Fatalf("failed in decanonicalization: %v", err)
	}
}

// Tests coverage conversion when modules are instantiated.
func TestModules(t *testing.T) {
	serv := &RPCServer{
		fuzzers: make(map[string]*Fuzzer),
	}

	// Create modules at the specified address offsets.
	f1ModuleAddresses := []uint64{0x00015000, 0x00020000, 0x00030000, 0x00040000, 0x00045000}
	f1ModuleSizes := []uint64{0x5000, 0x5000, 0x10000, 0x5000, 0x10000}
	f1Modules := initModules(f1ModuleAddresses, f1ModuleSizes)
	serv.connect("f1", f1Modules)

	f2ModuleAddresses := []uint64{0x00015000, 0x00040000, 0x00045000, 0x00020000, 0x00030000}
	f2ModuleSizes := []uint64{0x5000, 0x5000, 0x10000, 0x5000, 0x10000}
	f2Modules := initModules(f2ModuleAddresses, f2ModuleSizes)
	serv.connect("f2", f2Modules)

	// f1 is the "canonical" fuzzer as it is first one instantiated.
	// This means that all coverage output should be the same as the inputs.
	serv.fuzzers["f1"].testCov = []uint32{0x00010000, 0x00015000, 0x00020000, 0x00025000, 0x00030000,
		0x00035000, 0x00040000, 0x00045000, 0x00050000, 0x00055000}
	serv.fuzzers["f1"].goalOut = []uint32{0x00010000, 0x00015000, 0x00020000, 0x00025000, 0x00030000,
		0x00035000, 0x00040000, 0x00045000, 0x00050000, 0x00055000}

	// The modules addresss are inverted between: (2 and 4), (3 and 5),
	// affecting the output canonical coverage values in these ranges.
	serv.fuzzers["f2"].testCov = []uint32{0x00010000, 0x00015000, 0x00020000, 0x00025000, 0x00030000,
		0x00035000, 0x00040000, 0x00045000, 0x00050000, 0x00055000}
	serv.fuzzers["f2"].goalOut = []uint32{0x00010000, 0x00015000, 0x00040000, 0x00025000, 0x00045000,
		0x0004a000, 0x00020000, 0x00030000, 0x0003b000, 0x00055000}
	if err := serv.runTest(Canonicalize); err != "" {
		t.Fatalf("failed in canonicalization: %v", err)
	}

	serv.fuzzers["f1"].goalOut = []uint32{0x00010000, 0x00015000, 0x00020000, 0x00025000, 0x00030000,
		0x00035000, 0x00040000, 0x00045000, 0x00050000, 0x00055000}
	serv.fuzzers["f2"].goalOut = []uint32{0x00010000, 0x00015000, 0x00020000, 0x00025000, 0x00030000,
		0x00035000, 0x00040000, 0x00045000, 0x00050000, 0x00055000}
	if err := serv.runTest(Decanonicalize); err != "" {
		t.Fatalf("failed in decanonicalization: %v", err)
	}
}

func (serv *RPCServer) runTest(val canonicalizeValue) string {
	for name, fuzzer := range serv.fuzzers {
		if val == Canonicalize {
			fuzzer.instModules.Canonicalize(fuzzer.testCov)
		} else {
			fuzzer.instModules.Decanonicalize(fuzzer.testCov)
		}
		if !reflect.DeepEqual(fuzzer.testCov, fuzzer.goalOut) {
			return fmt.Sprintf("fuzzer %v.\nExpected: 0x%x.\nReturned: 0x%x",
				name, fuzzer.goalOut, fuzzer.testCov)
		}
	}
	return ""
}

func (serv *RPCServer) connect(name string, modules []host.KernelModule) {
	if !serv.modulesInitialized {
		serv.canonicalModules = cover.NewCanonicalizer(modules)
		serv.modulesInitialized = true
	}

	serv.fuzzers[name] = &Fuzzer{
		instModules: serv.canonicalModules.NewInstance(modules),
	}
}

func initModules(addrs, sizes []uint64) []host.KernelModule {
	var modules []host.KernelModule
	for idx, addr := range addrs {
		modules = append(modules, host.KernelModule{
			Name: strconv.FormatInt(int64(idx), 10),
			Addr: addr,
			Size: sizes[idx],
		})
	}
	return modules
}
