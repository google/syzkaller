// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Tests the translation of coverage pcs between fuzzer instances with differing module offsets.

package cover_test

import (
	"fmt"
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
}

// Confirms there is no change to coverage if modules aren't instantiated.
func TestNilModules(t *testing.T) {
	serv := &RPCServer{
		fuzzers: make(map[string]*Fuzzer),
	}
	serv.Connect("f1", nil)
	serv.Connect("f2", nil)

	testCov := []uint32{0x00010000, 0x00020000, 0x00030000, 0x00040000}
	goalOut := []uint32{0x00010000, 0x00020000, 0x00030000, 0x00040000}

	for name, fuzzer := range serv.fuzzers {
		fuzzer.instModules.Canonicalize(testCov)
		for idx, cov := range testCov {
			if cov != goalOut[idx] {
				failMsg := fmt.Errorf("fuzzer %v.\nExpected: 0x%x.\nReturned: 0x%x",
					name, goalOut[idx], cov)
				t.Fatalf("failed in canonicalization. %v", failMsg)
			}
		}

		fuzzer.instModules.Decanonicalize(testCov)
		for idx, cov := range testCov {
			if cov != goalOut[idx] {
				failMsg := fmt.Errorf("fuzzer %v.\nExpected: 0x%x.\nReturned: 0x%x",
					name, goalOut[idx], cov)
				t.Fatalf("failed in decanonicalization. %v", failMsg)
			}
		}
	}
}

// Tests coverage conversion when modules are instantiated.
func TestModules(t *testing.T) {
	serv := &RPCServer{
		fuzzers: make(map[string]*Fuzzer),
	}

	// Create modules at the specified address offsets.
	var f1Modules, f2Modules []host.KernelModule
	f1ModuleAddresses := []uint64{0x00015000, 0x00020000, 0x00030000, 0x00040000, 0x00045000}
	f1ModuleSizes := []uint64{0x5000, 0x5000, 0x10000, 0x5000, 0x10000}

	f2ModuleAddresses := []uint64{0x00015000, 0x00040000, 0x00045000, 0x00020000, 0x00030000}
	f2ModuleSizes := []uint64{0x5000, 0x5000, 0x10000, 0x5000, 0x10000}
	for idx, address := range f1ModuleAddresses {
		f1Modules = append(f1Modules, host.KernelModule{
			Name: strconv.FormatInt(int64(idx), 10),
			Addr: address,
			Size: f1ModuleSizes[idx],
		})
	}
	for idx, address := range f2ModuleAddresses {
		f2Modules = append(f2Modules, host.KernelModule{
			Name: strconv.FormatInt(int64(idx), 10),
			Addr: address,
			Size: f2ModuleSizes[idx],
		})
	}

	serv.Connect("f1", f1Modules)
	serv.Connect("f2", f2Modules)

	testCov := make(map[string][]uint32)
	goalOutCanonical := make(map[string][]uint32)
	goalOutDecanonical := make(map[string][]uint32)

	// f1 is the "canonical" fuzzer as it is first one instantiated.
	// This means that all coverage output should be the same as the inputs.
	testCov["f1"] = []uint32{0x00010000, 0x00015000, 0x00020000, 0x00025000, 0x00030000,
		0x00035000, 0x00040000, 0x00045000, 0x00050000, 0x00055000}
	goalOutCanonical["f1"] = []uint32{0x00010000, 0x00015000, 0x00020000, 0x00025000, 0x00030000,
		0x00035000, 0x00040000, 0x00045000, 0x00050000, 0x00055000}
	goalOutDecanonical["f1"] = []uint32{0x00010000, 0x00015000, 0x00020000, 0x00025000, 0x00030000,
		0x00035000, 0x00040000, 0x00045000, 0x00050000, 0x00055000}

	// The modules addresss are inverted between: (2 and 4), (3 and 5),
	// affecting the output canonical coverage values in these ranges.
	testCov["f2"] = []uint32{0x00010000, 0x00015000, 0x00020000, 0x00025000, 0x00030000,
		0x00035000, 0x00040000, 0x00045000, 0x00050000, 0x00055000}
	goalOutCanonical["f2"] = []uint32{0x00010000, 0x00015000, 0x00040000, 0x00025000, 0x00045000,
		0x0004a000, 0x00020000, 0x00030000, 0x0003b000, 0x00055000}
	goalOutDecanonical["f2"] = []uint32{0x00010000, 0x00015000, 0x00020000, 0x00025000, 0x00030000,
		0x00035000, 0x00040000, 0x00045000, 0x00050000, 0x00055000}

	for name, fuzzer := range serv.fuzzers {
		// Test address conversion from instance to canonical.
		fuzzer.instModules.Canonicalize(testCov[name])
		for idx, cov := range testCov[name] {
			if cov != goalOutCanonical[name][idx] {
				failMsg := fmt.Errorf("fuzzer %v.\nExpected: 0x%x.\nReturned: 0x%x",
					name, goalOutCanonical[name][idx], cov)
				t.Fatalf("failed in canonicalization. %v", failMsg)
			}
		}

		// Test address conversion from canonical to instance.
		fuzzer.instModules.Decanonicalize(testCov[name])
		for idx, cov := range testCov[name] {
			if cov != goalOutDecanonical[name][idx] {
				failMsg := fmt.Errorf("fuzzer %v.\nExpected: 0x%x.\nReturned: 0x%x",
					name, goalOutDecanonical[name][idx], cov)
				t.Fatalf("failed in decanonicalization. %v", failMsg)
			}
		}
	}
}

func (serv *RPCServer) Connect(name string, modules []host.KernelModule) {
	if !serv.modulesInitialized {
		serv.canonicalModules = cover.NewCanonicalizer(modules)
		serv.modulesInitialized = true
	}

	serv.fuzzers[name] = &Fuzzer{
		instModules: serv.canonicalModules.NewInstance(modules),
	}
}
