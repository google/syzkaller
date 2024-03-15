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
	cov         []uint32
	goalCov     []uint32
	bitmap      map[uint32]uint32
	goalBitmap  map[uint32]uint32
	sign        []uint32
	goalSign    []uint32
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
	serv.connect("f1", nil, true)
	serv.connect("f2", nil, true)

	serv.fuzzers["f1"].cov = []uint32{0x00010000, 0x00020000, 0x00030000, 0x00040000}
	serv.fuzzers["f1"].goalCov = []uint32{0x00010000, 0x00020000, 0x00030000, 0x00040000}

	serv.fuzzers["f2"].cov = []uint32{0x00010000, 0x00020000, 0x00030000, 0x00040000}
	serv.fuzzers["f2"].goalCov = []uint32{0x00010000, 0x00020000, 0x00030000, 0x00040000}

	serv.fuzzers["f1"].bitmap = map[uint32]uint32{
		0x00010011: 1,
		0x00020FFF: 2,
		0x00030000: 3,
		0x00040000: 4,
	}
	serv.fuzzers["f1"].goalBitmap = map[uint32]uint32{
		0x00010011: 1,
		0x00020FFF: 2,
		0x00030000: 3,
		0x00040000: 4,
	}
	serv.fuzzers["f2"].bitmap = map[uint32]uint32{
		0x00010011: 1,
		0x00020FFF: 2,
		0x00030000: 3,
		0x00040000: 4,
	}
	serv.fuzzers["f2"].goalBitmap = map[uint32]uint32{
		0x00010011: 1,
		0x00020FFF: 2,
		0x00030000: 3,
		0x00040000: 4,
	}

	if err := serv.runTest(Canonicalize); err != "" {
		t.Fatalf("failed in canonicalization: %v", err)
	}

	serv.fuzzers["f1"].goalCov = []uint32{0x00010000, 0x00020000, 0x00030000, 0x00040000}
	serv.fuzzers["f1"].goalSign = serv.fuzzers["f1"].goalCov
	serv.fuzzers["f2"].goalCov = []uint32{0x00010000, 0x00020000, 0x00030000, 0x00040000}
	serv.fuzzers["f2"].goalSign = serv.fuzzers["f2"].goalCov
	if err := serv.runTest(Decanonicalize); err != "" {
		t.Fatalf("failed in decanonicalization: %v", err)
	}
}

// Confirms there is no change to PCs if coverage is disabled and fallback signals are used.
func TestDisabledSignals(t *testing.T) {
	serv := &RPCServer{
		fuzzers: make(map[string]*Fuzzer),
	}
	// Create modules at the specified address offsets.
	f1ModuleAddresses := []uint64{0x00015000, 0x00020000, 0x00030000, 0x00040000, 0x00045000}
	f1ModuleSizes := []uint64{0x5000, 0x5000, 0x10000, 0x5000, 0x10000}
	f1Modules := initModules(f1ModuleAddresses, f1ModuleSizes)
	serv.connect("f1", f1Modules, false)

	f2ModuleAddresses := []uint64{0x00015000, 0x00040000, 0x00045000, 0x00020000, 0x00030000}
	f2ModuleSizes := []uint64{0x5000, 0x5000, 0x10000, 0x5000, 0x10000}
	f2Modules := initModules(f2ModuleAddresses, f2ModuleSizes)
	serv.connect("f2", f2Modules, false)

	pcs := []uint32{0x00010000, 0x00020000, 0x00030000, 0x00040000}
	serv.fuzzers["f1"].cov = pcs
	serv.fuzzers["f1"].goalCov = pcs

	serv.fuzzers["f2"].sign = pcs
	serv.fuzzers["f2"].goalSign = pcs

	if err := serv.runTest(Canonicalize); err != "" {
		t.Fatalf("failed in canonicalization: %v", err)
	}

	serv.fuzzers["f1"].goalSign = pcs
	serv.fuzzers["f2"].goalSign = pcs
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
	serv.connect("f1", f1Modules, true)

	f2ModuleAddresses := []uint64{0x00015000, 0x00040000, 0x00045000, 0x00020000, 0x00030000}
	f2ModuleSizes := []uint64{0x5000, 0x5000, 0x10000, 0x5000, 0x10000}
	f2Modules := initModules(f2ModuleAddresses, f2ModuleSizes)
	serv.connect("f2", f2Modules, true)

	// f1 is the "canonical" fuzzer as it is first one instantiated.
	// This means that all coverage output should be the same as the inputs.
	serv.fuzzers["f1"].cov = []uint32{0x00010000, 0x00015000, 0x00020000, 0x00025000, 0x00030000,
		0x00035000, 0x00040000, 0x00045000, 0x00050000, 0x00055000}
	serv.fuzzers["f1"].goalCov = []uint32{0x00010000, 0x00015000, 0x00020000, 0x00025000, 0x00030000,
		0x00035000, 0x00040000, 0x00045000, 0x00050000, 0x00055000}

	// The modules addresss are inverted between: (2 and 4), (3 and 5),
	// affecting the output canonical coverage values in these ranges.
	serv.fuzzers["f2"].cov = []uint32{0x00010000, 0x00015000, 0x00020000, 0x00025000, 0x00030000,
		0x00035000, 0x00040000, 0x00045000, 0x00050000, 0x00055000}
	serv.fuzzers["f2"].goalCov = []uint32{0x00010000, 0x00015000, 0x00040000, 0x00025000, 0x00045000,
		0x0004a000, 0x00020000, 0x00030000, 0x0003b000, 0x00055000}

	serv.fuzzers["f1"].bitmap = map[uint32]uint32{
		0x00010011: 1,
		0x00020FFF: 2,
		0x00030000: 3,
		0x00040000: 4,
	}
	serv.fuzzers["f1"].goalBitmap = map[uint32]uint32{
		0x00010011: 1,
		0x00020FFF: 2,
		0x00030000: 3,
		0x00040000: 4,
	}
	serv.fuzzers["f2"].bitmap = map[uint32]uint32{
		0x00010011: 1,
		0x00020FFF: 2,
		0x00030000: 3,
		0x00040000: 4,
	}
	serv.fuzzers["f2"].goalBitmap = map[uint32]uint32{
		0x00010011: 1,
		0x00040FFF: 2,
		0x00045000: 3,
		0x00020000: 4,
	}

	if err := serv.runTest(Canonicalize); err != "" {
		t.Fatalf("failed in canonicalization: %v", err)
	}

	serv.fuzzers["f1"].goalCov = []uint32{0x00010000, 0x00015000, 0x00020000, 0x00025000, 0x00030000,
		0x00035000, 0x00040000, 0x00045000, 0x00050000, 0x00055000}
	serv.fuzzers["f2"].goalCov = []uint32{0x00010000, 0x00015000, 0x00020000, 0x00025000, 0x00030000,
		0x00035000, 0x00040000, 0x00045000, 0x00050000, 0x00055000}
	if err := serv.runTest(Decanonicalize); err != "" {
		t.Fatalf("failed in decanonicalization: %v", err)
	}
}

// Tests coverage conversion when modules are added after initialization.
func TestChangingModules(t *testing.T) {
	serv := &RPCServer{
		fuzzers: make(map[string]*Fuzzer),
	}

	// Create modules at the specified address offsets.
	f1ModuleAddresses := []uint64{0x00015000}
	f1ModuleSizes := []uint64{0x5000}
	f1Modules := initModules(f1ModuleAddresses, f1ModuleSizes)
	serv.connect("f1", f1Modules, true)

	f2ModuleAddresses := []uint64{0x00015000, 0x00020000}
	f2ModuleSizes := []uint64{0x5000, 0x5000}
	f2Modules := initModules(f2ModuleAddresses, f2ModuleSizes)
	serv.connect("f2", f2Modules, true)

	// Module 2 is not present in the "canonical" fuzzer, so coverage values
	// in this range should be deleted.
	serv.fuzzers["f2"].cov = []uint32{0x00010000, 0x00015000, 0x00020000, 0x00025000}
	serv.fuzzers["f2"].goalCov = []uint32{0x00010000, 0x00015000, 0x00025000}

	if err := serv.runTest(Canonicalize); err != "" {
		t.Fatalf("failed in canonicalization: %v", err)
	}

	serv.fuzzers["f2"].goalCov = []uint32{0x00010000, 0x00015000, 0x00025000}
	if err := serv.runTest(Decanonicalize); err != "" {
		t.Fatalf("failed in decanonicalization: %v", err)
	}
}

func (serv *RPCServer) runTest(val canonicalizeValue) string {
	var cov []uint32
	for name, fuzzer := range serv.fuzzers {
		if val == Canonicalize {
			cov = fuzzer.instModules.Canonicalize(fuzzer.cov)
		} else {
			cov = fuzzer.instModules.Decanonicalize(fuzzer.cov)
			instBitmap := fuzzer.instModules.DecanonicalizeFilter(fuzzer.bitmap)
			if !reflect.DeepEqual(instBitmap, fuzzer.goalBitmap) {
				return fmt.Sprintf("failed in bitmap conversion. Fuzzer %v.\nExpected: 0x%x.\nReturned: 0x%x",
					name, fuzzer.goalBitmap, instBitmap)
			}
		}
		if !reflect.DeepEqual(cov, fuzzer.goalCov) {
			return fmt.Sprintf("failed in coverage conversion. Fuzzer %v.\nExpected: 0x%x.\nReturned: 0x%x",
				name, fuzzer.goalCov, cov)
		}
		fuzzer.cov = cov
	}
	return ""
}

func (serv *RPCServer) connect(name string, modules []host.KernelModule, flagSignal bool) {
	if !serv.modulesInitialized {
		serv.canonicalModules = cover.NewCanonicalizer(modules, flagSignal)
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
