// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"sort"

	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/signal"
)

type Canonicalizer struct {
	// Map of modules stored as module name:kernel module.
	modules map[string]host.KernelModule

	// Contains a sorted list of the canonical module addresses.
	moduleKeys []uint32
}

type CanonicalizerInstance struct {
	canonical Canonicalizer

	// Contains the canonicalize and decanonicalize conversion maps.
	canonicalize   *Convert
	decanonicalize *Convert
}

// Contains the current conversion maps used.
type Convert struct {
	conversionHash map[uint32]*canonicalizerModule
	moduleKeys     []uint32
}

// Contains the offset and final address of each module.
type canonicalizerModule struct {
	offset  int
	endAddr uint32
}

func NewCanonicalizer(modules []host.KernelModule, flagSignal bool) *Canonicalizer {
	// Return if not using canonicalization.
	if len(modules) == 0 || !flagSignal {
		return &Canonicalizer{}
	}
	// Create a map of canonical module offsets by name.
	canonicalModules := make(map[string]host.KernelModule)
	for _, module := range modules {
		canonicalModules[module.Name] = module
	}

	// Store sorted canonical address keys.
	canonicalModuleKeys := make([]uint32, len(modules))
	setModuleKeys(canonicalModuleKeys, modules)
	return &Canonicalizer{
		modules:    canonicalModules,
		moduleKeys: canonicalModuleKeys,
	}
}

func (can *Canonicalizer) NewInstance(modules []host.KernelModule) *CanonicalizerInstance {
	if can.moduleKeys == nil {
		return &CanonicalizerInstance{}
	}
	// Save sorted list of module offsets.
	moduleKeys := make([]uint32, len(modules))
	setModuleKeys(moduleKeys, modules)

	// Create a hash between the "canonical" module addresses and each VM instance.
	instToCanonicalMap := make(map[uint32]*canonicalizerModule)
	canonicalToInstMap := make(map[uint32]*canonicalizerModule)
	for _, module := range modules {
		canonicalModule, found := can.modules[module.Name]
		if !found || canonicalModule.Size != module.Size {
			log.Fatalf("kernel build has changed; instance module %v differs from canonical", module.Name)
		}

		instAddr := uint32(module.Addr)
		canonicalAddr := uint32(canonicalModule.Addr)

		canonicalToInstMap[canonicalAddr] = &canonicalizerModule{
			offset:  int(instAddr) - int(canonicalAddr),
			endAddr: uint32(module.Size) + canonicalAddr,
		}

		instToCanonicalMap[instAddr] = &canonicalizerModule{
			offset:  int(canonicalAddr) - int(instAddr),
			endAddr: uint32(module.Size) + instAddr,
		}
	}

	return &CanonicalizerInstance{
		canonical: *can,
		canonicalize: &Convert{
			conversionHash: instToCanonicalMap,
			moduleKeys:     moduleKeys,
		},
		decanonicalize: &Convert{
			conversionHash: canonicalToInstMap,
			moduleKeys:     can.moduleKeys,
		},
	}
}

func (ci *CanonicalizerInstance) Canonicalize(cov []uint32, sign signal.Serial) {
	if ci.canonical.moduleKeys == nil {
		return
	}
	ci.canonicalize.convertPCs(cov, sign)
}

func (ci *CanonicalizerInstance) Decanonicalize(cov []uint32, sign signal.Serial) {
	if ci.canonical.moduleKeys == nil {
		return
	}
	ci.decanonicalize.convertPCs(cov, sign)
}

func (ci *CanonicalizerInstance) DecanonicalizeFilter(bitmap map[uint32]uint32) map[uint32]uint32 {
	// Skip conversion if modules or filter are not used.
	if ci.canonical.moduleKeys == nil || len(bitmap) == 0 {
		return bitmap
	}
	instBitmap := make(map[uint32]uint32)
	for pc, val := range bitmap {
		instBitmap[ci.decanonicalize.convertPC(pc)] = val
	}
	return instBitmap
}

// Store sorted list of addresses. Used to binary search when converting PCs.
func setModuleKeys(moduleKeys []uint32, modules []host.KernelModule) {
	for idx, module := range modules {
		// Truncate PCs to uint32, assuming that they fit into 32 bits.
		// True for x86_64 and arm64 without KASLR.
		moduleKeys[idx] = uint32(module.Addr)
	}

	// Sort modules by address.
	sort.Slice(moduleKeys, func(i, j int) bool { return moduleKeys[i] < moduleKeys[j] })
}

func findModule(pc uint32, moduleKeys []uint32) (moduleIdx int) {
	moduleIdx, _ = sort.Find(len(moduleKeys), func(moduleIdx int) int {
		if pc < moduleKeys[moduleIdx] {
			return -1
		}
		return +1
	})
	// Sort.Find returns the index above the correct module.
	return moduleIdx - 1
}

func (convert *Convert) convertPCs(cov []uint32, sign signal.Serial) {
	// Convert coverage.
	for idx, pc := range cov {
		cov[idx] = convert.convertPC(pc)
	}
	// Convert signals.
	for idx, elem := range sign.Elems {
		sign.UpdateElem(idx, convert.convertPC(uint32(elem)))
	}
}

func (convert *Convert) convertPC(pc uint32) uint32 {
	moduleIdx := findModule(pc, convert.moduleKeys)
	// Check if address is above the first module offset.
	if moduleIdx >= 0 {
		module := convert.conversionHash[convert.moduleKeys[moduleIdx]]
		// If the address is within the found module add the offset.
		if pc < module.endAddr {
			pc = uint32(int(pc) + module.offset)
		}
	}
	return pc
}
