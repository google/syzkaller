// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"sort"

	"github.com/google/syzkaller/pkg/host"
)

type Canonicalizer struct {
	// Map of modules stored as module name:kernel offset.
	modules map[string]uint32

	// Contains a sorted list of the canonical module addresses.
	moduleKeys []uint32
}

type CanonicalizerInstance struct {
	canonical Canonicalizer

	// Contains a sorted list of the instance's module addresses.
	moduleKeys []uint32

	// Contains a map of the uint32 address to the necessary offset.
	instToCanonicalMap map[uint32]*canonicalizerModule
	canonicalToInstMap map[uint32]*canonicalizerModule
}

// Contains the offset and final address of each module.
type canonicalizerModule struct {
	offset  int
	endAddr uint32
}

func NewCanonicalizer(modules []host.KernelModule) *Canonicalizer {
	// Create a map of canonical module offsets by name.
	canonicalModules := make(map[string]uint32)
	for _, module := range modules {
		canonicalModules[module.Name] = uint32(module.Addr)
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
	// Save sorted list of module offsets.
	moduleKeys := make([]uint32, len(modules))
	setModuleKeys(moduleKeys, modules)

	// Create a hash between the "canonical" module addresses and each VM instance.
	instToCanonicalMap := make(map[uint32]*canonicalizerModule)
	canonicalToInstMap := make(map[uint32]*canonicalizerModule)
	for _, module := range modules {
		canonicalAddr := can.modules[module.Name]
		instAddr := uint32(module.Addr)

		canonicalModule := &canonicalizerModule{
			offset:  int(instAddr) - int(canonicalAddr),
			endAddr: uint32(module.Size) + canonicalAddr,
		}
		canonicalToInstMap[canonicalAddr] = canonicalModule

		instModule := &canonicalizerModule{
			offset:  int(canonicalAddr) - int(instAddr),
			endAddr: uint32(module.Size) + instAddr,
		}
		instToCanonicalMap[instAddr] = instModule
	}

	return &CanonicalizerInstance{
		canonical:          *can,
		moduleKeys:         moduleKeys,
		instToCanonicalMap: instToCanonicalMap,
		canonicalToInstMap: canonicalToInstMap,
	}
}

func (ci *CanonicalizerInstance) Canonicalize(cov []uint32) {
	convertModulePCs(ci.moduleKeys, ci.instToCanonicalMap, cov)
}

func (ci *CanonicalizerInstance) Decanonicalize(cov []uint32) {
	convertModulePCs(ci.canonical.moduleKeys, ci.canonicalToInstMap, cov)
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

func convertModulePCs(moduleKeys []uint32, conversionHash map[uint32]*canonicalizerModule, cov []uint32) {
	// Skip conversion if modules are not used.
	if len(moduleKeys) == 0 {
		return
	}
	for idx, pc := range cov {
		// Determine which module each pc belongs to.
		moduleIdx, _ := sort.Find(len(moduleKeys), func(i int) int {
			if pc < moduleKeys[i] {
				return -1
			}
			return +1
		})
		// Sort.Find returns the index above the correct module.
		moduleIdx -= 1
		// Check if address is above the first module address.
		if moduleIdx >= 0 {
			module := conversionHash[moduleKeys[moduleIdx]]
			// If the address is within the found module add the offset.
			if pc < module.endAddr {
				cov[idx] = uint32(int(pc) + module.offset)
			}
		}
	}
}
