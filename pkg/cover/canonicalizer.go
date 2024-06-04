// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"fmt"
	"sort"

	"github.com/google/syzkaller/pkg/log"
)

type Canonicalizer struct {
	// Map of modules stored as module name:kernel module.
	modules map[string]KernelModule

	// Contains a sorted list of the canonical module addresses.
	moduleKeys []uint64
}

type CanonicalizerInstance struct {
	canonical Canonicalizer

	// Contains the canonicalize and decanonicalize conversion maps.
	canonicalize   *Convert
	decanonicalize *Convert
}

// Contains the current conversion maps used.
type Convert struct {
	conversionHash map[uint64]*canonicalizerModule
	moduleKeys     []uint64
}

type convertContext struct {
	errCount int
	errPC    uint64
	convert  *Convert
}

// Contains the offset and final address of each module.
type canonicalizerModule struct {
	offset  int64
	name    string
	endAddr uint64
	// Discard coverage from current module.
	// Set to true if module is not present in canonical.
	discard bool
}

func NewCanonicalizer(modules []KernelModule, flagSignal bool) *Canonicalizer {
	// Return if not using canonicalization.
	if len(modules) == 0 || !flagSignal {
		return &Canonicalizer{}
	}
	// Create a map of canonical module offsets by name.
	canonicalModules := make(map[string]KernelModule)
	for _, module := range modules {
		canonicalModules[module.Name] = module
	}

	// Store sorted canonical address keys.
	canonicalModuleKeys := make([]uint64, len(modules))
	setModuleKeys(canonicalModuleKeys, modules)
	return &Canonicalizer{
		modules:    canonicalModules,
		moduleKeys: canonicalModuleKeys,
	}
}

func (can *Canonicalizer) NewInstance(modules []KernelModule) *CanonicalizerInstance {
	if can.moduleKeys == nil {
		return &CanonicalizerInstance{}
	}
	// Save sorted list of module offsets.
	moduleKeys := make([]uint64, len(modules))
	setModuleKeys(moduleKeys, modules)

	// Create a hash between the "canonical" module addresses and each VM instance.
	instToCanonicalMap := make(map[uint64]*canonicalizerModule)
	canonicalToInstMap := make(map[uint64]*canonicalizerModule)
	for _, module := range modules {
		discard := false
		canonicalAddr := uint64(0)
		canonicalModule, found := can.modules[module.Name]
		if !found || canonicalModule.Size != module.Size {
			log.Errorf("kernel build has changed; instance module %v differs from canonical", module.Name)
			discard = true
		}
		if found {
			canonicalAddr = canonicalModule.Addr
		}

		instAddr := module.Addr

		canonicalToInstMap[canonicalAddr] = &canonicalizerModule{
			offset:  int64(instAddr - canonicalAddr),
			name:    module.Name,
			endAddr: module.Size + canonicalAddr,
			discard: discard,
		}

		instToCanonicalMap[instAddr] = &canonicalizerModule{
			offset:  int64(canonicalAddr - instAddr),
			name:    module.Name,
			endAddr: module.Size + instAddr,
			discard: discard,
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

func (ci *CanonicalizerInstance) Canonicalize(elems []uint64) []uint64 {
	return ci.canonicalize.convertPCs(elems)
}

func (ci *CanonicalizerInstance) Decanonicalize(elems []uint64) []uint64 {
	return ci.decanonicalize.convertPCs(elems)
}

// Store sorted list of addresses. Used to binary search when converting PCs.
func setModuleKeys(moduleKeys []uint64, modules []KernelModule) {
	for idx, module := range modules {
		moduleKeys[idx] = module.Addr
	}

	// Sort modules by address.
	sort.Slice(moduleKeys, func(i, j int) bool { return moduleKeys[i] < moduleKeys[j] })
}

func findModule(pc uint64, moduleKeys []uint64) (moduleIdx int) {
	moduleIdx, _ = sort.Find(len(moduleKeys), func(moduleIdx int) int {
		if pc < moduleKeys[moduleIdx] {
			return -1
		}
		return +1
	})
	// Sort.Find returns the index above the correct module.
	return moduleIdx - 1
}

func (convert *Convert) convertPCs(pcs []uint64) []uint64 {
	if convert == nil {
		return pcs
	}
	var ret []uint64
	convCtx := &convertContext{convert: convert}
	for _, pc := range pcs {
		if newPC, ok := convert.convertPC(pc); ok {
			ret = append(ret, newPC)
		} else {
			convCtx.discard(pc)
		}
	}
	if msg := convCtx.discarded(); msg != "" {
		log.Logf(4, "error in PC/signal conversion: %v", msg)
	}
	return ret
}

func (convert *Convert) convertPC(pc uint64) (uint64, bool) {
	moduleIdx := findModule(pc, convert.moduleKeys)
	// Check if address is above the first module offset.
	if moduleIdx >= 0 {
		module, found := convert.conversionHash[convert.moduleKeys[moduleIdx]]
		if !found {
			return pc, false
		}
		// If the address is within the found module add the offset.
		if pc < module.endAddr {
			if module.discard {
				return pc, false
			}
			if module.name != "" {
				pc = uint64(int64(pc) + module.offset)
			}
		}
	}
	return pc, true
}

func (cc *convertContext) discarded() string {
	if cc.errCount == 0 {
		return ""
	}
	errMsg := fmt.Sprintf("discarded 0x%x (and %v other PCs) during conversion", cc.errPC, cc.errCount)
	return fmt.Sprintf("%v; not found in module map", errMsg)
}

func (cc *convertContext) discard(pc uint64) {
	cc.errCount += 1
	if cc.errPC == 0 {
		cc.errPC = pc
	}
}
