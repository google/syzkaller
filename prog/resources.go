// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
)

// We need to support structs as resources,
// but for now we just special-case timespec/timeval.
var timespecRes = &ResourceDesc{
	Name: "timespec",
	Kind: []string{"timespec"},
}

func (target *Target) calcResourceCtors(kind []string, precise bool) []*Syscall {

	//fmt.Printf("calcResourceCtors: kind=%+v\n", kind)

	// Find calls that produce the necessary resources.
	var metas []*Syscall
	for _, meta := range target.Syscalls {
		// Recurse into arguments to see if there is an out/inout arg of necessary type.
		ok := false
		//if meta.Name != "pipe$9p" { continue }
		//fmt.Printf("found pipe$9p\n")

		ForeachType(meta, func(typ Type) {
			if ok {
				return
			}
			switch typ1 := typ.(type) {
			case *ResourceType:
				//fmt.Printf("   output: %+v\n", typ1.Desc.Kind)
				if typ1.Dir() != DirIn && isCompatibleResourceImpl(kind, typ1.Desc.Kind, precise) {
					ok = true
				}
			}
		})
		if ok {
			metas = append(metas, meta)
		}
	}
	if kind[0] == timespecRes.Name {
		if c := target.SyscallMap["clock_gettime"]; c != nil {
			metas = append(metas, c)
		}
	}
	return metas
}

// isCompatibleResource returns true if resource of kind src can be passed as an argument of kind dst.
func (target *Target) isCompatibleResource(dst, src string) bool {
	if dst == target.any.res16.TypeName ||
		dst == target.any.res32.TypeName ||
		dst == target.any.res64.TypeName ||
		dst == target.any.resdec.TypeName ||
		dst == target.any.reshex.TypeName ||
		dst == target.any.resoct.TypeName {
		return true
	}
	dstRes := target.resourceMap[dst]
	if dstRes == nil {
		panic(fmt.Sprintf("unknown resource '%v'", dst))
	}
	srcRes := target.resourceMap[src]
	if srcRes == nil {
		panic(fmt.Sprintf("unknown resource '%v'", src))
	}
	return isCompatibleResourceImpl(dstRes.Kind, srcRes.Kind, false)
}

// isCompatibleResourceImpl returns true if resource of kind src can be passed as an argument of kind dst.
// If precise is true, then it does not allow passing a less specialized resource (e.g. fd)
// as a more specialized resource (e.g. socket). Otherwise it does.
func isCompatibleResourceImpl(dst, src []string, precise bool) bool {
	//fmt.Printf("isCompatibleResourceImpl: %+v/%v vs %+v/%v\n", dst, len(dst), src, len(src))
	if len(dst) > len(src) {
		// dst is more specialized, e.g dst=socket, src=fd.
		if precise {
			//fmt.Printf("     = false1\n")
			return false
		}
		dst = dst[:len(src)]
	}
	if len(src) > len(dst) {
		// src is more specialized, e.g dst=fd, src=socket.
		src = src[:len(dst)]
	}
	for i, k := range dst {
		if k != src[i] {
			//fmt.Printf("     = false2\n")
			return false
		}
	}
	//fmt.Printf("     = true\n")
	return true
}

func (target *Target) inputResources(c *Syscall) []*ResourceDesc {
	var resources []*ResourceDesc
	ForeachType(c, func(typ Type) {
		if typ.Dir() == DirOut {
			return
		}
		switch typ1 := typ.(type) {
		case *ResourceType:
			if !typ1.IsOptional {
				resources = append(resources, typ1.Desc)
			}
		case *StructType:
			if target.OS == "linux" && (typ1.Name() == "timespec" || typ1.Name() == "timeval") {
				resources = append(resources, timespecRes)
			}
		}
	})
	return resources
}

func (target *Target) outputResources(c *Syscall) []*ResourceDesc {
	var resources []*ResourceDesc
	ForeachType(c, func(typ Type) {
		switch typ1 := typ.(type) {
		case *ResourceType:
			if typ1.Dir() != DirIn {
				resources = append(resources, typ1.Desc)
			}
		}
	})
	if c.CallName == "clock_gettime" {
		resources = append(resources, timespecRes)
	}
	return resources
}

func (target *Target) TransitivelyEnabledCalls(enabled map[*Syscall]bool) (map[*Syscall]bool, map[*Syscall]string) {
	supported := make(map[*Syscall]bool)
	disabled := make(map[*Syscall]string)
	canCreate := make(map[string]bool)
	inputResources := make(map[*Syscall][]*ResourceDesc)
	for c := range enabled {
		inputResources[c] = target.inputResources(c)

		if c.Name == "pipe$9p" {
			fmt.Printf("%v: input resource: %+v\n", c.Name, inputResources[c])
		}
	}
	for {
		n := len(supported)
		for c := range enabled {
			if supported[c] {
				continue
			}
			ready := true
			for _, res := range inputResources[c] {
				if !canCreate[res.Name] {
					ready = false
					break
				}
			}
			if ready {
				supported[c] = true
				for _, res := range target.outputResources(c) {
					for _, kind := range res.Kind {
						canCreate[kind] = true
					}
				}
			}
		}
		if n == len(supported) {
			break
		}
	}
	ctors := make(map[string][]string)
	for c := range enabled {
		if supported[c] {
			continue
		}
		for _, res := range inputResources[c] {
			if canCreate[res.Name] {
				continue
			}
			if ctors[res.Name] == nil {
				var names []string
				for _, call := range target.calcResourceCtors(res.Kind, true) {
					names = append(names, call.Name)
				}
				ctors[res.Name] = names
			}
			disabled[c] = fmt.Sprintf("no syscalls can create resource %v,"+
				" enable some syscalls that can create it %v",
				res.Name, ctors[res.Name])
			break
		}
	}
	if len(enabled) != len(supported)+len(disabled) {
		panic("lost syscalls")
	}
	return supported, disabled
}
