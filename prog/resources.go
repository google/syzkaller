// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
)

var (
	// We need to support structs as resources,
	// but for now we just special-case timespec/timeval.
	timespecRes = &ResourceDesc{
		Name: "timespec",
		Kind: []string{"timespec"},
	}
	// On one hand these are resources, but they don't have constructors.
	// It can make sense to provide generic support for such things,
	// but for now we just special-case them.
	filenameRes = &ResourceDesc{
		Name: "filename",
		Kind: []string{"filename"},
	}
	vmaRes = &ResourceDesc{
		Name: "vma",
		Kind: []string{"vma"},
	}
)

func (target *Target) calcResourceCtors(res *ResourceDesc, preciseOnly bool) []ResourceCtor {
	var ret []ResourceCtor
	for _, ctor := range res.Ctors {
		if !preciseOnly || ctor.Precise {
			ret = append(ret, ctor)
		}
	}
	if res.Kind[0] == timespecRes.Name {
		if c := target.SyscallMap["clock_gettime"]; c != nil {
			ret = append(ret, ResourceCtor{c, true})
		}
	}
	return ret
}

func (target *Target) populateResourceCtors() {
	// Find resources that are created by each call.
	callsResources := make([][]*ResourceDesc, len(target.Syscalls))
	for _, meta := range target.Syscalls {
		dedup := make(map[*ResourceDesc]bool)
		ForeachCallType(meta, func(typ Type, ctx *TypeCtx) {
			if typ.Optional() {
				ctx.Stop = true
				return
			}
			switch typ1 := typ.(type) {
			case *UnionType:
				ctx.Stop = true
			case *ResourceType:
				if ctx.Dir == DirIn || dedup[typ1.Desc] || meta.Attrs.Disabled {
					break
				}
				dedup[typ1.Desc] = true
				meta.usesResources = append(meta.usesResources, typ1.Desc)
				if !meta.Attrs.NoGenerate {
					callsResources[meta.ID] = append(callsResources[meta.ID], typ1.Desc)
					meta.createsResources = append(meta.createsResources, typ1.Desc)
				}
			}
		})
	}

	if c := target.SyscallMap["clock_gettime"]; c != nil {
		c.usesResources = append(c.usesResources, timespecRes)
		c.createsResources = append(c.createsResources, timespecRes)
		callsResources[c.ID] = append(callsResources[c.ID], timespecRes)
	}

	for _, c := range target.Syscalls {
		c.inputResources = target.getInputResources(c)
		c.usesResources = append(c.usesResources, c.inputResources...)
	}

	// Populate resource ctors accounting for resource compatibility.
	for _, res := range target.Resources {
		for call, callResources := range callsResources {
			preciseOk := false
			impreciseOk := false
			for _, callRes := range callResources {
				if preciseOk && impreciseOk {
					break
				}
				if isCompatibleResourceImpl(res.Kind, callRes.Kind, true) {
					preciseOk = true
				}
				if isCompatibleResourceImpl(res.Kind, callRes.Kind, false) {
					impreciseOk = true
				}
			}
			if preciseOk {
				res.Ctors = append(res.Ctors, ResourceCtor{target.Syscalls[call], true})
			}
			if impreciseOk {
				res.Ctors = append(res.Ctors, ResourceCtor{target.Syscalls[call], false})
			}
		}
	}
}

// isCompatibleResource returns true if resource of kind src can be passed as an argument of kind dst.
func (target *Target) isCompatibleResource(dst, src string) bool {
	if target.isAnyRes(dst) {
		return true
	}
	if target.isAnyRes(src) {
		return false
	}
	dstRes := target.resourceMap[dst]
	if dstRes == nil {
		panic(fmt.Sprintf("unknown resource %q", dst))
	}
	srcRes := target.resourceMap[src]
	if srcRes == nil {
		panic(fmt.Sprintf("unknown resource %q", src))
	}
	return isCompatibleResourceImpl(dstRes.Kind, srcRes.Kind, false)
}

// isCompatibleResourceImpl returns true if resource of kind src can be passed as an argument of kind dst.
// If precise is true, then it does not allow passing a less specialized resource (e.g. fd)
// as a more specialized resource (e.g. socket). Otherwise it does.
func isCompatibleResourceImpl(dst, src []string, precise bool) bool {
	if len(dst) > len(src) {
		// Destination resource is more specialized, e.g dst=socket, src=fd.
		if precise {
			return false
		}
		dst = dst[:len(src)]
	}
	if len(src) > len(dst) {
		// Source resource is more specialized, e.g dst=fd, src=socket.
		src = src[:len(dst)]
	}
	for i, k := range dst {
		if k != src[i] {
			return false
		}
	}
	return true
}

func (target *Target) getInputResources(c *Syscall) []*ResourceDesc {
	dedup := make(map[*ResourceDesc]bool)
	var resources []*ResourceDesc
	ForeachCallType(c, func(typ Type, ctx *TypeCtx) {
		if ctx.Dir == DirOut {
			return
		}
		switch typ1 := typ.(type) {
		case *ResourceType:
			if !ctx.Optional && !dedup[typ1.Desc] {
				dedup[typ1.Desc] = true
				resources = append(resources, typ1.Desc)
			}
		case *StructType:
			if target.OS == "linux" && !dedup[timespecRes] && (typ1.Name() == "timespec" || typ1.Name() == "timeval") {
				dedup[timespecRes] = true
				resources = append(resources, timespecRes)
			}
		}
	})
	return resources
}

func (target *Target) transitivelyEnabled(enabled map[*Syscall]bool) (map[*Syscall]bool, map[string]bool) {
	supported := make(map[*Syscall]bool, len(enabled))
	canCreate := make(map[string]bool, len(enabled))
	for {
		n := len(supported)
	nextCall:
		for c := range enabled {
			if supported[c] {
				continue
			}
			for _, res := range c.inputResources {
				if !canCreate[res.Name] {
					continue nextCall
				}
			}
			supported[c] = true
			for _, res := range c.createsResources {
				for _, kind := range res.Kind {
					canCreate[kind] = true
				}
			}
		}
		if n == len(supported) {
			break
		}
	}
	return supported, canCreate
}

func (target *Target) TransitivelyEnabledCalls(enabled map[*Syscall]bool) (map[*Syscall]bool, map[*Syscall]string) {
	supported, canCreate := target.transitivelyEnabled(enabled)
	disabled := make(map[*Syscall]string)
	ctors := make(map[string][]string)
	for c := range enabled {
		if supported[c] {
			continue
		}
		for _, res := range c.inputResources {
			if canCreate[res.Name] {
				continue
			}
			if ctors[res.Name] == nil {
				var names []string
				for _, ctor := range target.calcResourceCtors(res, true) {
					names = append(names, ctor.Call.Name)
				}
				if len(names) > 5 {
					names = append(names[:3], "...")
				}
				ctors[res.Name] = names
			}
			disabled[c] = fmt.Sprintf("%v %v", res.Name, ctors[res.Name])
			break
		}
	}
	if len(enabled) != len(supported)+len(disabled) {
		panic("lost syscalls")
	}
	return supported, disabled
}
