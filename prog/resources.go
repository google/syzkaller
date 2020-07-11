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

func (target *Target) calcResourceCtors(res *ResourceDesc, precise bool) []*Syscall {
	var metas []*Syscall
	for _, ctor := range res.Ctors {
		if !precise || ctor.Precise {
			metas = append(metas, target.Syscalls[ctor.Call])
		}
	}
	if res.Kind[0] == timespecRes.Name {
		if c := target.SyscallMap["clock_gettime"]; c != nil {
			metas = append(metas, c)
		}
	}
	return metas
}

func (target *Target) populateResourceCtors() {
	// Find resources that are created by each call.
	callsResources := make([][]*ResourceDesc, len(target.Syscalls))
	ForeachType(target.Syscalls, func(typ Type, ctx TypeCtx) {
		switch typ1 := typ.(type) {
		case *ResourceType:
			if ctx.Dir != DirIn {
				callsResources[ctx.Meta.ID] = append(callsResources[ctx.Meta.ID], typ1.Desc)
			}
		}
	})

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
				res.Ctors = append(res.Ctors, ResourceCtor{call, true})
			}
			if impreciseOk {
				res.Ctors = append(res.Ctors, ResourceCtor{call, false})
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
	var resources []*ResourceDesc
	ForeachCallType(c, func(typ Type, ctx TypeCtx) {
		if ctx.Dir == DirOut {
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

func (target *Target) getOutputResources(c *Syscall) []*ResourceDesc {
	var resources []*ResourceDesc
	ForeachCallType(c, func(typ Type, ctx TypeCtx) {
		switch typ1 := typ.(type) {
		case *ResourceType:
			if ctx.Dir != DirIn {
				resources = append(resources, typ1.Desc)
			}
		}
	})
	if c.CallName == "clock_gettime" {
		resources = append(resources, timespecRes)
	}
	return resources
}

func (target *Target) transitivelyEnabled(enabled map[*Syscall]bool) (map[*Syscall]bool, map[string]bool) {
	supported := make(map[*Syscall]bool, len(enabled))
	canCreate := make(map[string]bool, len(enabled))
	for {
		n := len(supported)
		for c := range enabled {
			if supported[c] {
				continue
			}
			ready := true
			for _, res := range c.inputResources {
				if !canCreate[res.Name] {
					ready = false
					break
				}
			}
			if ready {
				supported[c] = true
				for _, res := range c.outputResources {
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
				for _, call := range target.calcResourceCtors(res, true) {
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
