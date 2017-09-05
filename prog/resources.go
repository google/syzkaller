// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
)

func calcResourceCtors(kind []string, precise bool) []*Syscall {
	// Find calls that produce the necessary resources.
	var metas []*Syscall
	for _, meta := range Syscalls {
		// Recurse into arguments to see if there is an out/inout arg of necessary type.
		ok := false
		ForeachType(meta, func(typ Type) {
			if ok {
				return
			}
			switch typ1 := typ.(type) {
			case *ResourceType:
				if typ1.Dir() != DirIn && isCompatibleResource(kind, typ1.Desc.Kind, precise) {
					ok = true
				}
			}
		})
		if ok {
			metas = append(metas, meta)
		}
	}
	return metas
}

// IsCompatibleResource returns true if resource of kind src can be passed as an argument of kind dst.
func IsCompatibleResource(dst, src string) bool {
	dstRes := Resources[dst]
	if dstRes == nil {
		panic(fmt.Sprintf("unknown resource '%v'", dst))
	}
	srcRes := Resources[src]
	if srcRes == nil {
		panic(fmt.Sprintf("unknown resource '%v'", src))
	}
	return isCompatibleResource(dstRes.Kind, srcRes.Kind, false)
}

// isCompatibleResource returns true if resource of kind src can be passed as an argument of kind dst.
// If precise is true, then it does not allow passing a less specialized resource (e.g. fd)
// as a more specialized resource (e.g. socket). Otherwise it does.
func isCompatibleResource(dst, src []string, precise bool) bool {
	if len(dst) > len(src) {
		// dst is more specialized, e.g dst=socket, src=fd.
		if precise {
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
			return false
		}
	}
	return true
}

func (c *Syscall) InputResources() []*ResourceType {
	var resources []*ResourceType
	ForeachType(c, func(typ Type) {
		switch typ1 := typ.(type) {
		case *ResourceType:
			if typ1.Dir() != DirOut && !typ1.IsOptional {
				resources = append(resources, typ1)
			}
		}
	})
	return resources
}

func TransitivelyEnabledCalls(enabled map[*Syscall]bool) map[*Syscall]bool {
	supported := make(map[*Syscall]bool)
	for c := range enabled {
		supported[c] = true
	}
	inputResources := make(map[*Syscall][]*ResourceType)
	ctors := make(map[string][]*Syscall)
	for c := range supported {
		inputs := c.InputResources()
		inputResources[c] = inputs
		for _, res := range inputs {
			if _, ok := ctors[res.Desc.Name]; ok {
				continue
			}
			ctors[res.Desc.Name] = calcResourceCtors(res.Desc.Kind, true)
		}
	}
	for {
		n := len(supported)
		haveGettime := supported[SyscallMap["clock_gettime"]]
		for c := range supported {
			canCreate := true
			for _, res := range inputResources[c] {
				noctors := true
				for _, ctor := range ctors[res.Desc.Name] {
					if supported[ctor] {
						noctors = false
						break
					}
				}
				if noctors {
					canCreate = false
					break
				}
			}
			// We need to support structs as resources,
			// but for now we just special-case timespec/timeval.
			if canCreate && !haveGettime {
				ForeachType(c, func(typ Type) {
					if a, ok := typ.(*StructType); ok && a.Dir() != DirOut && (a.Name() == "timespec" || a.Name() == "timeval") {
						canCreate = false
					}
				})
			}
			if !canCreate {
				delete(supported, c)
			}
		}
		if n == len(supported) {
			break
		}
	}
	return supported
}
