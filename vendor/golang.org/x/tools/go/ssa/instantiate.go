// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import (
	"fmt"
	"go/types"
	"sync"

	"golang.org/x/tools/internal/typeparams"
)

// A generic records information about a generic origin function,
// including a cache of existing instantiations.
type generic struct {
	instancesMu sync.Mutex
	instances   map[*typeList]*Function // canonical type arguments to an instance.
}

// instance returns a Function that is the instantiation of generic
// origin function fn with the type arguments targs.
//
// Any created instance is added to cr.
//
// Acquires fn.generic.instancesMu.
func (fn *Function) instance(targs []types.Type, cr *creator) *Function {
	key := fn.Prog.canon.List(targs)

	gen := fn.generic

	gen.instancesMu.Lock()
	defer gen.instancesMu.Unlock()
	inst, ok := gen.instances[key]
	if !ok {
		inst = createInstance(fn, targs, cr)
		if gen.instances == nil {
			gen.instances = make(map[*typeList]*Function)
		}
		gen.instances[key] = inst
	}
	return inst
}

// createInstance returns the instantiation of generic function fn using targs.
// If the instantiation is created, this is added to cr.
//
// Requires fn.generic.instancesMu.
func createInstance(fn *Function, targs []types.Type, cr *creator) *Function {
	prog := fn.Prog

	// Compute signature.
	var sig *types.Signature
	var obj *types.Func
	if recv := fn.Signature.Recv(); recv != nil {
		// method
		obj = prog.canon.instantiateMethod(fn.object, targs, prog.ctxt)
		sig = obj.Type().(*types.Signature)
	} else {
		// function
		instSig, err := typeparams.Instantiate(prog.ctxt, fn.Signature, targs, false)
		if err != nil {
			panic(err)
		}
		instance, ok := instSig.(*types.Signature)
		if !ok {
			panic("Instantiate of a Signature returned a non-signature")
		}
		obj = fn.object // instantiation does not exist yet
		sig = prog.canon.Type(instance).(*types.Signature)
	}

	// Choose strategy (instance or wrapper).
	var (
		synthetic string
		subst     *subster
		build     buildFunc
	)
	if prog.mode&InstantiateGenerics != 0 && !prog.parameterized.anyParameterized(targs) {
		synthetic = fmt.Sprintf("instance of %s", fn.Name())
		if fn.syntax != nil {
			scope := typeparams.OriginMethod(obj).Scope()
			subst = makeSubster(prog.ctxt, scope, fn.typeparams, targs, false)
			build = (*builder).buildFromSyntax
		} else {
			build = (*builder).buildParamsOnly
		}
	} else {
		synthetic = fmt.Sprintf("instantiation wrapper of %s", fn.Name())
		build = (*builder).buildInstantiationWrapper
	}

	/* generic instance or instantiation wrapper */
	instance := &Function{
		name:           fmt.Sprintf("%s%s", fn.Name(), targs), // may not be unique
		object:         obj,
		Signature:      sig,
		Synthetic:      synthetic,
		syntax:         fn.syntax,    // \
		info:           fn.info,      //  } empty for non-created packages
		goversion:      fn.goversion, // /
		build:          build,
		topLevelOrigin: fn,
		pos:            obj.Pos(),
		Pkg:            nil,
		Prog:           fn.Prog,
		typeparams:     fn.typeparams, // share with origin
		typeargs:       targs,
		subst:          subst,
	}
	cr.Add(instance)
	return instance
}
