// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vm

import (
	"fmt"
)

type Instance interface {
	Run()
}

type ctorFunc func(workdir string, syscalls map[int]bool, port, index int, params []byte) (Instance, error)

var ctors = make(map[string]ctorFunc)

func Register(typ string, ctor ctorFunc) {
	ctors[typ] = ctor
}

func Create(typ string, workdir string, syscalls map[int]bool, port, index int, params []byte) (Instance, error) {
	ctor := ctors[typ]
	if ctor == nil {
		return nil, fmt.Errorf("unknown instance type '%v'", typ)
	}
	return ctor(workdir, syscalls, port, index, params)
}
