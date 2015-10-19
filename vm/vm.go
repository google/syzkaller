// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vm

import (
	"fmt"
)

type Instance interface {
	Run()
}

type Config struct {
	Workdir         string
	ManagerPort     int
	Params          []byte
	EnabledSyscalls string
	NoCover         bool
}

type ctorFunc func(cfg *Config, index int) (Instance, error)

var ctors = make(map[string]ctorFunc)

func Register(typ string, ctor ctorFunc) {
	ctors[typ] = ctor
}

func Create(typ string, cfg *Config, index int) (Instance, error) {
	ctor := ctors[typ]
	if ctor == nil {
		return nil, fmt.Errorf("unknown instance type '%v'", typ)
	}
	return ctor(cfg, index)
}
