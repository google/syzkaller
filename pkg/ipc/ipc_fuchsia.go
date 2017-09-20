// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build fuchsia

package ipc

import (
	"github.com/google/syzkaller/prog"
)

type Env struct {
	In []byte

	StatExecs    uint64
	StatRestarts uint64
}

func MakeEnv(bin string, pid int, config Config) (*Env, error) {
	env := &Env{}
	return env, nil
}

func (env *Env) Close() error {
	return nil
}

func (env *Env) Exec(opts *ExecOpts, p *prog.Prog) (output []byte, info []CallInfo, failed, hanged bool, err0 error) {
	return
}
