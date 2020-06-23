// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"github.com/google/syzkaller/pkg/compiler"
)

type windows struct{}

func (*windows) prepare(sourcedir string, build bool, arches []*Arch) error {
	return nil
}

func (*windows) prepareArch(arch *Arch) error {
	return nil
}

func (*windows) processFile(arch *Arch, info *compiler.ConstInfo) (map[string]uint64, map[string]bool, error) {
	params := &extractParams{
		DeclarePrintf: true,
		TargetEndian:  arch.target.HostEndian,
	}
	return extract(info, "cl", nil, params)
}
