// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:generate bash -c "TARGETARCH=amd64 go run fidlgen/main.go"
//go:generate bash -c "TARGETARCH=arm64 go run fidlgen/main.go"

package fuchsia

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func InitTarget(target *prog.Target) {
	target.MakeDataMmap = targets.MakeSyzMmap(target)
}
