// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"strings"

	"github.com/google/syzkaller/prog"
)

func (arch *arch) generateIptables(g *prog.Gen, typ prog.Type, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	if old == nil {
		arg = g.GenerateSpecialArg(typ, &calls)
	} else {
		arg = old
		calls = g.MutateArg(arg)
	}
	tableArg := arg.(*prog.UnionArg).Option.(*prog.GroupArg)
	if len(tableArg.Inner) != 17 {
		panic("iptable is expected to have 17 fields")
	}
	entriesArg := tableArg.Inner[16].(*prog.GroupArg)
	if len(entriesArg.Inner) != 2 {
		panic("iptable entries is expected to have 2 fields")
	}
	underflowArg := entriesArg.Inner[0].(*prog.GroupArg)
	entriesArray := entriesArg.Inner[1].(*prog.GroupArg)
	// Collect offsets of entries.
	offsets := make([]uint64, len(entriesArray.Inner))
	pos := underflowArg.Size()
	for i, entryArg := range entriesArray.Inner {
		offsets[i] = pos
		pos += entryArg.Size()
	}
	genOffset := func() uint64 {
		if g.Rand().Intn(100) == 0 {
			// Assign the underflow entry once in a while.
			// We have it in underflow hooks, so no point in using it frequently.
			return 0
		} else {
			return offsets[g.Rand().Intn(len(offsets))]
		}
	}
	// Assign offsets to used hooks.
	for hook := 4; hook < 9; hook++ {
		hookArg := tableArg.Inner[hook].(*prog.ConstArg)
		if hookArg.Type().(*prog.ConstType).Val == uint64(^uint32(0)) {
			continue // unused hook
		}
		hookArg.Val = genOffset()
	}
	// Now update standard target jump offsets.
	prog.ForeachSubarg(arg, func(arg, _ prog.Arg, _ *[]prog.Arg) {
		if !strings.HasPrefix(arg.Type().Name(), `xt_target_t["", `) {
			return
		}
		targetArg := arg.(*prog.GroupArg)
		valArg := targetArg.Inner[3].(*prog.ConstArg)
		if flagsType, ok := valArg.Type().(*prog.FlagsType); ok && int64(valArg.Val) < 0 {
			for _, val := range flagsType.Vals {
				if val == valArg.Val {
					return // verdict
				}
			}
		}
		valArg.Val = genOffset()
	})
	return
}
