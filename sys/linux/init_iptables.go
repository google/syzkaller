// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"strings"

	"github.com/google/syzkaller/prog"
)

func (arch *arch) generateIptables(g *prog.Gen, typ prog.Type, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	return arch.generateNetfilterTable(g, typ, old, true, 5)
}

func (arch *arch) generateArptables(g *prog.Gen, typ prog.Type, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	return arch.generateNetfilterTable(g, typ, old, false, 3)
}

func (arch *arch) generateNetfilterTable(g *prog.Gen, typ prog.Type, old prog.Arg,
	hasUnion bool, hookCount int) (arg prog.Arg, calls []*prog.Call) {
	const (
		hookStart     = 4
		nonHookFields = 7
		unused        = uint64(^uint32(0))
	)
	if old == nil {
		arg = g.GenerateSpecialArg(typ, &calls)
	} else {
		// TODO(dvyukov): try to restore original hook order after mutation
		// instead of assigning brand new offsets.
		arg = old
		calls = g.MutateArg(arg)
	}
	var tableArg *prog.GroupArg
	if hasUnion {
		tableArg = arg.(*prog.UnionArg).Option.(*prog.GroupArg)
	} else {
		tableArg = arg.(*prog.GroupArg)
	}
	numFileds := nonHookFields + 2*hookCount
	if len(tableArg.Inner) != numFileds {
		panic("wrong number of fields in netfilter table")
	}
	entriesArg := tableArg.Inner[numFileds-1].(*prog.GroupArg)
	if len(entriesArg.Inner) != 2 {
		panic("netfilter entries is expected to have 2 fields")
	}
	entriesArray := entriesArg.Inner[0].(*prog.GroupArg)
	// Collect offsets of entries.
	offsets := make([]uint64, len(entriesArray.Inner))
	var pos uint64
	for i, entryArg := range entriesArray.Inner {
		offsets[i] = pos
		pos += entryArg.Size()
	}
	if pos != entriesArray.Size() {
		panic("netfilter offsets are broken")
	}
	genOffset := func() uint64 {
		if g.Rand().Intn(100) == 0 {
			// Assign the underflow entry once in a while.
			// We have it in underflow hooks, so no point in using it frequently.
			return pos
		} else {
			return offsets[g.Rand().Intn(len(offsets))]
		}
	}
	// Assign offsets to used hooks.
	for hook := hookStart; hook < hookStart+hookCount; hook++ {
		hookArg := tableArg.Inner[hook].(*prog.ConstArg)
		if hookArg.Type().(*prog.ConstType).Val == unused {
			continue // unused hook
		}
		hookArg.Val = genOffset()
	}
	// Assign offsets to used underflow entries.
	for hook := hookStart + hookCount; hook < hookStart+2*hookCount; hook++ {
		hookArg := tableArg.Inner[hook].(*prog.ConstArg)
		if hookArg.Type().(*prog.ConstType).Val == unused {
			continue // unused hook
		}
		hookArg.Val = pos
	}
	// Now update standard target jump offsets.
	prog.ForeachSubarg(arg, func(arg, _ prog.Arg, _ *[]prog.Arg) {
		if !strings.HasPrefix(arg.Type().Name(), `xt_target_t["", `) {
			return
		}
		targetArg := arg.(*prog.GroupArg)
		valArg := targetArg.Inner[3].(*prog.ConstArg)
		flagsType, ok := valArg.Type().(*prog.FlagsType)
		if !ok {
			return
		}
		if int64(valArg.Val) < 0 {
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
