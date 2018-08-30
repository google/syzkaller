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
		}
		return offsets[g.Rand().Intn(len(offsets))]
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
	prog.ForeachSubArg(arg, func(arg prog.Arg, _ *prog.ArgCtx) {
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

func (arch *arch) generateEbtables(g *prog.Gen, typ prog.Type, old prog.Arg) (
	arg prog.Arg, calls []*prog.Call) {
	if old == nil {
		arg = g.GenerateSpecialArg(typ, &calls)
	} else {
		// TODO(dvyukov): try to restore original hook order after mutation
		// instead of assigning brand new offsets.
		arg = old
		calls = g.MutateArg(arg)
	}
	if g.Target().ArgContainsAny(arg) {
		return
	}
	hooksField, entriesField := 4, 7
	if g.Target().PtrSize == 8 {
		// Account for paddings.
		hooksField, entriesField = 5, 9
	}
	tableArg := arg.(*prog.UnionArg).Option.(*prog.GroupArg)
	entriesPtr := tableArg.Inner[entriesField].(*prog.PointerArg)
	if entriesPtr.Res == nil {
		return
	}
	entriesArray := entriesPtr.Res.(*prog.GroupArg)
	offsets := make([]uint64, len(entriesArray.Inner))
	var pos, totalEntries uint64
	for i, entriesArg0 := range entriesArray.Inner {
		entriesArg := entriesArg0.(*prog.GroupArg)
		arrayArg := entriesArg.Inner[len(entriesArg.Inner)-1].(*prog.GroupArg)
		entriesArg.Inner[2].(*prog.ConstArg).Val = totalEntries
		totalEntries += uint64(len(arrayArg.Inner))
		offsets[i] = pos
		pos += entriesArg.Size()
	}
	tableArg.Inner[2].(*prog.ConstArg).Val = totalEntries
	if pos != entriesArray.Size() {
		panic("netfilter offsets are broken")
	}
	// Assign offsets to used hooks.
	validHooks := tableArg.Inner[1].(*prog.ConstArg).Val
	hooksArg := tableArg.Inner[hooksField].(*prog.GroupArg)
	for i, hookArg0 := range hooksArg.Inner {
		hookArg := hookArg0.(*prog.ConstArg)
		if validHooks&(1<<uint(i)) == 0 {
			hookArg.Val = 0
			continue
		}
		addr := g.Target().PhysicalAddr(entriesPtr)
		if len(offsets) != 0 {
			addr += offsets[0]
			offsets = offsets[1:]
		}
		hookArg.Val = addr
	}
	// TODO(dvyukov): assign jump targets for targets.
	return
}

func (arch *arch) sanitizeEbtables(c *prog.Call) {
	// This is very hacky... just as netfilter interfaces.
	// setsockopt's len argument must be equal to size of ebt_replace + entries size.
	lenArg := c.Args[4].(*prog.ConstArg)
	tablePtr := c.Args[3].(*prog.PointerArg).Res
	if tablePtr == nil {
		return
	}
	tableArg := tablePtr.(*prog.UnionArg).Option.(*prog.GroupArg)
	entriesField := len(tableArg.Inner) - 1
	entriesArg := tableArg.Inner[entriesField].(*prog.PointerArg).Res
	if entriesArg == nil {
		return
	}
	lenArg.Val = tableArg.Size() + entriesArg.Size()
}
