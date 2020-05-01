// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proggen

import (
	"bytes"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-trace2syz/parser"
	"strconv"
	"unicode"
)

var discriminatorArgs = map[string][]int{
	"bpf":         {0},
	"fcntl":       {1},
	"ioprio_get":  {0},
	"socket":      {0, 1, 2},
	"socketpair":  {0, 1, 2},
	"ioctl":       {0, 1},
	"getsockopt":  {1, 2},
	"setsockopt":  {1, 2},
	"accept":      {0},
	"accept4":     {0},
	"bind":        {0},
	"connect":     {0},
	"recvfrom":    {0},
	"sendto":      {0},
	"sendmsg":     {0},
	"getsockname": {0},
	"openat":      {1},
}

var openDiscriminatorArgs = map[string]int{
	"open":         0,
	"openat":       1,
	"syz_open_dev": 0,
}

type callSelector interface {
	Select(call *parser.Syscall) *prog.Syscall
}

func newSelectors(target *prog.Target, returnCache returnCache) []callSelector {
	sc := newSelectorCommon(target, returnCache)
	return []callSelector{
		&defaultCallSelector{sc},
		&openCallSelector{sc},
	}
}

type selectorCommon struct {
	target      *prog.Target
	returnCache returnCache
	callCache   map[string][]*prog.Syscall
}

func newSelectorCommon(target *prog.Target, returnCache returnCache) *selectorCommon {
	return &selectorCommon{
		target:      target,
		returnCache: returnCache,
		callCache:   make(map[string][]*prog.Syscall),
	}
}

// matches strace file string with a constant string in openat or syz_open_dev
// if the string in openat or syz_open_dev has a # then this method will
// return the corresponding  id from the strace string
func (cs *selectorCommon) matchFilename(syzFile, straceFile []byte) (bool, int) {
	syzFile = bytes.Trim(syzFile, "\x00")
	straceFile = bytes.Trim(straceFile, "\x00")
	if len(syzFile) != len(straceFile) {
		return false, -1
	}
	var id []byte
	dev := -1
	for i, c := range syzFile {
		x := straceFile[i]
		if c == x {
			continue
		}
		if c != '#' || !unicode.IsDigit(rune(x)) {
			return false, -1
		}
		id = append(id, x)
	}
	if len(id) > 0 {
		dev, _ = strconv.Atoi(string(id))
	}
	return true, dev
}

// callSet returns all syscalls with the given name.
func (cs *selectorCommon) callSet(callName string) []*prog.Syscall {
	calls, ok := cs.callCache[callName]
	if ok {
		return calls
	}
	for _, call := range cs.target.Syscalls {
		if call.CallName == callName {
			calls = append(calls, call)
		}
	}
	cs.callCache[callName] = calls
	return calls
}

type openCallSelector struct {
	*selectorCommon
}

// Select returns the best matching descrimination for this syscall.
func (cs *openCallSelector) Select(call *parser.Syscall) *prog.Syscall {
	if _, ok := openDiscriminatorArgs[call.CallName]; !ok {
		return nil
	}
	for callName := range openDiscriminatorArgs {
		for _, variant := range cs.callSet(callName) {
			match, devID := cs.matchOpen(variant, call)
			if !match {
				continue
			}
			if call.CallName == "open" && callName == "openat" {
				cwd := parser.Constant(cs.target.ConstMap["AT_FDCWD"])
				call.Args = append([]parser.IrType{cwd}, call.Args...)
				return variant
			}
			if match && call.CallName == "open" && callName == "syz_open_dev" {
				if devID < 0 {
					return variant
				}
				args := []parser.IrType{call.Args[0], parser.Constant(uint64(devID))}
				call.Args = append(args, call.Args[1:]...)
				return variant
			}
		}
	}
	return nil
}

func (cs *openCallSelector) matchOpen(meta *prog.Syscall, call *parser.Syscall) (bool, int) {
	straceFileArg := call.Args[openDiscriminatorArgs[call.CallName]]
	straceBuf := straceFileArg.(*parser.BufferType).Val
	syzFileArg := meta.Args[openDiscriminatorArgs[meta.CallName]].Type
	if _, ok := syzFileArg.(*prog.PtrType); !ok {
		return false, -1
	}
	syzBuf := syzFileArg.(*prog.PtrType).Elem.(*prog.BufferType)
	if syzBuf.Kind != prog.BufferString {
		return false, -1
	}
	for _, val := range syzBuf.Values {
		match, devID := cs.matchFilename([]byte(val), []byte(straceBuf))
		if match {
			return match, devID
		}
	}
	return false, -1
}

type defaultCallSelector struct {
	*selectorCommon
}

// Select returns the best matching descrimination for this syscall.
func (cs *defaultCallSelector) Select(call *parser.Syscall) *prog.Syscall {
	var match *prog.Syscall
	discriminators := discriminatorArgs[call.CallName]
	if len(discriminators) == 0 {
		return nil
	}
	score := 0
	for _, meta := range cs.callSet(call.CallName) {
		if score1 := cs.matchCall(meta, call, discriminators); score1 > score {
			match, score = meta, score1
		}
	}
	return match
}

// matchCall returns match score between meta and call.
// Higher score means better match, -1 if they are not matching at all.
func (cs *defaultCallSelector) matchCall(meta *prog.Syscall, call *parser.Syscall, discriminators []int) int {
	score := 0
	for _, i := range discriminators {
		if i >= len(meta.Args) || i >= len(call.Args) {
			return -1
		}
		typ := meta.Args[i].Type
		arg := call.Args[i]
		switch t := typ.(type) {
		case *prog.ConstType:
			// Consts must match precisely.
			constant, ok := arg.(parser.Constant)
			if !ok || constant.Val() != t.Val {
				return -1
			}
			score += 10
		case *prog.FlagsType:
			// Flags may or may not match, but matched flags increase score.
			constant, ok := arg.(parser.Constant)
			if !ok {
				return -1
			}
			val := constant.Val()
			for _, v := range t.Vals {
				if v == val {
					score++
					break
				}
			}
		case *prog.ResourceType:
			// Resources must match one of subtypes,
			// the more precise match, the higher the score.
			retArg := cs.returnCache.get(t, arg)
			if retArg == nil {
				return -1
			}
			matched := false
			for i, kind := range retArg.Type().(*prog.ResourceType).Desc.Kind {
				if kind == t.Desc.Name {
					score += i + 1
					matched = true
					break
				}
			}
			if !matched {
				return -1
			}
		case *prog.PtrType:
			switch r := t.Elem.(type) {
			case *prog.BufferType:
				matched := false
				buffer, ok := arg.(*parser.BufferType)
				if !ok {
					return -1
				}
				if r.Kind != prog.BufferString {
					return -1
				}
				for _, val := range r.Values {
					matched, _ = cs.matchFilename([]byte(val), []byte(buffer.Val))
					if matched {
						score++
						break
					}
				}
				if !matched {
					return -1
				}
			}
		}
	}
	return score
}
