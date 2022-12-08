// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ifuzz

import (
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/ifuzz/iset"
	"github.com/google/syzkaller/pkg/testutil"
)

var allArches = []string{ArchX86, ArchPowerPC}

func TestMode(t *testing.T) {
	for _, arch := range allArches {
		t.Run(arch, func(t *testing.T) {
			testMode(t, arch)
		})
	}
}

func testMode(t *testing.T, arch string) {
	all := make(map[iset.Insn]bool)
	for mode := iset.Mode(0); mode < iset.ModeLast; mode++ {
		for priv := 0; priv < 2; priv++ {
			for exec := 0; exec < 2; exec++ {
				insns := allInsns(arch, mode, priv != 0, exec != 0)
				t.Logf("mode=%v priv=%v exec=%v: %v instructions", mode, priv, exec, len(insns))
				for _, insn := range insns {
					all[insn] = true
				}
			}
		}
	}
	t.Logf("total: %v instructions", len(all))
}

func TestDecode(t *testing.T) {
	for _, arch := range allArches {
		t.Run(arch, func(t *testing.T) {
			testDecode(t, arch)
		})
	}
}

func testDecode(t *testing.T, arch string) {
	insnset := iset.Arches[arch]
	xedEnabled := false
	if _, err := insnset.DecodeExt(0, nil); err == nil {
		xedEnabled = true
	}
	r := rand.New(testutil.RandSource(t))

	for repeat := 0; repeat < 10; repeat++ {
		for mode := iset.Mode(0); mode < iset.ModeLast; mode++ {
			cfg := &iset.Config{
				Mode: mode,
				Priv: true,
				Exec: true,
			}
			failed := false
			for _, insn := range allInsns(arch, mode, true, true) {
				name, _, pseudo, _ := insn.Info()
				text0 := insn.Encode(cfg, r)
				text := text0
			repeat:
				size, err := insnset.Decode(mode, text)
				if err != nil {
					t.Errorf("decoding %v %v failed (mode=%v): %v", name, hex.EncodeToString(text), mode, err)
					if len(text) != len(text0) {
						t.Errorf("whole: %v", hex.EncodeToString(text0))
					}
					failed = true
					continue
				}
				if xedEnabled {
					xedSize, xedErr := insnset.DecodeExt(mode, text)
					if xedErr != nil {
						t.Errorf("xed decoding %v %v failed (mode=%v): %v", name, hex.EncodeToString(text), mode, xedErr)
						if len(text) != len(text0) {
							t.Errorf("whole: %v", hex.EncodeToString(text0))
						}
						failed = true
						continue
					}
					if size != xedSize {
						t.Errorf("decoding %v %v failed (mode=%v): decoded %v/%v, xed decoded %v/%v",
							name, hex.EncodeToString(text), mode, size, xedSize, size, len(text))
						if len(text) != len(text0) {
							t.Errorf("whole: %v", hex.EncodeToString(text0))
						}
						failed = true
						continue
					}
				}
				if pseudo && size >= 0 && size < len(text) {
					text = text[size:]
					goto repeat
				}
				if size != len(text) {
					t.Errorf("decoding %v %v failed (mode=%v): decoded %v/%v",
						name, hex.EncodeToString(text), mode, size, len(text))
					if len(text) != len(text0) {
						t.Errorf("whole: %v", hex.EncodeToString(text0))
					}
					failed = true
				}
			}
			if failed {
				return
			}
		}
	}
}

func allInsns(arch string, mode iset.Mode, priv, exec bool) []iset.Insn {
	insnset := iset.Arches[arch]
	insns := insnset.GetInsns(mode, iset.TypeUser)
	if priv {
		insns = append(insns, insnset.GetInsns(mode, iset.TypePriv)...)
		if exec {
			insns = append(insns, insnset.GetInsns(mode, iset.TypeExec)...)
		}
	}
	return insns
}
