// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ifuzz

import (
	"encoding/hex"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/ifuzz/ifuzzimpl"
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
	all := make(map[ifuzzimpl.Insn]bool)
	for mode := ifuzzimpl.Mode(0); mode < ifuzzimpl.ModeLast; mode++ {
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
	insnset := ifuzzimpl.Arches[arch]
	xedEnabled := false
	if _, err := insnset.DecodeExt(0, nil); err == nil {
		xedEnabled = true
	}
	seed := time.Now().UnixNano()
	if os.Getenv("CI") != "" {
		seed = 0 // required for deterministic coverage reports
	}
	t.Logf("seed=%v", seed)
	r := rand.New(rand.NewSource(seed))

	for repeat := 0; repeat < 10; repeat++ {
		for mode := ifuzzimpl.Mode(0); mode < ifuzzimpl.ModeLast; mode++ {
			cfg := &ifuzzimpl.Config{
				Mode: mode,
				Priv: true,
				Exec: true,
			}
			failed := false
			for _, insn := range allInsns(arch, mode, true, true) {
				text0 := insn.Encode(cfg, r)
				text := text0
			repeat:
				size, err := insnset.Decode(mode, text)
				if err != nil {
					t.Errorf("decoding %v %v failed (mode=%v): %v", insn.GetName(), hex.EncodeToString(text), mode, err)
					if len(text) != len(text0) {
						t.Errorf("whole: %v", hex.EncodeToString(text0))
					}
					failed = true
					continue
				}
				if xedEnabled {
					xedSize, xedErr := insnset.DecodeExt(mode, text)
					if xedErr != nil {
						t.Errorf("xed decoding %v %v failed (mode=%v): %v", insn.GetName(), hex.EncodeToString(text), mode, xedErr)
						if len(text) != len(text0) {
							t.Errorf("whole: %v", hex.EncodeToString(text0))
						}
						failed = true
						continue
					}
					if size != xedSize {
						t.Errorf("decoding %v %v failed (mode=%v): decoded %v/%v, xed decoded %v/%v",
							insn.GetName(), hex.EncodeToString(text), mode, size, xedSize, size, len(text))
						if len(text) != len(text0) {
							t.Errorf("whole: %v", hex.EncodeToString(text0))
						}
						failed = true
						continue
					}
				}
				if insn.GetPseudo() && size >= 0 && size < len(text) {
					text = text[size:]
					goto repeat
				}
				if size != len(text) {
					t.Errorf("decoding %v %v failed (mode=%v): decoded %v/%v",
						insn.GetName(), hex.EncodeToString(text), mode, size, len(text))
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

func allInsns(arch string, mode ifuzzimpl.Mode, priv, exec bool) []ifuzzimpl.Insn {
	insnset := ifuzzimpl.Arches[arch]
	insns := insnset.GetInsns(mode, ifuzzimpl.TypeUser)
	if priv {
		insns = append(insns, insnset.GetInsns(mode, ifuzzimpl.TypePriv)...)
		if exec {
			insns = append(insns, insnset.GetInsns(mode, ifuzzimpl.TypeExec)...)
		}
	}
	return insns
}
