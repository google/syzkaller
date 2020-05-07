// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ifuzz_test

import (
	"encoding/hex"
	"math/rand"
	"os"
	"testing"
	"time"

	. "github.com/google/syzkaller/pkg/ifuzz"
	_ "github.com/google/syzkaller/pkg/ifuzz/generated"
)

func TestMode(t *testing.T) {
	all := make(map[*Insn]bool)
	for mode := 0; mode < ModeLast; mode++ {
		for priv := 0; priv < 2; priv++ {
			for exec := 0; exec < 2; exec++ {
				cfg := &Config{
					Mode: mode,
					Priv: priv != 0,
					Exec: exec != 0,
				}
				insns := ModeInsns(cfg)
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
	seed := time.Now().UnixNano()
	if os.Getenv("CI") != "" {
		seed = 0 // required for deterministic coverage reports
	}
	t.Logf("seed=%v", seed)
	r := rand.New(rand.NewSource(seed))

	for repeat := 0; repeat < 10; repeat++ {
		for mode := 0; mode < ModeLast; mode++ {
			cfg := &Config{
				Mode: mode,
				Priv: true,
				Exec: true,
			}
			failed := false
			for _, insn := range ModeInsns(cfg) {
				text0 := insn.Encode(cfg, r)
				text := text0
			repeat:
				size, err := Decode(mode, text)
				if err != nil {
					t.Errorf("decoding %v %v failed (mode=%v): %v", insn.Name, hex.EncodeToString(text), mode, err)
					if len(text) != len(text0) {
						t.Errorf("whole: %v", hex.EncodeToString(text0))
					}
					failed = true
					continue
				}
				if XedDecode != nil {
					xedSize, xedErr := XedDecode(mode, text)
					if xedErr != nil {
						t.Errorf("xed decoding %v %v failed (mode=%v): %v", insn.Name, hex.EncodeToString(text), mode, xedErr)
						if len(text) != len(text0) {
							t.Errorf("whole: %v", hex.EncodeToString(text0))
						}
						failed = true
						continue
					}
					if size != xedSize {
						t.Errorf("decoding %v %v failed (mode=%v): decoded %v/%v, xed decoded %v/%v",
							insn.Name, hex.EncodeToString(text), mode, size, xedSize, size, len(text))
						if len(text) != len(text0) {
							t.Errorf("whole: %v", hex.EncodeToString(text0))
						}
						failed = true
						continue
					}
				}
				if insn.Pseudo && size >= 0 && size < len(text) {
					text = text[size:]
					goto repeat
				}
				if size != len(text) {
					t.Errorf("decoding %v %v failed (mode=%v): decoded %v/%v",
						insn.Name, hex.EncodeToString(text), mode, size, len(text))
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
