// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer

import (
	"testing"
)

func TestSymbols(t *testing.T) {
	symbols, err := ReadSymbols("testdata/nm.test.out")
	if err != nil {
		t.Fatalf("failed to read symbols: %v", err)
	}
	if len(symbols) != 5 {
		t.Fatalf("got %v symbols, want 5", len(symbols))
	}
	{
		s := symbols["barfoo"]
		if len(s) != 1 {
			t.Fatalf("got %v barfoo symbols, want 1", len(s))
		}
		if s[0].Addr != 0x400507 {
			t.Fatalf("bad barfoo address: 0x%x", s[0].Addr)
		}
		if s[0].Size != 0x30 {
			t.Fatalf("bad barfoo size: 0x%x", s[0].Size)
		}
	}
	{
		s := symbols["foobar"]
		if len(s) != 2 {
			t.Fatalf("got %v foobar symbols, want 2", len(s))
		}
		want := []Symbol{
			{
				Addr: 0x4004fa,
				Size: 0x10,
			},
			{
				Addr: 0x4004ed,
				Size: 0x10,
			},
		}
		if !symcmp(want[0], s[0]) && !symcmp(want[0], s[1]) {
			t.Fatalf("foobar symbol %+v not found", want[0])
		}
		if !symcmp(want[1], s[0]) && !symcmp(want[1], s[1]) {
			t.Fatalf("foobar symbol %+v not found", want[1])
		}
	}
}

func symcmp(want Symbol, got Symbol) bool {
	if want.Addr != got.Addr {
		return false
	}
	if want.Size != got.Size {
		return false
	}
	return true
}
