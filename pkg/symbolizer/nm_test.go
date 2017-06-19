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
		if s[0].Addr != 0x4004ed {
			t.Fatalf("bad foobar[0] address: 0x%x", s[0].Addr)
		}
		if s[0].Size != 0x10 {
			t.Fatalf("bad foobar[0] size: 0x%x", s[0].Size)
		}
		if s[1].Addr != 0x4004fa {
			t.Fatalf("bad foobar[1] address: 0x%x", s[1].Addr)
		}
		if s[1].Size != 0x10 {
			t.Fatalf("bad foobar[1] size: 0x%x", s[1].Size)
		}
	}
}
