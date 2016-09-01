// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer

import (
	"os"
	"testing"
)

func TestSymbols(t *testing.T) {
	symbols, err := ReadSymbols(os.Args[0])
	if err != nil {
		t.Fatalf("failed to read symbols: %v", err)
	}
	t.Logf("Read %v symbols", len(symbols))
	s, ok := symbols["github.com/google/syzkaller/symbolizer.TestSymbols"]
	if !ok {
		t.Fatalf("symbols don't contain this function")
	}
	if len(s) != 1 {
		t.Fatalf("more than 1 symbol: %v", len(s))
	}
	if s[0].Addr == 0 {
		t.Fatalf("symbol address is 0")
	}
	if s[0].Size <= 10 || s[0].Size > 1<<20 {
		t.Fatalf("bogus symbol size: %v", s[0].Size)
	}
}
