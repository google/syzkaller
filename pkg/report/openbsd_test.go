// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"testing"
)

func TestOpenbsdSymbolizeLine(t *testing.T) {
	tests := []symbolizeLineTest{
		// Normal symbolization.
		{
			"closef(ffffffff,ffffffff) at closef+0xaf\n",
			"closef(ffffffff,ffffffff) at closef+0xaf kern_descrip.c:1241\n",
		},
		// Inlined frames.
		{
			"sleep_finish_all(ffffffff,32) at sleep_finish_all+0x22\n",
			"sleep_finish_all(ffffffff,32) at sleep_finish_all+0x22 sleep_finish_timeout kern_synch.c:336 [inline]\n" +
				"sleep_finish_all(ffffffff,32) at sleep_finish_all+0x22 kern_synch.c:157\n",
		},
		// Missing symbol.
		{
			"foo(ffffffff,ffffffff) at foo+0x1e",
			"foo(ffffffff,ffffffff) at foo+0x1e",
		},
		// Witness symbolization.
		{
			"#4  closef+0xaf\n",
			"#4  closef+0xaf kern_descrip.c:1241\n",
		},
		{
			"#10 closef+0xaf\n",
			"#10 closef+0xaf kern_descrip.c:1241\n",
		},
	}
	testSymbolizeLine(t, ctorOpenbsd, tests)
}
