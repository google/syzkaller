// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
)

var oopses = [][]byte{
	[]byte("Kernel panic"),
	[]byte("BUG:"),
	[]byte("kernel BUG"),
	[]byte("WARNING:"),
	[]byte("INFO:"),
	[]byte("unable to handle"),
	[]byte("Unable to handle kernel"),
	[]byte("general protection fault"),
	[]byte("UBSAN:"),
	[]byte("unreferenced object"),
}

// FindCrash searches kernel console output for oops messages.
// Desc contains a more-or-less representative description of the first oops,
// start and end denote region of output with oops message(s).
func FindCrash(output []byte) (desc string, start int, end int, found bool) {
	for pos := 0; pos < len(output); {
		next := bytes.IndexByte(output[pos:], '\n')
		if next != -1 {
			next += pos
		} else {
			next = len(output)
		}
		for _, oops := range oopses {
			match := bytes.Index(output[pos:next], oops)
			if match == -1 {
				continue
			}
			if !found {
				found = true
				start = pos
				desc = string(output[pos+match : next])
				if desc[len(desc)-1] == '\r' {
					desc = desc[:len(desc)-1]
				}
			}
			end = next
		}
		pos = next + 1
	}
	return
}
