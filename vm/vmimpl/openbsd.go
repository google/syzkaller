// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vmimpl

import (
	"io"
	"time"
)

// DiagnoseOpenBSD sends the debug commands to the given writer which
// is expected to be connected to a paniced openbsd kernel. If kernel
// just hanged, we've lost connection or detected some non-panic error,
// console still shows normal login prompt.
func DiagnoseOpenBSD(w io.Writer) ([]byte, bool) {
	commands := []string{
		"",
		"set $lines = 0",    // disable pagination
		"set $maxwidth = 0", // disable line continuation
		"show panic",
		"trace",
		"show registers",
		"show proc",
		"ps",
		"show all locks",
		"show malloc",
		"show all pools",
		"machine ddbcpu 0", // Traces a couple of first CPUs (enough on GCE farm).
		"trace",
		"machine ddbcpu 1", // One of these is likely a dup of the very first trace.
		"trace",
	}
	for _, c := range commands {
		w.Write([]byte(c + "\n"))
		time.Sleep(1 * time.Second)
	}
	return nil, true
}
