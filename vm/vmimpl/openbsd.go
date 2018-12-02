package vmimpl

import (
	"io"
	"time"
)

// DiagnoseOpenBSD sends the debug commands to the given writer which
// is expected to be connected to a paniced openbsd kernel.  If kernel
// just hanged, we've lost connection or detected some non-panic
// error, console still shows normal login prompt.
func DiagnoseOpenBSD(w io.Writer) bool {
	commands := []string{
		"",
		"set $lines = 0", // disable pagination
		"show panic",
		"trace",
		"show registers",
		"show proc",
		"ps",
	}
	for _, c := range commands {
		w.Write([]byte(c + "\n"))
		time.Sleep(1 * time.Second)
	}
	return true
}
