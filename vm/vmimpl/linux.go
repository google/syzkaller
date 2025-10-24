
package vmimpl

import (
	"regexp"
	"strings"

	"github.com/VerditeLabs/syzkaller/pkg/report"
)

// DiagnoseLinux diagnoses some Linux kernel bugs over the provided ssh callback.
func DiagnoseLinux(rep *report.Report, ssh func(args ...string) ([]byte, error)) (output []byte, wait, handled bool) {
	if !strings.Contains(rep.Title, "MAX_LOCKDEP") {
		return nil, false, false
	}
	// Dump /proc/lockdep* files on BUG: MAX_LOCKDEP_{KEYS,ENTRIES,CHAINS,CHAIN_HLOCKS} too low!
	output, err := ssh("cat", "/proc/lockdep_stats", "/proc/lockdep", "/proc/lockdep_chains")
	if err != nil {
		output = append(output, err.Error()...)
	}
	// Remove mangled pointer values, they take lots of space but don't add any value.
	output = regexp.MustCompile(` *\[?[0-9a-f]{8,}\]?\s*`).ReplaceAll(output, nil)
	return output, false, true
}
