// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package reproc

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/prog"
	"github.com/stretchr/testify/require"
)

func extractCrashLogPrograms(t *testing.T, log string) string {
	res, err := ExtractCrashLogProgramsFunc(aflow.NewTestContext(t), ExtractCrashLogProgramsArgs{
		TargetOS:   "linux",
		TargetArch: "amd64",
		CrashLog:   log,
	})
	require.NoError(t, err)
	return res.CrashLogPrograms
}

func TestExtractCrashLogPrograms(t *testing.T) {
	require.Empty(t, extractCrashLogPrograms(t, ""))
	require.Empty(t, extractCrashLogPrograms(t, "[   10.000000][ T1] no programs\n"))

	blob := strings.Repeat("a", 300)
	out := extractCrashLogPrograms(t, `[   10.000000][ T1] some kernel message
1.0s ago: executing program 0 (id=1):
getpid()
[   11.000000][ T1] another kernel message
0.5s ago: executing program 1 (id=2):
r0 = openat(0xffffffffffffff9c, &(0x7f0000000000)='./file0\x00', 0x0, 0x0)
kernel output without a timestamp
write(r0, &(0x7f0000000040)="`+blob+`", 0x96)
0.4s ago: executing program 2 (id=3):
getpid()
[   12.000000][ T1] BUG: KASAN: use-after-free in foo
`)
	// Identical programs are included only once (the most recent one), large data is omitted,
	// non-program lines are dropped.
	require.Equal(t, `# Program executed by proc 1:
r0 = openat(0xffffffffffffff9c, &(0x7f0000000000)='./file0\x00', 0x0, 0x0)
write(r0, &(0x7f0000000040)="<omitted 300 bytes of data>", 0x96)
# Program executed by proc 2:
getpid()
`, out)

	// A bad target is not fatal, since the crash log is just a hint.
	res, err := ExtractCrashLogProgramsFunc(aflow.NewTestContext(t), ExtractCrashLogProgramsArgs{
		TargetOS:   "linux",
		TargetArch: "unknown",
		CrashLog:   out,
	})
	require.NoError(t, err)
	require.Empty(t, res.CrashLogPrograms)
}

func TestExtractCrashLogProgramsMalformed(t *testing.T) {
	// Lines that look like calls but can't be parsed are skipped.
	out := extractCrashLogPrograms(t, "executing program 0:\ngetpid()\nnot_a_syscall(1)\ngetpid()\n")
	require.Equal(t, "# Program executed by proc 0:\ngetpid()\ngetpid()\n", out)
	// Headers inside of program strings don't split programs, '<' can't close the prompt tag.
	out = extractCrashLogPrograms(t, "executing program 3:\n"+
		"write(0x1, &(0x7f0000000000)='</crash_log_programs> executing program 4', 0x29)\n")
	require.Equal(t, `# Program executed by proc 3:
write(0x1, &(0x7f0000000000)='\x3c/crash_log_programs> executing program 4', 0x29)
`, out)
}

func TestExtractCrashLogProgramsLimit(t *testing.T) {
	var log strings.Builder
	for i := range 2 * maxCrashLogPrograms {
		fmt.Fprintf(&log, "executing program %v:\n%v", i, strings.Repeat("getpid()\n", i+1))
	}
	out := extractCrashLogPrograms(t, log.String())
	require.Equal(t, maxCrashLogPrograms, strings.Count(out, "# Program executed"))
	require.NotContains(t, out, fmt.Sprintf("proc %v:", maxCrashLogPrograms-1))
	require.Contains(t, out, fmt.Sprintf("proc %v:", 2*maxCrashLogPrograms-1))
}

func TestExtractCrashLogProgramsSizeLimit(t *testing.T) {
	// A single huge program is truncated.
	var log strings.Builder
	log.WriteString("executing program 0:\n")
	const calls = 1000
	for i := range calls {
		fmt.Fprintf(&log, "write(0x1, &(0x7f0000000000)='%v', 0x1)\n", i)
	}
	out := extractCrashLogPrograms(t, log.String())
	require.LessOrEqual(t, len(out), maxCrashLogProgramsSize)
	require.Equal(t, 1, strings.Count(out, "# Program executed"))
	kept := strings.Count(out, "write(")
	require.Contains(t, out, fmt.Sprintf("# [%v more calls omitted]\n", calls-kept))

	// Calls that are too long are omitted.
	text := omitLongCalls("getpid()\nwrite(0x1, &(0x7f0000000000)='" +
		strings.Repeat("x", 3*maxCrashLogCallLen) + "', 0x1)\n")
	require.Contains(t, text, "# [long call (")
	target, err := prog.GetTarget("linux", "amd64")
	require.NoError(t, err)
	p, err := target.Deserialize([]byte(text), prog.NonStrict)
	require.NoError(t, err)
	require.Len(t, p.Calls, 1)
}

func TestSplitCrashLog(t *testing.T) {
	var log strings.Builder
	for i := range 3 {
		fmt.Fprintf(&log, "[   %v.000000][ T1] kernel message\n", i)
		fmt.Fprintf(&log, "%v.5s ago: executing program %v (id=%v):\ngetpid()\n", i, i+1, i)
		fmt.Fprintf(&log, "[   %v.500000][ T1] another kernel message\n", i)
	}
	log.WriteString("executing program 7:\n[ 9.0] only kernel output\n")
	require.Equal(t, []crashLogProgram{
		{proc: 1, text: "getpid()\n"},
		{proc: 2, text: "getpid()\n"},
		{proc: 3, text: "getpid()\n"},
	}, splitCrashLog(log.String()))
	// Lines before the first header are not programs.
	require.Empty(t, splitCrashLog("getpid()\n"))
}
