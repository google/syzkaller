// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package reproc

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/image"
	"github.com/google/syzkaller/prog"
	"github.com/stretchr/testify/require"
)

func TestExtractCrashLogPrograms(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	args := ExtractCrashLogProgramsArgs{TargetOS: "linux", TargetArch: "amd64"}

	res, err := ExtractCrashLogProgramsFunc(ctx, args)
	require.NoError(t, err)
	require.Empty(t, res.CrashLogPrograms)

	blob := strings.Repeat("a", 300)
	args.CrashLog = `[   10.000000][ T1] some kernel message
1.0s ago: executing program 0 (id=1):
getpid()
[   11.000000][ T1] another kernel message
0.5s ago: executing program 1 (id=2):
r0 = openat(0xffffffffffffff9c, &(0x7f0000000000)='./file0\x00', 0x0, 0x0)
write(r0, &(0x7f0000000040)="` + blob + `", 0x96)
0.4s ago: executing program 2 (id=3):
getpid()
[   12.000000][ T1] BUG: KASAN: use-after-free in foo
`
	res, err = ExtractCrashLogProgramsFunc(ctx, args)
	require.NoError(t, err)
	out := res.CrashLogPrograms
	require.NotContains(t, out, blob)
	require.Contains(t, out, `"$SYZBLOB_`)
	require.NotContains(t, out, `"$BLOB_`)
	// Identical programs are included only once (the most recent one).
	require.NotContains(t, out, "proc 0:")
	first := strings.Index(out, "# Program executed by proc 1:\nr0 = openat(")
	second := strings.Index(out, "# Program executed by proc 2:\ngetpid()\n")
	require.NotEqual(t, -1, first, out)
	require.Greater(t, second, first, out)
	// Placeholders are restored to the original data.
	require.Contains(t, restoreProgramBlobs(ctx, out), blob)

	// A bad target is not fatal, since the crash log is just a hint.
	args.TargetArch = "unknown"
	res, err = ExtractCrashLogProgramsFunc(ctx, args)
	require.NoError(t, err)
	require.Empty(t, res.CrashLogPrograms)
}

func TestExtractCrashLogProgramsLimit(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	var log strings.Builder
	for i := range 2 * maxCrashLogPrograms {
		fmt.Fprintf(&log, "executing program %v:\n%v", i, strings.Repeat("getpid()\n", i+1))
	}
	res, err := ExtractCrashLogProgramsFunc(ctx, ExtractCrashLogProgramsArgs{
		TargetOS:   "linux",
		TargetArch: "amd64",
		CrashLog:   log.String(),
	})
	require.NoError(t, err)
	require.Equal(t, maxCrashLogPrograms, strings.Count(res.CrashLogPrograms, "# Program executed"))
	require.NotContains(t, res.CrashLogPrograms, fmt.Sprintf("proc %v:", maxCrashLogPrograms-1))
	require.Contains(t, res.CrashLogPrograms, fmt.Sprintf("proc %v:", 2*maxCrashLogPrograms-1))
}

func TestExtractCrashLogProgramsSizeLimit(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	// A single huge program is truncated.
	var log strings.Builder
	log.WriteString("executing program 0:\n")
	for i := range 2000 {
		fmt.Fprintf(&log, "write(0x1, &(0x7f0000000000)='%v', 0x1)\n", i)
	}
	res, err := ExtractCrashLogProgramsFunc(ctx, ExtractCrashLogProgramsArgs{
		TargetOS:   "linux",
		TargetArch: "amd64",
		CrashLog:   log.String(),
	})
	require.NoError(t, err)
	require.LessOrEqual(t, len(res.CrashLogPrograms), maxCrashLogProgramBytes+200)
	require.Contains(t, res.CrashLogPrograms, "more calls omitted]")
	require.Equal(t, 1, strings.Count(res.CrashLogPrograms, "# Program executed"))

	// Calls that are too long are replaced with placeholders (which may contain data placeholders),
	// and are restored by syz-prog-to-c.
	long := strings.Repeat("x", 3*maxCrashLogLineLen)
	program := replaceProgramBlobs(ctx, "getpid()\nwrite(0x1, &(0x7f0000000000)='"+long+"', 0x1)\n"+
		"writev(0x1, &(0x7f0000000000)=[{&(0x7f0000001000)=\""+strings.Repeat("ab", 200)+"\", 0x100}, "+
		"{&(0x7f0000002000)='"+long+"', 0x10}], 0x2)\n")
	require.Contains(t, program, syzBlobPrefix)
	text := replaceLongCalls(ctx, program)
	require.Less(t, len(text), 1000)
	require.Equal(t, 2, strings.Count(text, "# [long call ("))
	require.Equal(t, 2, strings.Count(text, syzBlobPrefix))
	restored := restoreProgramBlobs(ctx, text)
	for line := range strings.SplitSeq(restoreProgramBlobs(ctx, program), "\n") {
		require.Contains(t, restored, line+"\n")
	}
	res2, err := syzProgToC(ctx, syzProgToCState{TargetOS: "linux", TargetArch: "amd64"}, syzProgToCArgs{Program: text})
	require.NoError(t, err)
	require.Contains(t, res2.CProgram, "__NR_write,")
	require.Contains(t, res2.CProgram, "__NR_writev,")
}

func TestSyzProgToC(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	state := syzProgToCState{TargetOS: "linux", TargetArch: "amd64"}
	blob := strings.Repeat("0123456789abcdef", 64)
	program := replaceProgramBlobs(ctx, `r0 = openat(0xffffffffffffff9c, &(0x7f0000000000)='./file0\x00', 0x0, 0x0)
write(r0, &(0x7f0000000040)="`+blob+`", 0x200)
write(r0, &(0x7f0000001040)="`+blob[:128]+`", 0x40)
`)
	require.Contains(t, program, `"$SYZBLOB_`)
	res, err := syzProgToC(ctx, state, syzProgToCArgs{Program: program + "getpid()\n"})
	require.NoError(t, err)
	c := res.CProgram
	require.Contains(t, c, "__NR_openat")
	require.Contains(t, c, "__NR_getpid")
	require.Contains(t, c, "int main(")
	require.Contains(t, c, cBlobPrefix)
	require.NotContains(t, c, syzBlobPrefix)
	require.NotContains(t, c, strings.Repeat(`\x01\x23\x45\x67\x89\xab\xcd\xef`, 64))
	// Small data stays inline.
	require.Contains(t, c, `"`+strings.Repeat(`\x01\x23\x45\x67\x89\xab\xcd\xef`, 8)+`"`)
	// Helper code is collapsed into a marker.
	require.Regexp(t, `\n// SYZ_HELPERS [0-9a-f]{12}\n`, c)
	require.Contains(t, c, "do_sandbox_none")
	require.NotContains(t, c, "static int do_sandbox_none(void)")
	for line := range strings.SplitSeq(c, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			require.LessOrEqual(t, len(line), maxCommentLineLen+len(" ... [truncated]"), line)
		}
	}

	// The generated C program (with placeholders) compiles, but is kept unexpanded.
	compiled, err := CompileCProgFunc(ctx, CompileCProgArgs{
		TargetOS:               "linux",
		TargetArch:             "amd64",
		CurrentCandidateReproC: c,
	})
	require.NoError(t, err)
	require.Empty(t, compiled.CompilerError)
	require.Equal(t, c, compiled.FormattedReproC)

	expanded, err := expandCandidate(ctx, c)
	require.NoError(t, err)
	require.NotContains(t, expanded, "$BLOB_")
	require.NotContains(t, expanded, "SYZ_HELPERS")
	require.Contains(t, expanded, strings.Repeat(`\x01\x23\x45\x67\x89\xab\xcd\xef`, 64))
	require.Contains(t, expanded, "static int do_sandbox_none(void)")

	_, err = syzProgToC(ctx, state, syzProgToCArgs{Program: "unknown_syscall()"})
	require.IsType(t, aflow.BadCallError(""), err)
	// Parsing errors don't contain restored data blobs.
	_, err = syzProgToC(ctx, state, syzProgToCArgs{Program: strings.Replace(program, ", 0x200)", " 0x200)", 1)})
	require.IsType(t, aflow.BadCallError(""), err)
	require.Contains(t, err.Error(), syzBlobPrefix)
	require.NotContains(t, err.Error(), blob)
	require.Less(t, len(err.Error()), 1000)
}

func TestSyzProgToCOptions(t *testing.T) {
	target, err := prog.GetTarget("linux", "amd64")
	require.NoError(t, err)
	p, err := target.Deserialize([]byte("syz_usb_connect(0x0, 0x0, 0x0, 0x0)\n"), prog.NonStrict)
	require.NoError(t, err)
	opts := syzProgToCOptions(p)
	require.True(t, opts.USB)
	require.False(t, opts.NetInjection)
	require.NoError(t, opts.Check("linux"))
}

func TestReplaceProgramBlobsRoundTrip(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i * 7)
	}
	b64 := string(image.EncodeB64(image.Compress(data)))
	// A double quote inside of a single-quoted string must not confuse blob replacement.
	quoted := `'./file0\"` + strings.Repeat("x", 150) + `\x00'`
	program := `syz_mount_image$vfat(&(0x7f0000001780), &(0x7f00000017c0)=` + quoted +
		`, 0x0, &(0x7f0000000040)=ANY=[], 0x1, 0x0, &(0x7f000000adc0)="$` + b64 + `")` + "\n"
	replaced := replaceProgramBlobs(ctx, program)
	require.NotContains(t, replaced, `"$eJ`)
	require.Contains(t, replaced, quoted)
	require.Equal(t, program, restoreProgramBlobs(ctx, replaced))
	res, err := syzProgToC(ctx, syzProgToCState{TargetOS: "linux", TargetArch: "amd64"},
		syzProgToCArgs{Program: replaced})
	require.NoError(t, err)
	require.Contains(t, res.CProgram, "syz_mount_image")
}

func TestReplaceCBlobs(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	long := `"` + strings.Repeat(`\x01`, minCBlobLen) + `"`
	src := "// comment with an unbalanced \" quote\n" +
		"memcpy((void*)0x1000, " + long + ", 1024);\n" +
		"syscall(__NR_write, 1, \"short\", 5);\n" +
		"// " + long + "\n"
	res := replaceCBlobs(ctx, src)
	lines := strings.Split(res, "\n")
	require.Equal(t, "// comment with an unbalanced \" quote", lines[0])
	require.Regexp(t, `^memcpy\(\(void\*\)0x1000, "\$BLOB_[0-9a-f]{12}", 1024\);$`, lines[1])
	require.Equal(t, "syscall(__NR_write, 1, \"short\", 5);", lines[2])
	require.Equal(t, "// "+long, lines[3])
	require.Equal(t, src, ctx.RestoreBlobs(res))
}

func TestExpandCandidate(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	helpers := strings.Repeat("static int helper(void) { return 0; }\n", minCollapsedHelperLines)
	src := "#include <stdio.h>\n" + helpers + "int main(void) { return helper(); }\n"
	collapsed := collapseHelpers(ctx, src)
	require.NotEqual(t, src, collapsed)
	require.Contains(t, collapsed, "// It defines the following static functions:")

	expanded, err := expandCandidate(ctx, collapsed)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(expanded, "#include <stdio.h>\n"), expanded)
	require.Contains(t, expanded, helpers)
	require.True(t, strings.HasSuffix(expanded, "int main(void) { return helper(); }\n"), expanded)
	require.NotContains(t, expanded, "SYZ_HELPERS")

	// Duplicate identical markers are expanded once.
	marker := helpersMarkerRe.FindString(collapsed) + "\n"
	dup, err := expandCandidate(ctx, marker+collapsed)
	require.NoError(t, err)
	require.Equal(t, minCollapsedHelperLines, strings.Count(dup, "static int helper(void)"))

	// Different markers are rejected.
	other := collapseHelpers(ctx, "#include <stdio.h>\n"+strings.Repeat("static int other(void) { return 0; }\n",
		minCollapsedHelperLines)+"int main(void) { return other(); }\n")
	otherMarker := helpersMarkerRe.FindString(other) + "\n"
	_, err = expandCandidate(ctx, otherMarker+collapsed)
	require.ErrorContains(t, err, "several different")

	_, err = expandCandidate(ctx, "// SYZ_HELPERS 0123456789ab\nint main() { return 0; }")
	require.ErrorContains(t, err, "unknown \"// SYZ_HELPERS\" marker 0123456789ab")

	_, err = expandCandidate(ctx, `int main() { const char *p = "$BLOB_0123456789ab"; return p[0]; }`)
	require.ErrorContains(t, err, "unknown or misplaced data blob placeholders: $BLOB_0123456789ab")

	// Syzlang data placeholders can't be used in C.
	syzPlaceholder := replaceProgramBlobs(ctx, `write(0x1, &(0x7f0000000000)="`+strings.Repeat("ab", 200)+`", 0x190)`)
	syzBlob := regexp.MustCompile(`"\$SYZBLOB_[0-9a-f]{12}"`).FindString(syzPlaceholder)
	require.NotEmpty(t, syzBlob)
	_, err = expandCandidate(ctx, "int main() { const char *p = "+syzBlob+"; return p[0]; }")
	require.ErrorContains(t, err, "$SYZBLOB_")
	// Renamed syzlang data placeholders and helper code hashes are not C data.
	renamed := strings.Replace(syzBlob, "$SYZBLOB_", "$BLOB_", 1)
	_, err = expandCandidate(ctx, "int main() { const char *p = "+renamed+"; return p[0]; }")
	require.ErrorContains(t, err, "does not refer to C data")
	helpersBlob := `"$BLOB_` + helpersMarkerRe.FindStringSubmatch(collapsed)[1] + `"`
	_, err = expandCandidate(ctx, "int main() { const char *p = "+helpersBlob+"; return p[0]; }")
	require.ErrorContains(t, err, "does not refer to C data")
	// Data hashes are not helper code markers.
	_, err = expandCandidate(ctx, "// SYZ_HELPERS "+blobHash(renamed)+"\nint main() { return 0; }")
	require.ErrorContains(t, err, "unknown \"// SYZ_HELPERS\" marker")
}

func TestCompileCProgError(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	helpers := strings.Repeat("static int helper(void) { return 0; }\n", minCollapsedHelperLines)
	collapsed := collapseHelpers(ctx, "#include <stdio.h>\n"+helpers+"int main(void) {\n\treturn undefined_var;\n}\n")
	res, err := CompileCProgFunc(ctx, CompileCProgArgs{
		TargetOS:               "linux",
		TargetArch:             "amd64",
		CurrentCandidateReproC: collapsed,
	})
	require.NoError(t, err)
	require.Contains(t, res.CompilerError, "undefined_var")
	// The compiler error does not contain the expanded source.
	require.NotContains(t, res.CompilerError, "static int helper(void)")

	res, err = CompileCProgFunc(ctx, CompileCProgArgs{
		TargetOS:               "linux",
		TargetArch:             "amd64",
		CurrentCandidateReproC: "// SYZ_HELPERS 0123456789ab\nint main() { return 0; }",
	})
	require.NoError(t, err)
	require.Contains(t, res.CompilerError, "unknown \"// SYZ_HELPERS\" marker")
}
