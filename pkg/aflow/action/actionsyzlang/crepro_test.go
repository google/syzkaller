// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package actionsyzlang

import (
	"runtime"
	"testing"

	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func TestSyzlangToC(t *testing.T) {
	sysTarget := targets.Get("linux", "amd64")
	if runtime.GOOS != sysTarget.BuildOS || sysTarget.BrokenCompiler != "" {
		t.Skip("cannot build linux/amd64 on this host")
	}
	validProg := `r0 = openat(0xffffffffffffff9c, &AUTO='./file1\x00', 0x42, 0x1ff)
write(r0, &AUTO="01010101", 0x4)
`
	res, err := createCRepro(nil, createCReproArgs{ReproSyz: validProg})
	require.NoError(t, err)
	require.NotEmpty(t, res.SimplifiedCRepro)
	require.Contains(t, res.SimplifiedCRepro, "int main")
}

func TestSyzlangToC_Invalid(t *testing.T) {
	invalidProg := `r0 = unknown_syscall(0x123)`
	res, err := createCRepro(nil, createCReproArgs{ReproSyz: invalidProg})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to deserialize syz repro")
	require.Empty(t, res.SimplifiedCRepro)
}

func TestSyzlangToC_Empty(t *testing.T) {
	res, err := createCRepro(nil, createCReproArgs{ReproSyz: ""})
	require.NoError(t, err)
	require.Empty(t, res.SimplifiedCRepro)
}

func TestTruncateLargeData(t *testing.T) {
	input := `
    memcpy(
        (void*)0x20000001f7c0,
        "\x78\x9c\xec\xdd\x09\x9c\x4d\xf5\xdf\x07\xf0\xdf\xd9\xf7\xfd\x5c\xd9"
        "\x0d\x4d\x92\x90\x7d\x49\xb2\xaf\xd9\xb7\x90\xec\xfb\x9e\x2d\x24\x86"
        "\x64\x4b\x96\x08\xc9\x96\x64\x4b\x12\x2a\x49\x22\x89\x92\xec\x92\x90"
        "\x24\xa9\x24\xed\x92\x78\x5e\xce\xdc\x99\x66\x06\xff\x3a\x6d\xbf\x9e"
        "\xe3\xf3\xee\xd5\xf7\xdc\x39\x73\xef\x39\xdf\xbb\x7c\xce\x66\xce\xb9"
        "\x24\xa9\x24\xed\x92\x78\x5e\xce\xdc\x99\x66\x06\xff\x3a\x6d\xbf\x9e",
        200);
`
	expectedInput := `
    memcpy(
        (void*)0x20000001f7c0,
        "... [truncated large byte array] ...",
        200);
`
	require.Equal(t, expectedInput, truncateLargeData(input))

	singleLineInput := "memcpy((void*)0x20000, \"\\x78\\x9c\\xec\\xdd\\x09\\x9c\\x4d\\xf5\\xdf\\x07" +
		"\\xf0\\xdf\\xd9\\xf7\\xfd\\x5c\\xd9\\x0d\\x4d\\x92\\x90\\x7d\\x49\\xb2\\xaf\\xd9\\xb7\\x90" +
		"\\xec\\xfb\\x9e\\x2d\\x24\\x86\\x64\\x4b\\x96\\x08\\xc9\\x96\\x64\\x4b\\x12\\x2a\\x49\\x22" +
		"\\x89\\x92\\xec\\x92\\x90\", 200);"
	expectedSingleLineInput := `memcpy((void*)0x20000, "... [truncated large byte array] ...", 200);`
	require.Equal(t, expectedSingleLineInput, truncateLargeData(singleLineInput))

	smallInput := `memcpy((void*)0x20000, "\x11\x22", 2);`
	require.Equal(t, smallInput, truncateLargeData(smallInput))
}
