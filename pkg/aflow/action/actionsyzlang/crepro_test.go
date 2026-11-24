// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package actionsyzlang

import (
	"runtime"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyzlangToC(t *testing.T) {
	tests := []string{"amd64", "arm64"}
	for _, arch := range tests {
		t.Run(arch, func(t *testing.T) {
			sysTarget := targets.Get("linux", arch)
			if runtime.GOOS != sysTarget.BuildOS || sysTarget.BrokenCompiler != "" {
				t.Skipf("cannot build linux/%s on this host", arch)
			}
			validProg := `r0 = openat(0xffffffffffffff9c, &AUTO='./file1\x00', 0x42, 0x1ff)
write(r0, &AUTO="01010101", 0x4)
`
			res, err := createCRepro(&aflow.Context{}, createCReproArgs{
				TargetOS:   "linux",
				TargetArch: arch,
				ReproSyz:   validProg,
			})
			require.NoError(t, err)
			require.NotEmpty(t, res.SimplifiedCRepro)
			require.Contains(t, res.SimplifiedCRepro, "int main")
		})
	}
}

func TestSyzlangToC_NetInjection(t *testing.T) {
	sysTarget := targets.Get("linux", "amd64")
	if runtime.GOOS != sysTarget.BuildOS || sysTarget.BrokenCompiler != "" {
		t.Skipf("cannot build linux/amd64 on this host (broken compiler: %v)", sysTarget.BrokenCompiler)
	}
	progWithEth := `r0 = socket$nl_generic(0x10, 0x3, 0x10)
syz_emit_ethernet(0x10, &(0x7f0000000100)=ANY=[@ANYBLOB="ffffffffffffaabbccddeeff88ca5b50"], 0x0)
`
	res, err := createCRepro(&aflow.Context{}, createCReproArgs{
		TargetOS:   "linux",
		TargetArch: "amd64",
		ReproSyz:   progWithEth,
	})
	require.NoError(t, err)
	assert.Contains(t, res.SimplifiedCRepro, "int main")
	assert.Contains(t, res.SimplifiedCRepro, "syz_emit_ethernet(")
}

func TestSyzlangToC_Fallback(t *testing.T) {
	// The clone call is disabled in the descriptions, and unknown_syscall does not exist;
	// both fail NonStrict deserialization and should fall back instead of failing the job.
	progWithDisabled := `r0 = openat(0xffffffffffffff9c, &AUTO='./file1\x00', 0x42, 0x1ff)
clone(0x0, 0x0, 0x0, 0x0, 0x0)
write(r0, &AUTO="01010101", 0x4)
`
	t.Run("fallback to ReproC", func(t *testing.T) {
		origC := `int main(void) { memcpy((void*)0x20000, "` + strings.Repeat(`\x41`, 50) + `", 50); return 0; }`
		res, err := createCRepro(&aflow.Context{}, createCReproArgs{
			TargetOS:   "linux",
			TargetArch: "amd64",
			ReproSyz:   progWithDisabled,
			ReproC:     origC,
		})
		require.NoError(t, err)
		assert.Equal(t, `int main(void) { memcpy((void*)0x20000, "... [truncated large byte array] ...", 50); return 0; }`,
			res.SimplifiedCRepro)
	})

	t.Run("fallback to ReproSyz when ReproC is empty", func(t *testing.T) {
		invalidProg := `r0 = unknown_syscall(0x123, &AUTO="` + strings.Repeat("aa", 100) + `")`
		res, err := createCRepro(&aflow.Context{}, createCReproArgs{
			TargetOS:   "linux",
			TargetArch: "amd64",
			ReproSyz:   invalidProg,
		})
		require.NoError(t, err)
		assert.Equal(t, `r0 = unknown_syscall(0x123, &AUTO="... [truncated large byte array] ...")`,
			res.SimplifiedCRepro)
	})

	t.Run("fallback to ReproSyz head when exceeding size limit", func(t *testing.T) {
		head := "r0 = unknown_syscall(0x123)\n"
		hugeSyz := head + strings.Repeat("getpid()\n", maxFallbackReproSize/5)
		res, err := createCRepro(&aflow.Context{}, createCReproArgs{
			TargetOS:   "linux",
			TargetArch: "amd64",
			ReproSyz:   hugeSyz,
		})
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(res.SimplifiedCRepro, head))
		assert.Contains(t, res.SimplifiedCRepro, "<<cut ")
		assert.Less(t, len(res.SimplifiedCRepro), len(hugeSyz))
	})

	t.Run("fallback to ReproC tail when exceeding size limit", func(t *testing.T) {
		boilerplate := strings.Repeat("static void helper(void) {}\n", maxFallbackReproSize/10)
		tail := "int main(void) { syscall(__NR_getpid); return 0; }\n"
		res, err := createCRepro(&aflow.Context{}, createCReproArgs{
			TargetOS:   "linux",
			TargetArch: "amd64",
			ReproSyz:   progWithDisabled,
			ReproC:     boilerplate + tail,
		})
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(res.SimplifiedCRepro, "<<cut "))
		assert.True(t, strings.HasSuffix(res.SimplifiedCRepro, tail))
		assert.Less(t, len(res.SimplifiedCRepro), len(boilerplate+tail))
	})
}

func TestSyzlangToC_Empty(t *testing.T) {
	res, err := createCRepro(&aflow.Context{}, createCReproArgs{ReproSyz: ""})
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
