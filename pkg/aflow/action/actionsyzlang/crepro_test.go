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
