// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package targets

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckBSDSysroot(t *testing.T) {
	t.Run("freebsd", func(t *testing.T) {
		dir := t.TempDir()
		assert.NotEmpty(t, checkBSDSysroot(FreeBSD, AMD64, dir))

		// Linux ELF crt1.o must not be accepted as a FreeBSD sysroot.
		writeMinimalELF(t, filepath.Join(dir, "usr", "lib", "crt1.o"), elf.ELFOSABI_NONE, elf.EM_X86_64, elf.ELFCLASS64)
		assert.NotEmpty(t, checkBSDSysroot(FreeBSD, AMD64, dir))

		// FreeBSD amd64 + lib32 sysroot satisfies amd64 and 386, while arm64/riscv64 are unsupported.
		writeMinimalELF(t, filepath.Join(dir, "usr", "lib", "crt1.o"), elf.ELFOSABI_FREEBSD, elf.EM_X86_64, elf.ELFCLASS64)
		writeMinimalELF(t, filepath.Join(dir, "usr", "lib32", "crt1.o"), elf.ELFOSABI_FREEBSD, elf.EM_386, elf.ELFCLASS32)
		assert.Empty(t, checkBSDSysroot(FreeBSD, AMD64, dir))
		assert.Empty(t, checkBSDSysroot(FreeBSD, I386, dir))
		assert.NotEmpty(t, checkBSDSysroot(FreeBSD, ARM64, dir))
		assert.NotEmpty(t, checkBSDSysroot(FreeBSD, RiscV64, dir))
	})
}

func TestBSDCrossTargetScoping(t *testing.T) {
	t64 := Get(FreeBSD, AMD64)
	require.NotNil(t, t64)
	origFlags := slices.Clone(t64.CFlags)
	assert.Contains(t, origFlags, "--target=x86_64-unknown-freebsd14.0")

	otherClang := GetEx(FreeBSD, AMD64, true)
	require.NotNil(t, otherClang)
	assert.Contains(t, otherClang.CFlags, "--target=x86_64-unknown-freebsd14.0")
	assert.Equal(t, origFlags, t64.CFlags)

	otherGCC := GetEx(FreeBSD, AMD64, false)
	require.NotNil(t, otherGCC)
	assert.Equal(t, origFlags, t64.CFlags)

	if runtime.GOOS == Linux {
		assert.Equal(t, Linux, Get(FreeBSD, AMD64).BuildOS)
		assert.Equal(t, "cpp", Get(FreeBSD, AMD64).CPP)
		assert.Equal(t, Linux, Get(FreeBSD, I386).BuildOS)
		assert.Equal(t, FreeBSD, Get(FreeBSD, ARM64).BuildOS)
		assert.Equal(t, FreeBSD, Get(FreeBSD, RiscV64).BuildOS)
	}
}

func writeMinimalELF(t *testing.T, path string, osabi elf.OSABI, machine elf.Machine, class elf.Class) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0755))
	var buf [64]byte
	copy(buf[:4], []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = byte(class)
	buf[5] = byte(elf.ELFDATA2LSB)
	buf[6] = byte(elf.EV_CURRENT)
	buf[7] = byte(osabi)
	binary.LittleEndian.PutUint16(buf[16:18], uint16(elf.ET_REL))
	binary.LittleEndian.PutUint16(buf[18:20], uint16(machine))
	binary.LittleEndian.PutUint32(buf[20:24], uint32(elf.EV_CURRENT))
	require.NoError(t, os.WriteFile(path, buf[:], 0644))
}
