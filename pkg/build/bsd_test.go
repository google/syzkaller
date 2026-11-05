// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/vm/vmimpl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFreeBSDVMBuildScript(t *testing.T) {
	script, err := freebsdVMBuildScript(freebsdScriptData{
		ConfFile:        "SYZKALLER",
		HostSrcQuoted:   shellQuote("/syzkaller/managers/ci-freebsd/kernel"),
		CPUs:            8,
		CompilerIDEntry: bsdCompilerIDEntry,
		LoaderConf:      strings.TrimSpace(freebsdLoaderConf),
		SysctlConf:      strings.TrimSpace(freebsdSysctlConf),
	})
	require.NoError(t, err)
	checkShellSyntax(t, script)
	for _, want := range []string{
		"HOST_SRC='/syzkaller/managers/ci-freebsd/kernel'",
		`make -C "$SRC_DIR" -j 8 TARGET=amd64 TARGET_ARCH=amd64 kernel-toolchain`,
		"buildkernel WITH_EXTRA_TCP_STACKS= KERNCONF=SYZKALLER",
		"installkernel WITHOUT_KERNEL_SYMBOLS=yes WITH_EXTRA_TCP_STACKS= KERNCONF=SYZKALLER",
		`tar -cf /dev/vtbd3 -C "$KERN_OBJ_DIR" kernel.full compiler.id`,
		"vm.panic_on_oom=\"1\"\n__SYZ_LOADER_EOF__",
		"vm.redzone.panic=1\n__SYZ_SYSCTL_EOF__",
	} {
		assert.Contains(t, script, want)
	}
}

func TestOpenBSDVMBuildScript(t *testing.T) {
	// sys/arch/amd64/conf/Makefile.amd64 has "COPTS?= -O2", so a command-line COPTS
	// must keep -O2, otherwise the kernel silently gets built without optimizations.
	assert.Equal(t, "COPTS='-O2 -ffile-prefix-map=/build/src=/syzkaller/kernel' ",
		openbsdCOptsArg("/syzkaller/kernel"))
	assert.Empty(t, openbsdCOptsArg("/path with spaces"))
	assert.Empty(t, openbsdCOptsArg("/path$HOME"))

	tests := []struct {
		name    string
		data    openbsdScriptData
		want    []string
		notWant []string
	}{
		{
			name: "plain",
			data: openbsdScriptData{
				KernelName:      "SYZKALLER",
				CPUs:            12,
				COptsArg:        openbsdCOptsArg("/syzkaller/kernel"),
				CompilerIDEntry: bsdCompilerIDEntry,
			},
			want: []string{
				"COMPILE_DIR=/build/src/sys/arch/amd64/compile/SYZKALLER",
				"make -j 12 COPTS='-O2 -ffile-prefix-map=/build/src=/syzkaller/kernel' all",
				`tar -cf /dev/rsd3c -C "$KERN_OBJ_DIR" bsd bsd.gdb compiler.id`,
			},
			notWant: []string{"__SYZ_OVERLAY_EOF__", "__SYZ_SYSCTL_EOF__"},
		},
		{
			name: "overlay_and_sysctl",
			data: openbsdScriptData{
				KernelName:      "SYZKALLER",
				CPUs:            12,
				CompilerIDEntry: bsdCompilerIDEntry,
				OverlayB64:      "SGVsbG8=",
				ExtraSysctl:     "kern.pool_debug=1\nkern.splassert=3",
			},
			want: []string{
				"make -j 12 all",
				"b64decode -r <<'__SYZ_OVERLAY_EOF__' | tar -C /mnt/target -xf -\nSGVsbG8=\n__SYZ_OVERLAY_EOF__\n",
				"<<'__SYZ_SYSCTL_EOF__'\nkern.pool_debug=1\nkern.splassert=3\n__SYZ_SYSCTL_EOF__\n",
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			script, err := openbsdVMBuildScript(tc.data)
			require.NoError(t, err)
			checkShellSyntax(t, script)
			for _, s := range tc.want {
				assert.Contains(t, script, s)
			}
			for _, s := range tc.notWant {
				assert.NotContains(t, script, s)
			}
		})
	}
}

func TestBSDInfraError(t *testing.T) {
	err := bsdInfraError("failed to boot build VM: %w", vmimpl.BootError{Title: "no kvm", Output: []byte("qemu log")})
	infra, ok := errors.AsType[*InfraError](err)
	require.True(t, ok)
	assert.Equal(t, "failed to boot build VM: no kvm", infra.Title)
	assert.Equal(t, "qemu log", string(infra.Output))

	err = bsdInfraError("%w", errors.New("tar failed"))
	infra, ok = errors.AsType[*InfraError](err)
	require.True(t, ok)
	assert.Equal(t, "tar failed", infra.Title)
	assert.Empty(t, infra.Output)
}

func TestWriteKernelSourceTar(t *testing.T) {
	realSrcDir := t.TempDir()
	// Verify a symlinked top-level KernelDir is traversed while inner symlinks are not.
	srcDir := filepath.Join(t.TempDir(), "src-symlink")
	require.NoError(t, os.Symlink(realSrcDir, srcDir))

	secretFile := filepath.Join(t.TempDir(), "secret.txt")
	require.NoError(t, os.WriteFile(secretFile, []byte("TOP_SECRET_HOST_DATA"), 0600))
	require.NoError(t, osutil.FillDirectory(realSrcDir, map[string]string{
		".git/config":            "gitdata",
		"obj/old.o":              "objdata",
		"sub/obj/keep.c":         "nested\n",
		"sys/amd64/conf/GENERIC": "cpu HAMMER\n",
	}))
	require.NoError(t, os.Symlink(secretFile, filepath.Join(realSrcDir, "escape_link")))
	require.NoError(t, os.Symlink("nonexistent_target", filepath.Join(realSrcDir, "dangling_link")))

	tarPath := filepath.Join(t.TempDir(), "src.tar")
	require.NoError(t, writeKernelSourceTar(tarPath, srcDir, ""))
	entries := readTarFile(t, tarPath)

	for _, excluded := range []string{".git", ".git/", ".git/config", "obj", "obj/", "obj/old.o"} {
		assert.NotContains(t, entries, excluded)
	}
	assert.Equal(t, "nested\n", entries["sub/obj/keep.c"].body)
	assert.Equal(t, "cpu HAMMER\n", entries["sys/amd64/conf/GENERIC"].body)
	assert.Equal(t, tarEntry{name: "escape_link", typ: tar.TypeSymlink, link: secretFile}, entries["escape_link"])
	assert.Equal(t, tarEntry{name: "dangling_link", typ: tar.TypeSymlink, link: "nonexistent_target"},
		entries["dangling_link"])

	subTarPath := filepath.Join(t.TempDir(), "sub.tar")
	require.NoError(t, writeKernelSourceTar(subTarPath, srcDir, "sys"))
	subEntries := readTarFile(t, subTarPath)
	assert.Contains(t, subEntries, "sys/amd64/conf/GENERIC")
	assert.NotContains(t, subEntries, "sub/obj/keep.c")
}

func TestExtractExpectedTarOutputs(t *testing.T) {
	expected := map[string]string{"kernel.full": "obj/kernel.full"}

	t.Run("valid_with_compiler_id", func(t *testing.T) {
		tarPath := writeTestTar(t,
			tarEntry{name: "kernel.full", body: "ELF_PAYLOAD"},
			tarEntry{name: "compiler.id", body: "FreeBSD clang 19.1\n\n"},
		)
		outDir := t.TempDir()
		compilerID, err := extractExpectedTarOutputs(tarPath, outDir, expected, 1024)
		require.NoError(t, err)
		assert.Equal(t, "FreeBSD clang 19.1", compilerID)
		got, err := os.ReadFile(filepath.Join(outDir, "obj", "kernel.full"))
		require.NoError(t, err)
		assert.Equal(t, "ELF_PAYLOAD", string(got))
	})

	for _, tc := range []struct {
		name     string
		maxBytes int64
		entries  []tarEntry
		wantErr  string
	}{
		{
			name:     "symlink",
			maxBytes: 1024,
			entries:  []tarEntry{{name: "kernel.full", typ: tar.TypeSymlink, link: "/etc/passwd"}},
			wantErr:  "non-regular",
		},
		{
			name:     "path_traversal",
			maxBytes: 1024,
			entries:  []tarEntry{{name: "../evil", body: "evil"}},
			wantErr:  "unexpected archive entry",
		},
		{
			name:     "unexpected_file",
			maxBytes: 1024,
			entries:  []tarEntry{{name: "unexpected", body: "data"}},
			wantErr:  "unexpected archive entry",
		},
		{
			name:     "oversized",
			maxBytes: 5,
			entries:  []tarEntry{{name: "kernel.full", body: "0123456789"}},
			wantErr:  "out of bounds",
		},
		{
			name:     "missing_expected",
			maxBytes: 1024,
			wantErr:  "missing expected",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tarPath := writeTestTar(t, tc.entries...)
			_, err := extractExpectedTarOutputs(tarPath, t.TempDir(), expected, tc.maxBytes)
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestBSDUserspaceAndConfig(t *testing.T) {
	t.Run("keyless_userspace_and_separate_builder", func(t *testing.T) {
		userspaceDir, outDir := t.TempDir(), t.TempDir()
		require.NoError(t, osutil.FillDirectory(userspaceDir, map[string]string{"image": "RAW_DISK_DATA"}))

		disks, err := prepareBSDDisks(userspaceDir, outDir, "/tmp/freebsd-builder.raw")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(outDir, "image"), disks.outputImage)
		assert.Equal(t, "/tmp/freebsd-builder.raw", disks.bootImage)
		assert.Empty(t, disks.bootSSHKey)
	})

	t.Run("keyed_userspace_default_builder", func(t *testing.T) {
		userspaceDir, outDir := t.TempDir(), t.TempDir()
		require.NoError(t, osutil.FillDirectory(userspaceDir, map[string]string{
			"image": "RAW_DISK_DATA",
			"key":   "PRIVATE_KEY",
		}))

		disks, err := prepareBSDDisks(userspaceDir, outDir, "")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(outDir, "key"), disks.bootSSHKey)
		info, err := os.Stat(disks.bootSSHKey)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
		assert.Equal(t, filepath.Join(userspaceDir, "image"), disks.bootImage)
	})

	t.Run("openbsd_overlay_encoding", func(t *testing.T) {
		userspaceDir := t.TempDir()
		encoded, err := openbsdEncodeOverlay(userspaceDir)
		require.NoError(t, err)
		assert.Empty(t, encoded)

		realOverlay := t.TempDir()
		require.NoError(t, osutil.FillDirectory(realOverlay, map[string]string{"etc/rc.conf.local": "pf=YES\n"}))
		require.NoError(t, os.Symlink(realOverlay, filepath.Join(userspaceDir, "overlay")))

		encoded, err = openbsdEncodeOverlay(userspaceDir)
		require.NoError(t, err)
		rawTar, err := base64.StdEncoding.DecodeString(encoded)
		require.NoError(t, err)
		entries := readTar(t, bytes.NewReader(rawTar))
		assert.Equal(t, "pf=YES\n", entries["etc/rc.conf.local"].body)
	})
}

type tarEntry struct {
	name string
	typ  byte
	body string
	link string
}

// checkShellSyntax runs "sh -n" on the script so that template changes that break
// the guest build script are caught here rather than inside a VM.
func checkShellSyntax(t *testing.T, script string) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh is not available")
	}
	cmd := exec.Command(sh, "-n")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "sh -n failed: %s\n%s", out, script)
}

func writeTestTar(t *testing.T, entries ...tarEntry) string {
	t.Helper()
	tarPath := filepath.Join(t.TempDir(), "out.tar")
	f, err := os.Create(tarPath)
	require.NoError(t, err)
	tw := tar.NewWriter(f)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     e.name,
			Typeflag: typ,
			Mode:     0644,
			Size:     int64(len(e.body)),
			Linkname: e.link,
		}))
		if e.body != "" {
			_, err := tw.Write([]byte(e.body))
			require.NoError(t, err)
		}
	}
	require.NoError(t, tw.Close())
	require.NoError(t, f.Close())
	return tarPath
}

func readTarFile(t *testing.T, path string) map[string]tarEntry {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	return readTar(t, f)
}

func readTar(t *testing.T, r io.Reader) map[string]tarEntry {
	t.Helper()
	tr := tar.NewReader(r)
	entries := make(map[string]tarEntry)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return entries
		}
		require.NoError(t, err)
		name := strings.TrimPrefix(hdr.Name, "./")
		entry := tarEntry{name: name, typ: hdr.Typeflag, link: hdr.Linkname}
		if hdr.Typeflag == tar.TypeReg {
			data, err := io.ReadAll(tr)
			require.NoError(t, err)
			entry.body = string(data)
		}
		entries[name] = entry
	}
}
