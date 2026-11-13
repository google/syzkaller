// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build linux

package build

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestFixGrubRootDevice(t *testing.T) {
	tests := []struct {
		name     string
		origGrub string
		sig      uint32
		partType byte
		wantGrub string
		wantErr  bool
	}{
		{
			name:     "zero-mbr-sig",
			origGrub: "linux /boot/bzImage console=ttyS0 root=/dev/sda1 earlyprintk=serial\n",
			sig:      0,
			partType: 0x83,
			wantGrub: "linux /boot/bzImage console=ttyS0 root=PARTUUID=00000000-01 earlyprintk=serial\n",
		},
		{
			name:     "nonzero-mbr-sig",
			origGrub: "linux /boot/bzImage console=ttyS0 root=/dev/sda1 earlyprintk=serial\n",
			sig:      0xdeadbeef,
			partType: 0x83,
			wantGrub: "linux /boot/bzImage console=ttyS0 root=PARTUUID=deadbeef-01 earlyprintk=serial\n",
		},
		{
			name:     "gpt-partlabel-noop",
			origGrub: "linux /boot/Image console=ttyS0 root=PARTLABEL=rootfs earlyprintk=serial\n",
			sig:      0,
			partType: 0xee,
			wantGrub: "linux /boot/Image console=ttyS0 root=PARTLABEL=rootfs earlyprintk=serial\n",
		},
		{
			name:     "gpt-protective-mbr-rejected",
			origGrub: "linux /boot/bzImage console=ttyS0 root=/dev/sda1\n",
			sig:      0,
			partType: 0xee,
			wantErr:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mountDir := t.TempDir()
			grubCfg := filepath.Join(mountDir, "boot", "grub", "grub.cfg")
			require.NoError(t, os.MkdirAll(filepath.Dir(grubCfg), 0755))
			require.NoError(t, os.WriteFile(grubCfg, []byte(tc.origGrub), 0644))

			imgPath := writeTestMBRImage(t, tc.sig, tc.partType)
			err := fixGrubRootDevice(mountDir, imgPath)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			got, err := os.ReadFile(grubCfg)
			require.NoError(t, err)
			assert.Equal(t, tc.wantGrub, string(got))
		})
	}
}

func TestElfBinarySignature(t *testing.T) {
	t.Parallel()
	enumerateFlags(t, nil, []string{"-g", "-O1", "-O2", "-no-pie", "-static"})
}

func TestQueryLinuxCompiler(t *testing.T) {
	const goodDir = "./testdata/linux_compiler_ok"
	const expectedCompiler = "gcc (Debian 10.2.1-6+build2) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2"
	root, err := osutil.OpenSandboxRoot(goodDir)
	require.NoError(t, err)
	defer root.Close()
	ret, err := queryLinuxCompiler(root)
	require.NoError(t, err)
	assert.Equal(t, expectedCompiler, ret)

	// The testdata dir does not contain include/generated/compile.h.
	badRoot, err := osutil.OpenSandboxRoot("./testdata")
	require.NoError(t, err)
	defer badRoot.Close()
	_, err = queryLinuxCompiler(badRoot)
	assert.Error(t, err)
}

func enumerateFlags(t *testing.T, flags, allFlags []string) {
	if len(allFlags) != 0 {
		enumerateFlags(t, flags, allFlags[1:])
		enumerateFlags(t, append(flags, allFlags[0]), allFlags[1:])
		return
	}
	t.Run(strings.Join(flags, "-"), func(t *testing.T) {
		t.Parallel()
		sign1, sign2, sign3 := "", "", ""
		g, _ := errgroup.WithContext(context.Background())
		g.Go(func() error {
			var err error
			sign1, err = sign(t, flags, false, false)
			return err
		})
		g.Go(func() error {
			var err error
			sign2, err = sign(t, flags, false, true)
			return err
		})
		g.Go(func() error {
			var err error
			sign3, err = sign(t, flags, true, false)
			return err
		})
		if err := g.Wait(); err != nil {
			t.Error(err)
		}
		if sign1 != sign2 {
			t.Errorf("signature has changed after a comment-only change")
		}
		if sign1 == sign3 {
			t.Errorf("signature has not changed after a change")
		}
	})
}

func sign(t *testing.T, flags []string, changed, comment bool) (string, error) {
	buf := new(bytes.Buffer)
	if err := srcTemplate.Execute(buf, SrcParams{Changed: changed, Comment: comment}); err != nil {
		return "", fmt.Errorf("template exec failed: %w", err)
	}
	src := buf.Bytes()
	bin, err := osutil.TempFile("syz-build-test")
	if err != nil {
		return "", fmt.Errorf("temp file creation error: %w", err)
	}
	defer os.Remove(bin)
	cmd := osutil.Command("gcc", append(flags, "-pthread", "-o", bin, "-x", "c", "-")...)
	cmd.Stdin = buf
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("compiler failed: %w\n%s\n\n%s", err, src, out)
	}
	sign, err := elfBinarySignature(bin, &debugtracer.TestTracer{T: t})
	if err != nil {
		return "", fmt.Errorf("signature creation failed: %w", err)
	}
	return sign, nil
}

type SrcParams struct {
	Changed bool
	Comment bool
}

var srcTemplate = template.Must(template.New("").Parse(`
#include <stdio.h>
#include <pthread.h>

int main() {
	int x = {{if .Changed}}0{{else}}1{{end}};
	{{if .Comment}}
	// Some comment goes here.
	// It affects line numbers in debug info.
	{{end}}
	printf("%d %p\n", x, pthread_create);
}
`))

func writeTestMBRImage(t *testing.T, sig uint32, partType byte) string {
	t.Helper()
	imgPath := filepath.Join(t.TempDir(), "disk.raw")
	var mbr [512]byte
	binary.LittleEndian.PutUint32(mbr[0x1b8:0x1bc], sig)
	mbr[0x1c2] = partType
	mbr[0x1fe] = 0x55
	mbr[0x1ff] = 0xaa
	require.NoError(t, os.WriteFile(imgPath, mbr[:], 0600))
	return imgPath
}
