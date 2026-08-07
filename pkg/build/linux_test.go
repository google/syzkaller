// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build linux

package build

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"text/template"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestElfBinarySignature(t *testing.T) {
	t.Parallel()
	enumerateFlags(t, nil, []string{"-g", "-O1", "-O2", "-no-pie", "-static"})
}

func TestQueryLinuxCompiler(t *testing.T) {
	const goodDir = "./testdata/linux_compiler_ok"
	const expectedCompiler = "gcc (Debian 10.2.1-6+build2) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2"
	ret, err := queryLinuxCompiler(goodDir)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if ret != expectedCompiler {
		t.Fatalf("got: %T, expected: %T", ret, expectedCompiler)
	}
	const badDir = "./testingData/non_existing_folder"
	_, err = queryLinuxCompiler(badDir)
	if err == nil {
		t.Fatalf("expected an error, got none")
	}
}

func TestBuildEnvFiltersUnexpectedVariables(t *testing.T) {
	t.Setenv("CARGO_HOME", "/tmp/cargo")
	t.Setenv("CCACHE_COMPILERCHECK", "content")
	t.Setenv("LANGUAGE", "en_US")
	t.Setenv("LC_SYZ_TEST", "C")
	t.Setenv("NOT_FOR_TEST", "1")
	t.Setenv("RUSTUP_HOME", "/tmp/rustup")
	t.Setenv("SOURCE_DATE_EPOCH", "1")
	t.Setenv("TMPDIR", "/tmp/syzkaller")
	t.Setenv("CARGO_HOME_TOKEN", "secret")
	t.Setenv("SYZ_BUILD_ENV_SECRET", "secret")
	t.Setenv("USER_TOKEN", "secret")

	env := buildEnv("SYZ_VM_TYPE=qemu")

	require.Contains(t, env, "CARGO_HOME=/tmp/cargo")
	require.Contains(t, env, "CCACHE_COMPILERCHECK=content")
	require.Contains(t, env, "LANGUAGE=en_US")
	require.Contains(t, env, "LC_SYZ_TEST=C")
	require.Contains(t, env, "NOT_FOR_TEST=1")
	require.Contains(t, env, "RUSTUP_HOME=/tmp/rustup")
	require.Contains(t, env, "SOURCE_DATE_EPOCH=1")
	require.Contains(t, env, "TMPDIR=/tmp/syzkaller")
	require.Contains(t, env, "SYZ_VM_TYPE=qemu")
	require.NotContains(t, env, "CARGO_HOME_TOKEN=secret")
	require.NotContains(t, env, "SYZ_BUILD_ENV_SECRET=secret")
	require.NotContains(t, env, "USER_TOKEN=secret")
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
