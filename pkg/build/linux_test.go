// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build linux

package build

import (
	"bytes"
	"os"
	"testing"
	"text/template"

	"github.com/google/syzkaller/pkg/osutil"
)

func TestElfBinarySignature(t *testing.T) {
	enumerateFlags(t, nil, []string{"-g", "-O1", "-O2", "-no-pie", "-static"})
}

func enumerateFlags(t *testing.T, flags, allFlags []string) {
	if len(allFlags) != 0 {
		enumerateFlags(t, flags, allFlags[1:])
		enumerateFlags(t, append(flags, allFlags[0]), allFlags[1:])
		return
	}
	t.Logf("testing: %+v", flags)
	sign1 := sign(t, flags, false, false)
	sign2 := sign(t, flags, false, true)
	sign3 := sign(t, flags, true, false)
	if sign1 != sign2 {
		t.Errorf("signature has changed after a comment-only change")
	}
	if sign1 == sign3 {
		t.Errorf("signature has not changed after a change")
	}

	//func elfBinarySignature(bin string) (string, error) {
}

func sign(t *testing.T, flags []string, changed, comment bool) string {
	buf := new(bytes.Buffer)
	if err := srcTemplate.Execute(buf, SrcParams{Changed: changed, Comment: comment}); err != nil {
		t.Fatal(err)
	}
	src := buf.Bytes()
	bin, err := osutil.TempFile("syz-build-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(bin)
	cmd := osutil.Command("gcc", append(flags, "-pthread", "-o", bin, "-x", "c", "-")...)
	cmd.Stdin = buf
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compiler failed: %v\n%s\n\n%s", err, src, out)
	}
	sign, err := elfBinarySignature(bin)
	if err != nil {
		t.Fatal(err)
	}
	return sign
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
