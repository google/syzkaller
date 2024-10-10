// Copyright (c) Qualcomm Innovation Center, Inc. All rights reserved
// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func TestDBRemoveMatchLine(t *testing.T) {
	fn, err := osutil.TempFile("syzkaller.test.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(fn)
	db1, err := db.Open(fn, false)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	input := []string{
		"r0 = open$dir(&(0x7f0000000000), 0x161840, 0x162)",
		"ioctl$BTRFS_IOC_DEFRAG(r0, 0x50009402, 0x0)",
		"close(r0)",
	}
	want := []string{
		"ioctl$BTRFS_IOC_DEFRAG(0xffffffffffffffff, 0x50009402, 0x0)",
		"close(0xffffffffffffffff)",
	}
	db1.Save("rm", []byte(strings.Join(input, "\n")), 0)
	db1.Flush()
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	if err != nil {
		t.Fatal(err)
	}
	rm(fn, "open$dir", target)
	db1, err = db.Open(fn, false)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	expected := fmt.Sprintf("%s\n", strings.Join(want, "\n"))
	assert.Equal(t, expected, string(db1.Records["rm"].Val))
}
