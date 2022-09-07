// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package executor

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

func TestCommonExt(t *testing.T) {
	target, err := prog.GetTarget("test", "64_fork")
	if err != nil {
		t.Fatal(err)
	}
	bin, err := csource.BuildFile(target, "executor.cc", "-DSYZ_TEST_COMMON_EXT_EXAMPLE=1")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(bin)
	out, err := osutil.RunCmd(time.Minute, "", bin, "setup")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("example setup_ext called")) {
		t.Fatalf("setup_ext wasn't called:\n%s", out)
	}
}
