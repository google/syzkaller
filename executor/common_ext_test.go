// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package executor

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
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

	// The example setup_ext_test does:
	// *(uint64*)(SYZ_DATA_OFFSET + 0x1234) = 0xbadc0ffee;
	// The following program tests that that value is present at 0x1234.
	test := `syz_compare(&(0x7f0000001234)="", 0x8, &(0x7f0000000000)=@blob="eeffc0ad0b000000", AUTO)`
	p, err := target.Deserialize([]byte(test), prog.Strict)
	if err != nil {
		t.Fatal(err)
	}
	cfg, opts, err := ipcconfig.Default(target)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Executor = bin
	cfg.Flags |= ipc.FlagDebug
	env, err := ipc.MakeEnv(cfg, 0)
	if err != nil {
		t.Fatalf("failed to create env: %v", err)
	}
	defer env.Close()
	_, info, _, err := env.Exec(opts, p)
	if err != nil {
		t.Fatal(err)
	}
	if call := info.Calls[0]; (call.Flags&ipc.CallFinished) == 0 || call.Errno != 0 {
		t.Fatalf("bad call result: flags=%x errno=%v", call.Flags, call.Errno)
	}
}
