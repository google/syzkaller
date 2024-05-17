// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc

import (
	"testing"

	"github.com/google/syzkaller/pkg/flatrpc"
)

func TestOutputDeadline(t *testing.T) {
	// Run the command that leaks stderr to a child process.
	env := &Env{
		bin: []string{
			"sh",
			"-c",
			"exec 1>&2; ( sleep 100; echo fail ) & echo done",
		},
		pid:    1,
		config: &Config{},
	}
	c, err := env.makeCommand(&flatrpc.ExecOpts{}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c.wait()
	out := <-c.readDone
	if string(out) != "done\n" {
		t.Errorf("unexpected output: '%s'", out)
	}
}
