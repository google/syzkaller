// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc

import (
	"testing"
)

func TestOutputDeadline(t *testing.T) {
	// Run the command that leaks stderr to a child process.
	c, err := makeCommand(1, []string{
		"sh",
		"-c",
		"exec 1>&2; ( sleep 100; echo fail ) & echo done",
	}, &Config{}, nil, nil, nil, "/tmp")
	if err != nil {
		t.Fatal(err)
	}
	c.wait()
	out := <-c.readDone
	if string(out) != "done\n" {
		t.Errorf("Unexpected output: '%s'", out)
	}
}
