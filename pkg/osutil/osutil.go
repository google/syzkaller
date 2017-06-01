// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"bytes"
	"fmt"
	"os/exec"
	"time"
)

// RunCmd runs "bin args..." in dir with timeout and returns its output.
func RunCmd(timeout time.Duration, dir, bin string, args ...string) ([]byte, error) {
	output := new(bytes.Buffer)
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %v %+v: %v", bin, args, err)
	}
	done := make(chan bool)
	go func() {
		select {
		case <-time.After(time.Hour):
			cmd.Process.Kill()
		case <-done:
		}
	}()
	defer close(done)
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("failed to run %v %+v: %v\n%v", bin, args, err, output.String())
	}
	return output.Bytes(), nil
}
