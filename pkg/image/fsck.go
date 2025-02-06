// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package image

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
)

// Fsck runs fsckCmd against a file system image provided in r. It returns the
// fsck logs, whether the file system is clean and an error in case fsck could
// not be run.
func Fsck(r io.Reader, fsckCmd string) ([]byte, bool, error) {
	// Write the image to a temporary file.
	tempFile, err := os.CreateTemp("", "*.img")
	if err != nil {
		return nil, false, fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer os.Remove(tempFile.Name())

	_, err = io.Copy(tempFile, r)
	if err != nil {
		return nil, false, fmt.Errorf("failed to write data to temporary file: %w", err)
	}

	if err := tempFile.Close(); err != nil {
		return nil, false, fmt.Errorf("failed to close temporary file: %w", err)
	}

	osutil.SandboxChown(tempFile.Name())

	// And run the provided fsck command on it.
	fsck := append(strings.Fields(fsckCmd), tempFile.Name())
	cmd := osutil.Command(fsck[0], fsck[1:]...)
	if err := osutil.Sandbox(cmd, true, true); err != nil {
		return nil, false, err
	}

	exitCode := 0
	output, err := cmd.CombinedOutput()
	if err != nil {
		var exitError (*exec.ExitError)
		ok := errors.As(err, &exitError)
		if ok {
			exitCode = exitError.ExitCode()
		} else {
			return nil, false, err
		}
	}

	prefix := fsckCmd + " exited with status code " + strconv.Itoa(exitCode) + "\n"
	return append([]byte(prefix), output...), exitCode == 0, nil
}

type FsckChecker struct {
	mu     sync.Mutex
	exists map[string]bool
}

func (fc *FsckChecker) Exists(cmd string) bool {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	bin := strings.Fields(cmd)[0]
	if ret, ok := fc.exists[bin]; ok {
		return ret
	}
	if fc.exists == nil {
		fc.exists = map[string]bool{}
	}
	_, err := exec.LookPath(bin)
	found := err == nil
	if !found {
		log.Logf(0, "%s not found, images won't be checked", bin)
	}
	fc.exists[bin] = found
	return found
}
