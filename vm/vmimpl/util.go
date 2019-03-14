// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vmimpl

import (
	"fmt"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
)

// Sleep for d.
// If shutdown is in progress, return false prematurely.
func SleepInterruptible(d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-Shutdown:
		return false
	}
}

func WaitForSSH(debug bool, timeout time.Duration, addr, sshKey, sshUser, OS string, port int, stop chan error) error {
	pwd := "pwd"
	if OS == "windows" {
		pwd = "dir"
	}
	startTime := time.Now()
	SleepInterruptible(5 * time.Second)
	for {
		select {
		case <-time.After(5 * time.Second):
		case err := <-stop:
			return err
		case <-Shutdown:
			return fmt.Errorf("shutdown in progress")
		}
		args := append(SSHArgs(debug, sshKey, port), sshUser+"@"+addr, pwd)
		if debug {
			log.Logf(0, "running ssh: %#v", args)
		}
		_, err := osutil.RunCmd(time.Minute, "", "ssh", args...)
		if err == nil {
			return nil
		}
		if debug {
			log.Logf(0, "ssh failed: %v", err)
		}
		if time.Since(startTime) > timeout {
			return &osutil.VerboseError{Title: "can't ssh into the instance", Output: []byte(err.Error())}
		}
	}
}

func SSHArgs(debug bool, sshKey string, port int) []string {
	return sshArgs(debug, sshKey, "-p", port)
}

func SCPArgs(debug bool, sshKey string, port int) []string {
	return sshArgs(debug, sshKey, "-P", port)
}

func sshArgs(debug bool, sshKey, portArg string, port int) []string {
	args := []string{
		portArg, fmt.Sprint(port),
		"-F", "/dev/null",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=10",
	}
	if sshKey != "" {
		args = append(args, "-i", sshKey)
	}
	if debug {
		args = append(args, "-v")
	}
	return args
}
