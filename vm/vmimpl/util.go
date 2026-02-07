// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vmimpl

import (
	"fmt"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
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

type SSHOptions struct {
	Addr string
	Port int
	User string
	Key  string
}

func WaitForSSH(timeout time.Duration, opts SSHOptions, OS string, stop <-chan error, systemSSHCfg, debug bool) error {
	pwd := "pwd"
	if OS == targets.Windows {
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
		args := append(SSHArgs(debug, opts.Key, opts.Port, systemSSHCfg), opts.User+"@"+opts.Addr, pwd)
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
			return &osutil.VerboseError{
				Err:    ErrCantSSH,
				Output: []byte(err.Error()),
			}
		}
	}
}

var ErrCantSSH = fmt.Errorf("can't ssh into the instance")

func SSHArgs(debug bool, sshKey string, port int, systemSSHCfg bool) []string {
	return sshArgs(debug, sshKey, "-p", port, 0, systemSSHCfg)
}

func SSHArgsForward(debug bool, sshKey string, port, forwardPort int, systemSSHCfg bool) []string {
	return sshArgs(debug, sshKey, "-p", port, forwardPort, systemSSHCfg)
}

func SCPArgs(debug bool, sshKey string, port int, systemSSHCfg bool) []string {
	return sshArgs(debug, sshKey, "-P", port, 0, systemSSHCfg)
}

func sshArgs(debug bool, sshKey, portArg string, port, forwardPort int, systemSSHCfg bool) []string {
	args := []string{portArg, fmt.Sprint(port)}
	if !systemSSHCfg {
		args = append(args,
			"-F", "/dev/null",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "IdentitiesOnly=yes")
	}
	args = append(args,
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "ConnectTimeout=10",
	)
	if sshKey != "" {
		args = append(args, "-i", sshKey)
	}
	if forwardPort != 0 {
		// Forward target port as part of the ssh connection (reverse proxy).
		args = append(args, "-R", fmt.Sprintf("%v:127.0.0.1:%v", forwardPort, forwardPort))
	}
	if debug {
		args = append(args, "-v")
	}
	return args
}
