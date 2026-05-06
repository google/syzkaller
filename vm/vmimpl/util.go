// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vmimpl

import (
	"errors"
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
				Output: []byte(osutil.VerboseMessage(err)),
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

func scpArgs(debug bool, sshKey string, port int, systemSSHCfg bool) []string {
	return append(sshArgs(debug, sshKey, "-P", port, 0, systemSSHCfg), "-O") // Default to legacy scp protocol.
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

type SCPOptions struct {
	Debug         bool
	Key           string
	Port          int
	SystemSSHCfg  bool
	User          string
	Addr          string
	Timeout       time.Duration
	Dir           string
	VerboseOutput bool
}

func SCP(hostSrc, vmDst string, opts SCPOptions) error {
	args := append(scpArgs(opts.VerboseOutput, opts.Key, opts.Port, opts.SystemSSHCfg),
		hostSrc, opts.User+"@"+opts.Addr+":"+vmDst)
	if opts.Debug {
		log.Logf(0, "running command: scp %#v", args)
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	output, err := osutil.RunCmd(timeout, opts.Dir, "scp", args...)
	if err != nil {
		var verr *osutil.VerboseError
		if errors.As(err, &verr) {
			log.Logf(0, "scp failed: %v\n%s", err, string(verr.Output))
		}
		return fmt.Errorf("scp failed: %w", err)
	}
	if opts.Debug {
		log.Logf(0, "result: %s", output)
	}
	return nil
}
