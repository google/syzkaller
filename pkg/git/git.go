// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package git provides helper functions for working with git repositories.
package git

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// Poll checkouts the specified repository/branch in dir.
// This involves fetching/resetting/cloning as necessary to recover from all possible problems.
// Returns hash of the HEAD commit in the specified branch.
func Poll(dir, repo, branch string) (string, error) {
	runCmd(dir, "git", "reset", "--hard")
	if _, err := runCmd(dir, "git", "fetch", "--no-tags", "--depth=", "1"); err != nil {
		if err := os.RemoveAll(dir); err != nil {
			return "", fmt.Errorf("failed to remove repo dir: %v", err)
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			return "", fmt.Errorf("failed to create repo dir: %v", err)
		}
		args := []string{
			"clone",
			repo,
			"--no-tags",
			"--depth", "1",
			"--single-branch",
			"--branch", branch,
			dir,
		}
		if _, err := runCmd("", "git", args...); err != nil {
			return "", err
		}
	}
	if _, err := runCmd(dir, "git", "checkout", branch); err != nil {
		return "", err
	}
	return HeadCommit(dir)
}

// HeadCommit returns hash of the HEAD commit of the current branch of git repository in dir.
func HeadCommit(dir string) (string, error) {
	output, err := runCmd(dir, "git", "log", "--pretty=format:'%H'", "-n", "1")
	if err != nil {
		return "", err
	}
	if len(output) != 0 && output[len(output)-1] == '\n' {
		output = output[:len(output)-1]
	}
	if len(output) != 0 && output[0] == '\'' && output[len(output)-1] == '\'' {
		output = output[1 : len(output)-1]
	}
	if len(output) != 40 {
		return "", fmt.Errorf("unexpected git log output, want commit hash: %q", output)
	}
	return string(output), nil
}

func runCmd(dir, bin string, args ...string) ([]byte, error) {
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
