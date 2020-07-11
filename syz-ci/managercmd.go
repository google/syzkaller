// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
)

// ManagerCmd encapsulates a single instance of syz-manager process.
// It automatically restarts syz-manager if it exits unexpectedly,
// and supports graceful shutdown via SIGINT.
type ManagerCmd struct {
	name    string
	log     string
	errorf  Errorf
	bin     string
	args    []string
	closing chan bool
}

type Errorf func(msg string, args ...interface{})

// NewManagerCmd starts new syz-manager process.
// name - name for logging.
// log - manager log file with stdout/stderr.
// bin/args - process binary/args.
func NewManagerCmd(name, log string, errorf Errorf, bin string, args ...string) *ManagerCmd {
	mc := &ManagerCmd{
		name:    name,
		log:     log,
		errorf:  errorf,
		bin:     bin,
		args:    args,
		closing: make(chan bool),
	}
	go mc.loop()
	return mc
}

// Close gracefully shutdowns the process and waits for its termination.
func (mc *ManagerCmd) Close() {
	mc.closing <- true
	<-mc.closing
}

func (mc *ManagerCmd) loop() {
	const (
		restartPeriod    = 10 * time.Minute // don't restart crashing manager more frequently than that
		interruptTimeout = time.Minute      // give manager that much time to react to SIGINT
	)
	var (
		cmd         *exec.Cmd
		started     time.Time
		interrupted time.Time
		stopped     = make(chan error, 1)
		closing     = mc.closing
		ticker1     = time.NewTicker(restartPeriod)
		ticker2     = time.NewTicker(interruptTimeout)
	)
	defer func() {
		ticker1.Stop()
		ticker2.Stop()
	}()
	for closing != nil || cmd != nil {
		if cmd == nil {
			// The command is not running.
			// Don't restart too frequently (in case it instantly exits with an error).
			if time.Since(started) > restartPeriod {
				started = time.Now()
				osutil.Rename(mc.log, mc.log+".old")
				logfile, err := os.Create(mc.log)
				if err != nil {
					mc.errorf("failed to create manager log: %v", err)
				} else {
					cmd = osutil.Command(mc.bin, mc.args...)
					cmd.Stdout = logfile
					cmd.Stderr = logfile
					err := cmd.Start()
					logfile.Close()
					if err != nil {
						mc.errorf("failed to start manager: %v", err)
						cmd = nil
					} else {
						log.Logf(1, "%v: started manager", mc.name)
						go func() {
							stopped <- cmd.Wait()
						}()
					}
				}
			}
		} else {
			// The command is running. Check if we need to kill it.
			if closing == nil && time.Since(interrupted) > interruptTimeout {
				log.Logf(1, "%v: killing manager", mc.name)
				cmd.Process.Kill()
				interrupted = time.Now()
			}
		}

		select {
		case <-closing:
			closing = nil
			if cmd != nil {
				log.Logf(1, "%v: stopping manager", mc.name)
				cmd.Process.Signal(syscall.SIGINT)
				interrupted = time.Now()
			}
		case err := <-stopped:
			if cmd == nil {
				mc.errorf("spurious stop signal: %v", err)
			}
			if closing != nil {
				mc.errorf("manager exited unexpectedly: %v", err)
			}
			cmd = nil
			log.Logf(1, "%v: manager exited with %v", mc.name, err)
		case <-ticker1.C:
		case <-ticker2.C:
		}
	}
	close(mc.closing)
}
