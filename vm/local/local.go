// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package local

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/fileutil"
	"github.com/google/syzkaller/vm"
)

func init() {
	vm.Register("local", ctor)
}

type instance struct {
	cfg    *vm.Config
	closed chan bool
	files  map[string]string
}

func ctor(cfg *vm.Config) (vm.Instance, error) {
	inst := &instance{
		cfg:    cfg,
		closed: make(chan bool),
		files:  make(map[string]string),
	}
	return inst, nil
}

func (inst *instance) HostAddr() string {
	return "127.0.0.1"
}

func (inst *instance) Close() {
	close(inst.closed)
	os.RemoveAll(inst.cfg.Workdir)
}

func (inst *instance) Copy(hostSrc, vmDst string) error {
	dst := filepath.Join(inst.cfg.Workdir, vmDst)
	inst.files[vmDst] = dst
	if err := fileutil.CopyFile(hostSrc, dst, false); err != nil {
		return err
	}
	return os.Chmod(dst, 0777)
}

func (inst *instance) Run(timeout time.Duration, command string) (<-chan []byte, <-chan error, error) {
	for strings.Index(command, "  ") != -1 {
		command = strings.Replace(command, "  ", " ", -1)
	}
	args := strings.Split(command, " ")
	for i, arg := range args {
		if inst.files[arg] != "" {
			args[i] = inst.files[arg]
		}
	}
	cmd := exec.Command(args[0], args[1:]...)
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	outputC := make(chan []byte, 10)
	errorC := make(chan error, 2)
	done := make(chan bool)
	go func() {
		errorC <- cmd.Wait()
		close(done)
	}()
	go func() {
		ticker := time.NewTicker(time.Second)
		timeout := time.NewTicker(timeout)
		for {
			select {
			case <-ticker.C:
				select {
				case outputC <- []byte{'.'}:
				default:
				}
			case <-timeout.C:
				errorC <- vm.TimeoutErr
				cmd.Process.Kill()
				ticker.Stop()
				return
			case <-done:
				ticker.Stop()
				timeout.Stop()
				return
			case <-inst.closed:
				errorC <- fmt.Errorf("closed")
				cmd.Process.Kill()
				ticker.Stop()
				timeout.Stop()
				return
			}
		}
	}()
	return outputC, errorC, nil
}
