// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package adb

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/vm"
)

func init() {
	vm.Register("adb", ctor)
}

type instance struct {
	cfg     *vm.Config
	console string
	closed  chan bool
}

func ctor(cfg *vm.Config) (vm.Instance, error) {
	inst := &instance{
		cfg:    cfg,
		closed: make(chan bool),
	}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	if err := inst.repair(); err != nil {
		return nil, err
	}
	var err error
	if inst.console, err = findConsole(inst.cfg.Device); err != nil {
		return nil, err
	}
	if err := inst.checkBatteryLevel(); err != nil {
		return nil, err
	}
	// Remove temp files from previous runs.
	inst.adb("shell", "rm -Rf /data/syzkaller*")
	closeInst = nil
	return inst, nil
}

func validateConfig(cfg *vm.Config) error {
	if cfg.Bin == "" {
		cfg.Bin = "adb"
	}
	if !regexp.MustCompile("[0-9A-F]+").MatchString(cfg.Device) {
		return fmt.Errorf("invalid adb device id '%v'", cfg.Device)
	}
	return nil
}

var (
	consoleCacheMu sync.Mutex
	consoleToDev   = make(map[string]string)
	devToConsole   = make(map[string]string)
)

// findConsole returns console file associated with the dev device (e.g. /dev/ttyUSB0).
// This code was tested with Suzy-Q and Android Serial Cable (ASC). For Suzy-Q see:
// https://chromium.googlesource.com/chromiumos/platform/ec/+/master/docs/case_closed_debugging.md
// The difference between Suzy-Q and ASC is that ASC is a separate cable,
// so it is not possible to match USB bus/port used by adb with the serial console device;
// while Suzy-Q console uses the same USB calbe as adb.
// The overall idea is as follows. We use 'adb shell' to write a unique string onto console,
// then we read from all console devices and see on what console the unique string appears.
func findConsole(dev string) (string, error) {
	consoleCacheMu.Lock()
	defer consoleCacheMu.Unlock()
	if con := devToConsole[dev]; con != "" {
		return con, nil
	}
	consoles, err := filepath.Glob("/dev/ttyUSB*")
	if err != nil {
		return "", fmt.Errorf("failed to list /dev/ttyUSB devices: %v", err)
	}
	output := make(map[string]*[]byte)
	errors := make(chan error, len(consoles))
	done := make(chan bool)
	for _, con := range consoles {
		if consoleToDev[con] != "" {
			continue
		}
		out := new([]byte)
		output[con] = out
		go func(con string) {
			cmd := exec.Command("cat", con)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				errors <- err
			}
			if cmd.Start() != nil {
				errors <- err
			}
			go func() {
				<-done
				cmd.Process.Kill()
			}()
			*out, _ = ioutil.ReadAll(stdout)
			cmd.Wait()
			errors <- nil
		}(con)
	}
	if len(output) == 0 {
		return "", fmt.Errorf("no unassociated console devices left")
	}
	time.Sleep(500 * time.Millisecond)
	unique := fmt.Sprintf(">>>%v<<<", dev)
	cmd := exec.Command("adb", "-s", dev, "shell", "echo", "\"", unique, "\"", ">", "/dev/kmsg")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("failed to run adb shell: %v\n%s", err, out)
	}
	time.Sleep(500 * time.Millisecond)
	close(done)

	var anyErr error
	for range output {
		err := <-errors
		if anyErr == nil && err != nil {
			anyErr = err
		}
	}

	con := ""
	for con1, out := range output {
		if bytes.Contains(*out, []byte(unique)) {
			if con == "" {
				con = con1
			} else {
				anyErr = fmt.Errorf("device is associated with several consoles: %v and %v", con, con1)
			}
		}
	}

	if con == "" {
		if anyErr != nil {
			return "", anyErr
		}
		return "", fmt.Errorf("no console is associated with this device")
	}
	devToConsole[dev] = con
	consoleToDev[con] = dev
	Logf(0, "associating adb device %v with console %v", dev, con)
	return con, nil
}

func (inst *instance) Forward(port int) (string, error) {
	// If 35099 turns out to be busy, try to forward random ports several times.
	devicePort := 35099
	if _, err := inst.adb("reverse", fmt.Sprintf("tcp:%v", devicePort), fmt.Sprintf("tcp:%v", port)); err != nil {
		return "", err
	}
	return fmt.Sprintf("127.0.0.1:%v", devicePort), nil
}

func (inst *instance) adb(args ...string) ([]byte, error) {
	if inst.cfg.Debug {
		Logf(0, "executing adb %+v", args)
	}
	rpipe, wpipe, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	defer wpipe.Close()
	defer rpipe.Close()
	cmd := exec.Command(inst.cfg.Bin, append([]string{"-s", inst.cfg.Device}, args...)...)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	wpipe.Close()
	done := make(chan bool)
	go func() {
		select {
		case <-time.After(time.Minute):
			if inst.cfg.Debug {
				Logf(0, "adb hanged")
			}
			cmd.Process.Kill()
		case <-done:
		}
	}()
	if err := cmd.Wait(); err != nil {
		close(done)
		out, _ := ioutil.ReadAll(rpipe)
		if inst.cfg.Debug {
			Logf(0, "adb failed: %v\n%s", err, out)
		}
		return nil, fmt.Errorf("adb %+v failed: %v\n%s", args, err, out)
	}
	close(done)
	if inst.cfg.Debug {
		Logf(0, "adb returned")
	}
	out, _ := ioutil.ReadAll(rpipe)
	return out, nil
}

func (inst *instance) repair() error {
	// Assume that the device is in a bad state initially and reboot it.
	// Ignore errors, maybe we will manage to reboot it anyway.
	inst.waitForSsh()
	// adb reboot episodically hangs, so we use a more reliable way.
	// Ignore errors because all other adb commands hang as well
	// and the binary can already be on the device.
	inst.adb("push", inst.cfg.Executor, "/data/syz-executor")
	if _, err := inst.adb("shell", "/data/syz-executor", "reboot"); err != nil {
		return err
	}
	// Now give it another 5 minutes to boot.
	if !vm.SleepInterruptible(10 * time.Second) {
		return fmt.Errorf("shutdown in progress")
	}
	if err := inst.waitForSsh(); err != nil {
		return err
	}
	// Switch to root for userdebug builds.
	inst.adb("root")
	if err := inst.waitForSsh(); err != nil {
		return err
	}
	return nil
}

func (inst *instance) waitForSsh() error {
	var err error
	for i := 0; i < 300; i++ {
		if !vm.SleepInterruptible(time.Second) {
			return fmt.Errorf("shutdown in progress")
		}
		if _, err = inst.adb("shell", "pwd"); err == nil {
			return nil
		}
	}
	return fmt.Errorf("instance is dead and unrepairable: %v", err)
}

func (inst *instance) checkBatteryLevel() error {
	const (
		minLevel      = 20
		requiredLevel = 30
	)
	val, err := inst.getBatteryLevel()
	if err != nil {
		return err
	}
	if val >= minLevel {
		Logf(0, "device %v: battery level %v%%, OK", inst.cfg.Device, val)
		return nil
	}
	for {
		Logf(0, "device %v: battery level %v%%, waiting for %v%%", inst.cfg.Device, val, requiredLevel)
		if !vm.SleepInterruptible(time.Minute) {
			return nil
		}
		val, err = inst.getBatteryLevel()
		if err != nil {
			return err
		}
		if val >= requiredLevel {
			break
		}
	}
	return nil
}

func (inst *instance) getBatteryLevel() (int, error) {
	out, err := inst.adb("shell", "dumpsys battery | grep level:")
	if err != nil {
		return 0, err
	}
	val := 0
	for _, c := range out {
		if c >= '0' && c <= '9' {
			val = val*10 + int(c) - '0'
			continue
		}
		if val != 0 {
			break
		}
	}
	if val == 0 {
		return 0, fmt.Errorf("failed to parse 'dumpsys battery' output: %s", out)
	}
	return val, nil
}

func (inst *instance) Close() {
	close(inst.closed)
	os.RemoveAll(inst.cfg.Workdir)
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := filepath.Join("/data", filepath.Base(hostSrc))
	if _, err := inst.adb("push", hostSrc, vmDst); err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(timeout time.Duration, command string) (<-chan []byte, <-chan error, error) {
	catRpipe, catWpipe, err := vm.LongPipe()
	if err != nil {
		return nil, nil, err
	}

	cat := exec.Command("cat", inst.console)
	cat.Stdout = catWpipe
	cat.Stderr = catWpipe
	if err := cat.Start(); err != nil {
		catRpipe.Close()
		catWpipe.Close()
		return nil, nil, fmt.Errorf("failed to start cat %v: %v", inst.console, err)

	}
	catWpipe.Close()
	catDone := make(chan error, 1)
	go func() {
		err := cat.Wait()
		if inst.cfg.Debug {
			Logf(0, "cat exited: %v", err)
		}
		catDone <- fmt.Errorf("cat exited: %v", err)
	}()

	adbRpipe, adbWpipe, err := vm.LongPipe()
	if err != nil {
		cat.Process.Kill()
		catRpipe.Close()
		return nil, nil, err
	}
	if inst.cfg.Debug {
		Logf(0, "starting: adb shell %v", command)
	}
	adb := exec.Command(inst.cfg.Bin, "-s", inst.cfg.Device, "shell", "cd /data; "+command)
	adb.Stdout = adbWpipe
	adb.Stderr = adbWpipe
	if err := adb.Start(); err != nil {
		cat.Process.Kill()
		catRpipe.Close()
		adbRpipe.Close()
		adbWpipe.Close()
		return nil, nil, fmt.Errorf("failed to start adb: %v", err)
	}
	adbWpipe.Close()
	adbDone := make(chan error, 1)
	go func() {
		err := adb.Wait()
		if inst.cfg.Debug {
			Logf(0, "adb exited: %v", err)
		}
		adbDone <- fmt.Errorf("adb exited: %v", err)
	}()

	var tee io.Writer
	if inst.cfg.Debug {
		tee = os.Stdout
	}
	merger := vm.NewOutputMerger(tee)
	merger.Add(catRpipe)
	merger.Add(adbRpipe)

	errc := make(chan error, 1)
	signal := func(err error) {
		select {
		case errc <- err:
		default:
		}
	}

	go func() {
		select {
		case <-time.After(timeout):
			signal(vm.TimeoutErr)
			cat.Process.Kill()
			adb.Process.Kill()
		case <-inst.closed:
			if inst.cfg.Debug {
				Logf(0, "instance closed")
			}
			signal(fmt.Errorf("instance closed"))
			cat.Process.Kill()
			adb.Process.Kill()
		case err := <-catDone:
			signal(err)
			adb.Process.Kill()
		case err := <-adbDone:
			signal(err)
			cat.Process.Kill()
		}
		merger.Wait()
	}()
	return merger.Output, errc, nil
}
