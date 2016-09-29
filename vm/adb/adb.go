// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package adb

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"time"

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
	if err := inst.findConsole(); err != nil {
		return nil, err
	}
	if err := inst.repair(); err != nil {
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
	consoleCache   = make(map[string]string)
)

func (inst *instance) findConsole() error {
	// Case Closed Debugging using Suzy-Q:
	// https://chromium.googlesource.com/chromiumos/platform/ec/+/master/docs/case_closed_debugging.md
	consoleCacheMu.Lock()
	defer consoleCacheMu.Unlock()
	if inst.console = consoleCache[inst.cfg.Device]; inst.console != "" {
		return nil
	}
	out, err := exec.Command(inst.cfg.Bin, "devices", "-l").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to execute 'adb devices -l': %v\n%v\n", err, string(out))
	}
	// The regexp matches devices strings of the form usb:a-b.c.d....x, and
	// then treats everything but the final .x as the bus/port combo to look
	// for the ttyUSB number
	re := regexp.MustCompile(fmt.Sprintf("%v +device usb:([0-9]+-[0-9]+.*)(\\.[0-9]+) product.*\n", inst.cfg.Device))
	match := re.FindAllStringSubmatch(string(out), 1)
	if match == nil {
		return fmt.Errorf("can't find adb device '%v' in 'adb devices' output:\n%v\n", inst.cfg.Device, string(out))
	}
	busAndPort := match[0][1]
	files, err := filepath.Glob(fmt.Sprintf("/sys/bus/usb/devices/%v.2:1.1/ttyUSB*", busAndPort))
	if err != nil || len(files) == 0 {
		return fmt.Errorf("can't find any ttyUSB devices for adb device '%v' on bus/port %v", inst.cfg.Device, busAndPort)
	}
	inst.console = "/dev/" + filepath.Base(files[0])
	consoleCache[inst.cfg.Device] = inst.console
	log.Printf("associating adb device %v with console %v", inst.cfg.Device, inst.console)
	return nil
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
		log.Printf("executing adb %+v", args)
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
				log.Printf("adb hanged")
			}
			cmd.Process.Kill()
		case <-done:
		}
	}()
	if err := cmd.Wait(); err != nil {
		close(done)
		out, _ := ioutil.ReadAll(rpipe)
		if inst.cfg.Debug {
			log.Printf("adb failed: %v\n%s", err, out)
		}
		return nil, fmt.Errorf("adb %+v failed: %v\n%s", args, err, out)
	}
	close(done)
	if inst.cfg.Debug {
		log.Printf("adb returned")
	}
	out, _ := ioutil.ReadAll(rpipe)
	return out, nil
}

func (inst *instance) repair() error {
	// Give the device up to 5 minutes to come up (it can be rebooting after a previous crash).
	if !vm.SleepInterruptible(3 * time.Second) {
		return fmt.Errorf("shutdown in progress")
	}
	for i := 0; i < 300; i++ {
		if !vm.SleepInterruptible(time.Second) {
			return fmt.Errorf("shutdown in progress")
		}
		if _, err := inst.adb("shell", "pwd"); err == nil {
			return nil
		}
	}
	// If it does not help, reboot.
	// adb reboot episodically hangs, so we use a more reliable way.
	// Ignore errors because all other adb commands hang as well
	// and the binary can already be on the device.
	inst.adb("push", inst.cfg.Executor, "/data/syz-executor")
	if _, err := inst.adb("shell", "/data/syz-executor", "reboot"); err != nil {
		return err
	}
	// Now give it another 5 minutes.
	if !vm.SleepInterruptible(10 * time.Second) {
		return fmt.Errorf("shutdown in progress")
	}
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
		log.Printf("device %v: battery level %v%%, OK", inst.cfg.Device, val)
		return nil
	}
	for {
		log.Printf("device %v: battery level %v%%, waiting for %v%%", inst.cfg.Device, val, requiredLevel)
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
			log.Printf("cat exited: %v", err)
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
		log.Printf("starting: adb shell %v", command)
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
			log.Printf("adb exited: %v", err)
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
				log.Printf("instance closed")
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
