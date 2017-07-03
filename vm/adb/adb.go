// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build !ppc64le

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

	"github.com/google/syzkaller/pkg/config"
	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/vm/vmimpl"
)

func init() {
	vmimpl.Register("adb", ctor)
}

type Config struct {
	Adb     string   // adb binary name ("adb" by default)
	Devices []string // list of adb device IDs to use

	// Ensure that a device battery level is at 20+% before fuzzing.
	// Sometimes we observe that a device can't charge during heavy fuzzing
	// and eventually powers down (which then requires manual intervention).
	// This option is enabled by default. Turn it off if your devices
	// don't have battery service, or it causes problems otherwise.
	Battery_Check bool
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
}

type instance struct {
	adbBin  string
	device  string
	console string
	closed  chan bool
	debug   bool
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{
		Adb:           "adb",
		Battery_Check: true,
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse adb vm config: %v", err)
	}
	if _, err := exec.LookPath(cfg.Adb); err != nil {
		return nil, err
	}
	if len(cfg.Devices) == 0 {
		return nil, fmt.Errorf("no adb devices specified")
	}
	devRe := regexp.MustCompile("[0-9A-F]+")
	for _, dev := range cfg.Devices {
		if !devRe.MatchString(dev) {
			return nil, fmt.Errorf("invalid adb device id '%v'", dev)
		}
	}
	if env.Debug {
		cfg.Devices = cfg.Devices[:1]
	}
	pool := &Pool{
		cfg: cfg,
		env: env,
	}
	return pool, nil
}

func (pool *Pool) Count() int {
	return len(pool.cfg.Devices)
}

func (pool *Pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	inst := &instance{
		adbBin: pool.cfg.Adb,
		device: pool.cfg.Devices[index],
		closed: make(chan bool),
		debug:  pool.env.Debug,
	}
	closeInst := inst
	defer func() {
		if closeInst != nil {
			closeInst.Close()
		}
	}()
	if err := inst.repair(); err != nil {
		return nil, err
	}
	inst.console = findConsole(inst.adbBin, inst.device)
	if pool.cfg.Battery_Check {
		if err := inst.checkBatteryLevel(); err != nil {
			return nil, err
		}
	}
	// Remove temp files from previous runs.
	if _, err := inst.adb("shell", "rm -Rf /data/syzkaller*"); err != nil {
		return nil, err
	}
	closeInst = nil
	return inst, nil
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
func findConsole(adb, dev string) string {
	consoleCacheMu.Lock()
	defer consoleCacheMu.Unlock()
	if con := devToConsole[dev]; con != "" {
		return con
	}
	con, err := findConsoleImpl(adb, dev)
	if err != nil {
		Logf(0, "failed to associate adb device %v with console: %v", dev, err)
		Logf(0, "falling back to 'adb shell dmesg -w'")
		Logf(0, "note: some bugs may be detected as 'lost connection to test machine' with no kernel output")
		con = "adb"
		devToConsole[dev] = con
		return con
	}
	devToConsole[dev] = con
	consoleToDev[con] = dev
	Logf(0, "associating adb device %v with console %v", dev, con)
	return con
}

func findConsoleImpl(adb, dev string) (string, error) {
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
			tty, err := vmimpl.OpenConsole(con)
			if err != nil {
				errors <- err
				return
			}
			defer tty.Close()
			go func() {
				<-done
				tty.Close()
			}()
			*out, _ = ioutil.ReadAll(tty)
			errors <- nil
		}(con)
	}
	if len(output) == 0 {
		return "", fmt.Errorf("no unassociated console devices left")
	}
	time.Sleep(500 * time.Millisecond)
	unique := fmt.Sprintf(">>>%v<<<", dev)
	cmd := exec.Command(adb, "-s", dev, "shell", "echo", "\"", unique, "\"", ">", "/dev/kmsg")
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
	if inst.debug {
		Logf(0, "executing adb %+v", args)
	}
	rpipe, wpipe, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe: %v", err)
	}
	defer wpipe.Close()
	defer rpipe.Close()
	cmd := exec.Command(inst.adbBin, append([]string{"-s", inst.device}, args...)...)
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
			if inst.debug {
				Logf(0, "adb hanged")
			}
			cmd.Process.Kill()
		case <-done:
		}
	}()
	if err := cmd.Wait(); err != nil {
		close(done)
		out, _ := ioutil.ReadAll(rpipe)
		if inst.debug {
			Logf(0, "adb failed: %v\n%s", err, out)
		}
		return nil, fmt.Errorf("adb %+v failed: %v\n%s", args, err, out)
	}
	close(done)
	if inst.debug {
		Logf(0, "adb returned")
	}
	out, _ := ioutil.ReadAll(rpipe)
	return out, nil
}

func (inst *instance) repair() error {
	// Assume that the device is in a bad state initially and reboot it.
	// Ignore errors, maybe we will manage to reboot it anyway.
	inst.waitForSsh()
	// History: adb reboot episodically hangs, so we used a more reliable way:
	// using syz-executor to issue reboot syscall. However, this has stopped
	// working, probably due to the introduction of seccomp. Therefore,
	// we revert this to `adb shell reboot` in the meantime, until a more
	// reliable solution can be sought out.
	if _, err := inst.adb("shell", "reboot"); err != nil {
		return err
	}
	// Now give it another 5 minutes to boot.
	if !vmimpl.SleepInterruptible(10 * time.Second) {
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
		if !vmimpl.SleepInterruptible(time.Second) {
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
	val, err := inst.getBatteryLevel(30)
	if err != nil {
		return err
	}
	if val >= minLevel {
		Logf(0, "device %v: battery level %v%%, OK", inst.device, val)
		return nil
	}
	for {
		Logf(0, "device %v: battery level %v%%, waiting for %v%%", inst.device, val, requiredLevel)
		if !vmimpl.SleepInterruptible(time.Minute) {
			return nil
		}
		val, err = inst.getBatteryLevel(0)
		if err != nil {
			return err
		}
		if val >= requiredLevel {
			break
		}
	}
	return nil
}

func (inst *instance) getBatteryLevel(numRetry int) (int, error) {
	out, err := inst.adb("shell", "dumpsys battery | grep level:")

	// allow for retrying for devices that does not boot up so fast
	for ; numRetry >= 0 && err != nil; numRetry-- {
		if numRetry > 0 {
			// sleep for 5 seconds before retrying
			time.Sleep(5 * time.Second)
			out, err = inst.adb("shell", "dumpsys battery | grep level:")
		} else {
			if err != nil {
				return 0, err
			}
		}
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
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := filepath.Join("/data", filepath.Base(hostSrc))
	if _, err := inst.adb("push", hostSrc, vmDst); err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (<-chan []byte, <-chan error, error) {
	var tty io.ReadCloser
	var err error
	if inst.console == "adb" {
		tty, err = vmimpl.OpenAdbConsole(inst.adbBin, inst.device)
	} else {
		tty, err = vmimpl.OpenConsole(inst.console)
	}
	if err != nil {
		return nil, nil, err
	}

	adbRpipe, adbWpipe, err := osutil.LongPipe()
	if err != nil {
		tty.Close()
		return nil, nil, err
	}
	if inst.debug {
		Logf(0, "starting: adb shell %v", command)
	}
	adb := exec.Command(inst.adbBin, "-s", inst.device, "shell", "cd /data; "+command)
	adb.Stdout = adbWpipe
	adb.Stderr = adbWpipe
	if err := adb.Start(); err != nil {
		tty.Close()
		adbRpipe.Close()
		adbWpipe.Close()
		return nil, nil, fmt.Errorf("failed to start adb: %v", err)
	}
	adbWpipe.Close()

	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	merger := vmimpl.NewOutputMerger(tee)
	merger.Add("console", tty)
	merger.Add("adb", adbRpipe)

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
			signal(vmimpl.TimeoutErr)
		case <-stop:
			signal(vmimpl.TimeoutErr)
		case <-inst.closed:
			if inst.debug {
				Logf(0, "instance closed")
			}
			signal(fmt.Errorf("instance closed"))
		case err := <-merger.Err:
			adb.Process.Kill()
			tty.Close()
			merger.Wait()
			if cmdErr := adb.Wait(); cmdErr == nil {
				// If the command exited successfully, we got EOF error from merger.
				// But in this case no error has happened and the EOF is expected.
				err = nil
			}
			signal(err)
			return
		}
		adb.Process.Kill()
		tty.Close()
		merger.Wait()
		adb.Wait()
	}()
	return merger.Output, errc, nil
}
