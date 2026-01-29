// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !ppc64le

package adb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
)

func init() {
	vmimpl.Register("adb", vmimpl.Type{
		Ctor: ctor,
	})
}

type Device struct {
	Serial     string   `json:"serial"`      // device serial to connect
	Console    string   `json:"console"`     // console device name (e.g. "/dev/pts/0")
	ConsoleCmd []string `json:"console_cmd"` // command to obtain device console log
}

type Config struct {
	Adb     string            `json:"adb"`     // adb binary name ("adb" by default)
	Devices []json.RawMessage `json:"devices"` // list of adb devices to use

	// Ensure that a device battery level is at 20+% before fuzzing.
	// Sometimes we observe that a device can't charge during heavy fuzzing
	// and eventually powers down (which then requires manual intervention).
	// This option is enabled by default. Turn it off if your devices
	// don't have battery service, or it causes problems otherwise.
	BatteryCheck bool `json:"battery_check"`
	// If this option is set (default), the device is rebooted after each crash.
	// Set it to false to disable reboots.
	TargetReboot  bool   `json:"target_reboot"`
	RepairScript  string `json:"repair_script"`  // script to execute before each startup
	StartupScript string `json:"startup_script"` // script to execute after each startup
}

type Pool struct {
	env *vmimpl.Env
	cfg *Config
}

type instance struct {
	cfg        *Config
	adbBin     string
	device     string
	console    string
	consoleCmd []string
	closed     chan bool
	debug      bool
	timeouts   targets.Timeouts
}

var (
	androidSerial = "^[0-9A-Za-z]+$"
	ipAddress     = `^(?:localhost|(?:[0-9]{1,3}\.){3}[0-9]{1,3})\:(?:[0-9]{1,5})$` // cuttlefish or remote_device_proxy
	emulatorID    = `^emulator\-\d+$`
)

func loadDevice(data []byte) (*Device, error) {
	devObj := &Device{}
	var devStr string
	err1 := config.LoadData(data, devObj)
	err2 := config.LoadData(data, &devStr)
	if err1 != nil && err2 != nil {
		return nil, fmt.Errorf("failed to parse adb vm config: %w %w", err1, err2)
	}
	if err2 == nil {
		devObj.Serial = devStr
	}
	return devObj, nil
}

func ctor(env *vmimpl.Env) (vmimpl.Pool, error) {
	cfg := &Config{
		Adb:          "adb",
		BatteryCheck: true,
		TargetReboot: true,
	}
	if err := config.LoadData(env.Config, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse adb vm config: %w", err)
	}
	if _, err := exec.LookPath(cfg.Adb); err != nil {
		return nil, err
	}
	if len(cfg.Devices) == 0 {
		return nil, fmt.Errorf("no adb devices specified")
	}
	// Device should be either regular serial number, a valid Cuttlefish ID, or an Android Emulator ID.
	devRe := regexp.MustCompile(fmt.Sprintf("%s|%s|%s", androidSerial, ipAddress, emulatorID))
	for _, dev := range cfg.Devices {
		device, err := loadDevice(dev)
		if err != nil {
			return nil, err
		}
		if !devRe.MatchString(device.Serial) {
			return nil, fmt.Errorf("invalid adb device id '%v'", device.Serial)
		}
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

func (pool *Pool) Create(_ context.Context, workdir string, index int) (vmimpl.Instance, error) {
	device, err := loadDevice(pool.cfg.Devices[index])
	if err != nil {
		return nil, err
	}
	inst := &instance{
		cfg:        pool.cfg,
		adbBin:     pool.cfg.Adb,
		device:     device.Serial,
		console:    device.Console,
		consoleCmd: device.ConsoleCmd,
		closed:     make(chan bool),
		debug:      pool.env.Debug,
		timeouts:   pool.env.Timeouts,
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
	if len(inst.consoleCmd) > 0 {
		log.Logf(0, "associating adb device %v with console cmd `%v`", inst.device, inst.consoleCmd)
	} else {
		if inst.console == "" {
			// More verbose log level is required, otherwise echo to /dev/kmsg won't show.
			level, err := inst.adb("shell", "cat /proc/sys/kernel/printk")
			if err != nil {
				return nil, fmt.Errorf("failed to read /proc/sys/kernel/printk: %w", err)
			}
			inst.adb("shell", "echo 8 > /proc/sys/kernel/printk")
			inst.console = findConsole(inst.adbBin, inst.device)
			// Verbose kmsg slows down system, so disable it after findConsole.
			inst.adb("shell", fmt.Sprintf("echo %v > /proc/sys/kernel/printk", string(level)))
		}
		log.Logf(0, "associating adb device %v with console %v", inst.device, inst.console)
	}
	if pool.cfg.BatteryCheck {
		if err := inst.checkBatteryLevel(); err != nil {
			return nil, err
		}
	}
	// Remove temp files from previous runs.
	// rm chokes on bad symlinks so we must remove them first
	if _, err := inst.adb("shell", "ls /data/syzkaller*"); err == nil {
		if _, err := inst.adb("shell", "find /data/syzkaller* -type l -exec unlink {} \\;"+
			" && rm -Rf /data/syzkaller*"); err != nil {
			return nil, err
		}
	}
	inst.adb("shell", "echo 0 > /proc/sys/kernel/kptr_restrict")
	closeInst = nil
	return inst, nil
}

var (
	consoleCacheMu sync.Mutex
	consoleToDev   = make(map[string]string)
	devToConsole   = make(map[string]string)
)

func parseAdbOutToInt(out []byte) int {
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
	return val
}

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
		log.Logf(0, "failed to associate adb device %v with console: %v", dev, err)
		log.Logf(0, "falling back to 'adb shell dmesg -w'")
		log.Logf(0, "note: some bugs may be detected as 'lost connection to test machine' with no kernel output")
		con = "adb"
		devToConsole[dev] = con
		return con
	}
	devToConsole[dev] = con
	consoleToDev[con] = dev
	return con
}

func findConsoleImpl(adb, dev string) (string, error) {
	// Attempt to find an exact match, at /dev/ttyUSB.{SERIAL}
	// This is something that can be set up on Linux via 'udev' rules
	exactCon := "/dev/ttyUSB." + dev
	if osutil.IsExist(exactCon) {
		return exactCon, nil
	}

	// Search all consoles, as described in 'findConsole'
	consoles, err := filepath.Glob("/dev/ttyUSB*")
	if err != nil {
		return "", fmt.Errorf("failed to list /dev/ttyUSB devices: %w", err)
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
			*out, _ = io.ReadAll(tty)
			errors <- nil
		}(con)
	}
	if len(output) == 0 {
		return "", fmt.Errorf("no unassociated console devices left")
	}
	time.Sleep(500 * time.Millisecond)
	unique := fmt.Sprintf(">>>%v<<<", dev)
	cmd := osutil.Command(adb, "-s", dev, "shell", "echo", "\"<1>", unique, "\"", ">", "/dev/kmsg")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("failed to run adb shell: %w\n%s", err, out)
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
	var err error
	for i := 0; i < 1000; i++ {
		devicePort := vmimpl.RandomPort()
		_, err = inst.adb("reverse", fmt.Sprintf("tcp:%v", devicePort), fmt.Sprintf("tcp:%v", port))
		if err == nil {
			return fmt.Sprintf("127.0.0.1:%v", devicePort), nil
		}
	}
	return "", err
}

func (inst *instance) adb(args ...string) ([]byte, error) {
	return inst.adbWithTimeout(time.Minute, args...)
}

func (inst *instance) adbWithTimeout(timeout time.Duration, args ...string) ([]byte, error) {
	if inst.debug {
		log.Logf(0, "executing adb %+v", args)
	}
	args = append([]string{"-s", inst.device}, args...)
	out, err := osutil.RunCmd(timeout, "", inst.adbBin, args...)
	if inst.debug {
		log.Logf(0, "adb returned")
	}
	return out, err
}

func (inst *instance) waitForBootCompletion() {
	// ADB connects to a phone and starts syz-executor while the phone is still booting.
	// This enables syzkaller to create a race condition which in certain cases doesn't
	// allow the phone to finalize initialization.
	// To determine whether a system has booted and started all system processes and
	// services we wait for a process named 'com.android.systemui' to start. It's possible
	// that in the future a new devices which doesn't have 'systemui' process will be fuzzed
	// with adb, in this case this code should be modified with a new process name to search for.
	log.Logf(2, "waiting for boot completion")

	sleepTime := 5
	sleepDuration := time.Duration(sleepTime) * time.Second
	maxWaitTime := 60 * 3 // 3 minutes to wait until boot completion
	maxRetries := maxWaitTime / sleepTime
	i := 0
	for ; i < maxRetries; i++ {
		time.Sleep(sleepDuration)

		if out, err := inst.adb("shell", "pgrep systemui | wc -l"); err == nil {
			count := parseAdbOutToInt(out)
			if count != 0 {
				log.Logf(0, "boot completed")
				break
			}
		} else {
			log.Logf(0, "failed to execute command 'pgrep systemui | wc -l', %v", err)
			break
		}
	}
	if i == maxRetries {
		log.Logf(0, "failed to determine boot completion, can't find 'com.android.systemui' process")
	}
}

func (inst *instance) repair() error {
	// Assume that the device is in a bad state initially and reboot it.
	// Ignore errors, maybe we will manage to reboot it anyway.
	if inst.cfg.RepairScript != "" {
		if err := inst.runScript(inst.cfg.RepairScript); err != nil {
			return err
		}
	}
	inst.waitForSSH()
	// History: adb reboot episodically hangs, so we used a more reliable way:
	// using syz-executor to issue reboot syscall. However, this has stopped
	// working, probably due to the introduction of seccomp. Therefore,
	// we revert this to `adb shell reboot` in the meantime, until a more
	// reliable solution can be sought out.
	if inst.cfg.TargetReboot {
		if _, err := inst.adb("shell", "reboot"); err != nil {
			var verboseErr *osutil.VerboseError
			if !errors.As(err, &verboseErr) {
				return err
			}

			if verboseErr.ExitCode != 0 && verboseErr.ExitCode != 255 {
				return err
			}
		}

		// Now give it another 5 minutes to boot.
		if !vmimpl.SleepInterruptible(10 * time.Second) {
			return fmt.Errorf("shutdown in progress")
		}
		if err := inst.waitForSSH(); err != nil {
			return err
		}
	}
	// Switch to root for userdebug builds.
	inst.adb("root")
	inst.waitForSSH()
	inst.waitForBootCompletion()

	// Mount debugfs.
	if _, err := inst.adb("shell", "ls /sys/kernel/debug"); err != nil {
		log.Logf(2, "debugfs was unmounted mounting")
		// This prop only exist on Android 12+
		inst.adb("shell", "setprop persist.dbg.keep_debugfs_mounted 1")
		if _, err := inst.adb("shell", "mount -t debugfs debugfs /sys/kernel/debug "+
			"&& chmod 0755 /sys/kernel/debug"); err != nil {
			return err
		}
	}
	if inst.cfg.StartupScript != "" {
		if err := inst.runScript(inst.cfg.StartupScript); err != nil {
			return err
		}
	}
	return nil
}

func (inst *instance) runScript(script string) error {
	log.Logf(2, "adb: executing %s", script)
	output, err := osutil.RunCmd(5*time.Minute, "", "sh", script, inst.device, inst.console)
	if err != nil {
		return fmt.Errorf("failed to execute %s: %w", script, err)
	}
	log.Logf(2, "adb: execute %s output\n%s", script, output)
	log.Logf(2, "adb: done executing %s", script)
	return nil
}

func (inst *instance) waitForSSH() error {
	if !vmimpl.SleepInterruptible(time.Second) {
		return fmt.Errorf("shutdown in progress")
	}

	if _, err := inst.adbWithTimeout(10*time.Minute, "wait-for-device"); err != nil {
		return fmt.Errorf("instance is dead and unrepairable: %w", err)
	}

	return nil
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
		log.Logf(0, "device %v: battery level %v%%, OK", inst.device, val)
		return nil
	}
	for {
		log.Logf(0, "device %v: battery level %v%%, waiting for %v%%", inst.device, val, requiredLevel)
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

	// Allow for retrying for devices that does not boot up so fast.
	for ; numRetry >= 0 && err != nil; numRetry-- {
		if numRetry > 0 {
			// Sleep for 5 seconds before retrying.
			time.Sleep(5 * time.Second)
			out, err = inst.adb("shell", "dumpsys battery | grep level:")
		}
	}
	if err != nil {
		return 0, err
	}
	val := parseAdbOutToInt(out)
	if val == 0 {
		return 0, fmt.Errorf("failed to parse 'dumpsys battery' output: %s", out)
	}
	return val, nil
}

func (inst *instance) Close() error {
	close(inst.closed)
	return nil
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	vmDst := filepath.Join("/data", filepath.Base(hostSrc))
	if _, err := inst.adb("push", hostSrc, vmDst); err != nil {
		return "", err
	}
	inst.adb("shell", "chmod", "+x", vmDst)
	return vmDst, nil
}

// Check if the device is cuttlefish on remote vm.
func isRemoteCuttlefish(dev string) (bool, string) {
	if !strings.Contains(dev, ":") {
		return false, ""
	}
	ip := strings.Split(dev, ":")[0]
	if ip == "localhost" || ip == "0.0.0.0" || ip == "127.0.0.1" {
		return false, ip
	}
	return true, ip
}

func (inst *instance) Run(ctx context.Context, command string) (
	<-chan vmimpl.Chunk, <-chan error, error) {
	var tty io.ReadCloser
	var err error

	if len(inst.consoleCmd) > 0 {
		tty, err = vmimpl.OpenConsoleByCmd(inst.consoleCmd[0], inst.consoleCmd[1:])
	} else if ok, ip := isRemoteCuttlefish(inst.device); ok {
		tty, err = vmimpl.OpenRemoteKernelLog(ip, inst.console)
	} else if inst.console == "adb" {
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
	adbRpipeErr, adbWpipeErr, err := osutil.LongPipe()
	if err != nil {
		tty.Close()
		adbRpipe.Close()
		adbWpipe.Close()
		return nil, nil, err
	}
	if inst.debug {
		log.Logf(0, "starting: adb shell %v", command)
	}
	adb := osutil.Command(inst.adbBin, "-s", inst.device, "shell", "cd /data; "+command)
	adb.Stdout = adbWpipe
	adb.Stderr = adbWpipeErr
	if err := adb.Start(); err != nil {
		tty.Close()
		adbRpipe.Close()
		adbWpipe.Close()
		adbRpipeErr.Close()
		adbWpipeErr.Close()
		return nil, nil, fmt.Errorf("failed to start adb: %w", err)
	}
	adbWpipe.Close()
	adbWpipeErr.Close()

	var tee io.Writer
	if inst.debug {
		tee = os.Stdout
	}
	merger := vmimpl.NewOutputMerger(tee)
	merger.Add("console", vmimpl.OutputConsole, tty)
	merger.Add("adb", vmimpl.OutputStdout, adbRpipe)
	merger.Add("adb-err", vmimpl.OutputStderr, adbRpipeErr)

	return vmimpl.Multiplex(ctx, adb, merger, vmimpl.MultiplexConfig{
		Console: tty,
		Close:   inst.closed,
		Debug:   inst.debug,
		Scale:   inst.timeouts.Scale,
	})
}

func (inst *instance) Diagnose(rep *report.Report) ([]byte, bool) {
	return nil, false
}
