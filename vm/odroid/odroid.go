// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build odroid

package odroid

// #cgo pkg-config: libusb-1.0
// #include <linux/usb/ch9.h>
// #include <linux/usb/ch11.h>
// #include <libusb.h>
import "C"

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"time"
	"unsafe"

	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/vm"
)

func init() {
	vm.Register("odroid", ctor)
}

type instance struct {
	cfg    *vm.Config
	closed chan bool
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

	// Create working dir if doesn't exist.
	inst.ssh("mkdir -p /data/")

	// Remove temp files from previous runs.
	inst.ssh("rm -rf /data/syzkaller-*")

	closeInst = nil
	return inst, nil
}

func validateConfig(cfg *vm.Config) error {
	if _, err := os.Stat(cfg.Sshkey); err != nil {
		return fmt.Errorf("ssh key '%v' does not exist: %v", cfg.Sshkey, err)
	}
	if _, err := os.Stat(cfg.OdroidConsole); err != nil {
		return fmt.Errorf("console file '%v' does not exist: %v", cfg.OdroidConsole, err)
	}
	return nil
}

func (inst *instance) Forward(port int) (string, error) {
	return fmt.Sprintf(inst.cfg.OdroidHostAddr+":%v", port), nil
}

func (inst *instance) ssh(command string) ([]byte, error) {
	if inst.cfg.Debug {
		Logf(0, "executing ssh %+v", command)
	}

	rpipe, wpipe, err := vm.LongPipe()
	if err != nil {
		return nil, err
	}

	args := append(inst.sshArgs("-p"), "root@"+inst.cfg.OdroidSlaveAddr, command)
	if inst.cfg.Debug {
		Logf(0, "running command: ssh %#v", args)
	}
	cmd := exec.Command("ssh", args...)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		wpipe.Close()
		return nil, err
	}
	wpipe.Close()

	done := make(chan bool)
	go func() {
		select {
		case <-time.After(time.Minute):
			if inst.cfg.Debug {
				Logf(0, "ssh hanged")
			}
			cmd.Process.Kill()
		case <-done:
		}
	}()
	if err := cmd.Wait(); err != nil {
		close(done)
		out, _ := ioutil.ReadAll(rpipe)
		if inst.cfg.Debug {
			Logf(0, "ssh failed: %v\n%s", err, out)
		}
		return nil, fmt.Errorf("ssh %+v failed: %v\n%s", args, err, out)
	}
	close(done)
	if inst.cfg.Debug {
		Logf(0, "ssh returned")
	}
	out, _ := ioutil.ReadAll(rpipe)
	return out, nil
}

func switchPortPower(busNum, deviceNum, portNum int, power bool) error {
	var context *C.libusb_context
	if err := C.libusb_init(&context); err != 0 {
		return fmt.Errorf("failed to init libusb: %v\n", err)
	}
	defer C.libusb_exit(context)

	var rawList **C.libusb_device
	numDevices := int(C.libusb_get_device_list(context, &rawList))
	if numDevices < 0 {
		return fmt.Errorf("failed to init libusb: %v", numDevices)
	}
	defer C.libusb_free_device_list(rawList, 1)

	var deviceList []*C.libusb_device
	*(*reflect.SliceHeader)(unsafe.Pointer(&deviceList)) = reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(rawList)),
		Len:  numDevices,
		Cap:  numDevices,
	}

	var hub *C.libusb_device
	for i := 0; i < numDevices; i++ {
		var desc C.struct_libusb_device_descriptor
		if err := C.libusb_get_device_descriptor(deviceList[i], &desc); err != 0 {
			return fmt.Errorf("failed to get device descriptor: %v", err)
		}
		if desc.bDeviceClass != C.USB_CLASS_HUB {
			continue
		}
		if C.libusb_get_bus_number(deviceList[i]) != C.uint8_t(busNum) {
			continue
		}
		if C.libusb_get_device_address(deviceList[i]) != C.uint8_t(deviceNum) {
			continue
		}
		hub = deviceList[i]
		break
	}

	if hub == nil {
		return fmt.Errorf("hub not found: bus: %v, device: %v", busNum, deviceNum)
	}

	var handle *C.libusb_device_handle
	if err := C.libusb_open(hub, &handle); err != 0 {
		return fmt.Errorf("failed to open usb device: %v", err)
	}

	request := C.uint8_t(C.USB_REQ_CLEAR_FEATURE)
	if power {
		request = C.uint8_t(C.USB_REQ_SET_FEATURE)
	}
	port := C.uint16_t(portNum)
	timeout := C.uint(1000)
	if err := C.libusb_control_transfer(handle, C.USB_RT_PORT, request,
		C.USB_PORT_FEAT_POWER, port, nil, 0, timeout); err < 0 {
		return fmt.Errorf("failed to send control message: %v\n", err)
	}

	return nil
}

func (inst *instance) repair() error {
	// Try to shutdown gracefully.
	Logf(1, "odroid: trying to ssh")
	if err := inst.waitForSsh(10); err == nil {
		Logf(1, "odroid: ssh succeeded, shutting down now")
		inst.ssh("shutdown now")
		if !vm.SleepInterruptible(20 * time.Second) {
			return fmt.Errorf("shutdown in progress")
		}
	} else {
		Logf(1, "odroid: ssh failed")
	}

	// Hard reset by turning off and back on power on a hub port.
	Logf(1, "odroid: hard reset, turning off power")
	if err := switchPortPower(inst.cfg.OdroidHubBus, inst.cfg.OdroidHubDevice, inst.cfg.OdroidHubPort, false); err != nil {
		return err
	}
	if !vm.SleepInterruptible(5 * time.Second) {
		return fmt.Errorf("shutdown in progress")
	}
	if err := switchPortPower(inst.cfg.OdroidHubBus, inst.cfg.OdroidHubDevice, inst.cfg.OdroidHubPort, true); err != nil {
		return err
	}

	// Now wait for boot.
	Logf(1, "odroid: power back on, waiting for boot")
	if err := inst.waitForSsh(150); err != nil {
		return err
	}

	Logf(1, "odroid: boot succeeded")
	return nil
}

func (inst *instance) waitForSsh(timeout int) error {
	var err error
	start := time.Now()
	for {
		if !vm.SleepInterruptible(time.Second) {
			return fmt.Errorf("shutdown in progress")
		}
		if _, err = inst.ssh("pwd"); err == nil {
			return nil
		}
		if time.Since(start).Seconds() > float64(timeout) {
			break
		}
	}
	return fmt.Errorf("instance is dead and unrepairable: %v", err)
}

func (inst *instance) Close() {
	close(inst.closed)
	os.RemoveAll(inst.cfg.Workdir)
}

func (inst *instance) Copy(hostSrc string) (string, error) {
	basePath := "/data/"
	vmDst := filepath.Join(basePath, filepath.Base(hostSrc))
	args := append(inst.sshArgs("-P"), hostSrc, "root@"+inst.cfg.OdroidSlaveAddr+":"+vmDst)
	cmd := exec.Command("scp", args...)
	if inst.cfg.Debug {
		Logf(0, "running command: scp %#v", args)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stdout
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan bool)
	go func() {
		select {
		case <-time.After(3 * time.Minute):
			cmd.Process.Kill()
		case <-done:
		}
	}()
	err := cmd.Wait()
	close(done)
	if err != nil {
		return "", err
	}
	return vmDst, nil
}

func (inst *instance) Run(timeout time.Duration, stop <-chan bool, command string) (<-chan []byte, <-chan error, error) {
	tty, err := vm.OpenConsole(inst.cfg.OdroidConsole)
	if err != nil {
		return nil, nil, err
	}

	rpipe, wpipe, err := vm.LongPipe()
	if err != nil {
		tty.Close()
		return nil, nil, err
	}

	args := append(inst.sshArgs("-p"), "root@"+inst.cfg.OdroidSlaveAddr, "cd /data; "+command)
	if inst.cfg.Debug {
		Logf(0, "running command: ssh %#v", args)
	}
	cmd := exec.Command("ssh", args...)
	cmd.Stdout = wpipe
	cmd.Stderr = wpipe
	if err := cmd.Start(); err != nil {
		tty.Close()
		rpipe.Close()
		wpipe.Close()
		return nil, nil, err
	}
	wpipe.Close()

	var tee io.Writer
	if inst.cfg.Debug {
		tee = os.Stdout
	}
	merger := vm.NewOutputMerger(tee)
	merger.Add("console", tty)
	merger.Add("ssh", rpipe)

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
		case <-stop:
			signal(vm.TimeoutErr)
		case <-inst.closed:
			if inst.cfg.Debug {
				Logf(0, "instance closed")
			}
			signal(fmt.Errorf("instance closed"))
		case err := <-merger.Err:
			cmd.Process.Kill()
			tty.Close()
			merger.Wait()
			if cmdErr := cmd.Wait(); cmdErr == nil {
				// If the command exited successfully, we got EOF error from merger.
				// But in this case no error has happened and the EOF is expected.
				err = nil
			}
			signal(err)
			return
		}
		cmd.Process.Kill()
		tty.Close()
		merger.Wait()
		cmd.Wait()
	}()
	return merger.Output, errc, nil
}

func (inst *instance) sshArgs(portArg string) []string {
	args := []string{
		"-i", inst.cfg.Sshkey,
		portArg, "22",
		"-F", "/dev/null",
		"-o", "ConnectionAttempts=10",
		"-o", "ConnectTimeout=10",
		"-o", "BatchMode=yes",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "LogLevel=error",
	}
	if inst.cfg.Debug {
		args = append(args, "-v")
	}
	return args
}
