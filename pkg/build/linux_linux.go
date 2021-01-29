// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/google/syzkaller/pkg/osutil"
	"golang.org/x/sys/unix"
)

// embedLinuxKernel copies a new kernel into an existing disk image.
// There are several assumptions about the image:
// - the image is ext4 (may be inferred from image name if necessary, e.g. "image.btrfs")
// - the data is on partition 1 (we could see what partitions we got and use the last one)
// - ssh works without password (we don't copy the key)
// - cmdline file is not supported (should be moved to kernel config)
// - the kernel is stored in the image in /vmlinuz file.
func embedLinuxKernel(params *Params, kernelPath string) error {
	if params.CmdlineFile != "" {
		return fmt.Errorf("cmdline file is not supported for linux images")
	}
	tempDir, err := ioutil.TempDir("", "syz-build")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	imageFile := filepath.Join(tempDir, "image")
	if err := osutil.CopyFile(params.UserspaceDir, imageFile); err != nil {
		return err
	}
	loop, loopFile, err := linuxSetupLoop(imageFile)
	if err != nil {
		return err
	}
	defer func() {
		unix.IoctlGetInt(loop, unix.LOOP_CLR_FD)
		unix.Close(loop)
	}()
	mountDir := filepath.Join(tempDir, "mnt")
	if err := osutil.MkdirAll(mountDir); err != nil {
		return err
	}
	if err := unix.Mount(loopFile+"p1", mountDir, "ext4", 0, ""); err != nil {
		return fmt.Errorf("mount(%vp1, %v) failed: %v", loopFile, mountDir, err)
	}
	defer unix.Unmount(mountDir, 0)
	if err := osutil.CopyFile(kernelPath, filepath.Join(mountDir, "vmlinuz")); err != nil {
		return err
	}
	if params.SysctlFile != "" {
		if err := osutil.CopyFile(params.SysctlFile, filepath.Join(mountDir, "etc", "sysctl.conf")); err != nil {
			return err
		}
	}
	if err := unix.Unmount(mountDir, 0); err != nil {
		return err
	}
	return osutil.CopyFile(imageFile, filepath.Join(params.OutputDir, "image"))
}

func linuxSetupLoop(imageFile string) (int, string, error) {
	image, err := unix.Open(imageFile, unix.O_RDWR, 0)
	if err != nil {
		return 0, "", fmt.Errorf("failed to open %v: %v", imageFile, err)
	}
	defer unix.Close(image)
	loopControl, err := unix.Open("/dev/loop-control", unix.O_RDWR, 0)
	if err != nil {
		return 0, "", fmt.Errorf("failed to open /dev/loop-control: %v", err)
	}
	defer unix.Close(loopControl)
	loopIndex, err := unix.IoctlRetInt(loopControl, unix.LOOP_CTL_GET_FREE)
	if err != nil {
		return 0, "", fmt.Errorf("LOOP_CTL_GET_FREE failed: %v", err)
	}
	loopFile := fmt.Sprintf("/dev/loop%v", loopIndex)
	loop, err := unix.Open(loopFile, unix.O_RDWR, 0)
	if err != nil {
		return 0, "", fmt.Errorf("failed to open %v: %v", loopFile, err)
	}
	if err := unix.IoctlSetInt(loop, unix.LOOP_SET_FD, image); err != nil {
		unix.Close(loop)
		return 0, "", fmt.Errorf("LOOP_SET_FD failed: %v", err)
	}
	info := &unix.LoopInfo64{
		Flags: unix.LO_FLAGS_PARTSCAN,
	}
	for i := 0; i < len(imageFile); i++ {
		info.File_name[i] = imageFile[i]
	}
	if _, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(loop), unix.LOOP_SET_STATUS64,
		uintptr(unsafe.Pointer(info))); err != 0 {
		unix.Close(loop)
		return 0, "", fmt.Errorf("LOOP_SET_STATUS64 failed: %v", err)
	}
	return loop, loopFile, nil
}
