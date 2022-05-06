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
func embedLinuxKernel(params Params, kernelPath string) error {
	return embedFiles(params, func(mountDir string) error {
		if err := copyKernel(mountDir, kernelPath); err != nil {
			return err
		}
		return nil
	})
}

// embedFiles mounts the disk image specified by params.UserspaceDir and then calls the given
// callback function which should copy files into the image as needed.
func embedFiles(params Params, callback func(mountDir string) error) error {
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
	if err := tryMount(loopFile+"p1", mountDir); err != nil {
		return fmt.Errorf("mount(%vp1, %v) failed: %v", loopFile, mountDir, err)
	}
	defer unix.Unmount(mountDir, 0)
	if err := callback(mountDir); err != nil {
		return err
	}
	if params.SysctlFile != "" {
		if err := copySysctlFile(params.SysctlFile, loopFile, mountDir); err != nil {
			return err
		}
	}
	if err := unix.Unmount(mountDir, 0); err != nil {
		return err
	}
	return osutil.CopyFile(imageFile, filepath.Join(params.OutputDir, "image"))
}

func copySysctlFile(sysctlFile, loopFile, mountDir string) error {
	etcFolder := filepath.Join(mountDir, "etc")
	for idx := 2; ; idx++ {
		if osutil.IsExist(etcFolder) {
			break
		}
		err := tryMount(fmt.Sprintf("%sp%d", loopFile, idx), mountDir)
		if err != nil {
			// Most likely we've just run out of partitions.
			return fmt.Errorf("didn't find a partition that has /etc")
		}
		defer unix.Unmount(mountDir, 0)
	}
	return osutil.CopyFile(sysctlFile, filepath.Join(etcFolder, "sysctl.conf"))
}

func tryMount(device, mountDir string) error {
	var err error
loop:
	for _, fsType := range []string{"ext4", "vfat"} {
		err = unix.Mount(device, mountDir, fsType, 0, "")
		switch err {
		case syscall.EINVAL:
			// Most likely it just an invalid superblock error - try another fstype.
			continue
		case nil:
			break loop
		}
	}
	return err
}

func copyKernel(mountDir, kernelPath string) error {
	// Try several common locations where the kernel can be.
	for _, targetPath := range []string{"boot/vmlinuz", "boot/bzImage", "vmlinuz", "bzImage", "Image.gz"} {
		fullPath := filepath.Join(mountDir, filepath.FromSlash(targetPath))
		if !osutil.IsExist(fullPath) {
			continue
		}
		return osutil.CopyFile(kernelPath, fullPath)
	}
	return fmt.Errorf("did not find kernel in the template image")
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
