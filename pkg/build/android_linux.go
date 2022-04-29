// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/google/syzkaller/pkg/osutil"
)

// buildCuttlefishImage mounts a disk image, fetches and installs a Cuttlefish emulator binary,
// and copies in the required kernel artifacts.
func buildCuttlefishImage(params Params, bzImage, vmlinux, initramfs string) error {
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

	imageHomeDir := filepath.Join(mountDir, "root")
	if _, err := osutil.RunCmd(time.Hour, imageHomeDir, "./fetchcvd"); err != nil {
		return fmt.Errorf("run fetch_cvd: %s", err)
	}

	if err := osutil.CopyFile(bzImage, filepath.Join(imageHomeDir, "bzImage")); err != nil {
		return err
	}
	if err := osutil.CopyFile(vmlinux, filepath.Join(imageHomeDir, "vmlinux")); err != nil {
		return err
	}
	if err := osutil.CopyFile(initramfs, filepath.Join(imageHomeDir, "initramfs.img")); err != nil {
		return err
	}

	if err := unix.Unmount(mountDir, 0); err != nil {
		return err
	}

	return osutil.CopyFile(imageFile, filepath.Join(params.OutputDir, "image"))
}
