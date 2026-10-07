// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func fileTimes(file string) (time.Time, time.Time, error) {
	// Btime stands for "birth" time, which is creation time.
	var statx unix.Statx_t
	err := unix.Statx(unix.AT_FDCWD, file, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME|unix.STATX_MTIME, &statx)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	modTime := time.Unix(statx.Mtime.Sec, int64(statx.Mtime.Nsec))
	// Some filesystems may not store the birth time.
	creationTime := modTime
	if statx.Mask&unix.STATX_BTIME != 0 {
		creationTime = time.Unix(statx.Btime.Sec, int64(statx.Btime.Nsec))
	}
	return creationTime, modTime, nil
}

// RemoveAll is similar to os.RemoveAll, but can handle more cases.
func RemoveAll(dir string) error {
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		name := filepath.Join(dir, f.Name())
		if f.IsDir() {
			RemoveAll(name)
		}
		unix.Unmount(name, unix.MNT_FORCE)
	}
	if err := os.RemoveAll(dir); err != nil {
		removeImmutable(dir)
		return os.RemoveAll(dir)
	}
	return nil
}

func SystemMemorySize() uint64 {
	var info syscall.Sysinfo_t
	syscall.Sysinfo(&info)
	return uint64(info.Totalram) // nolint:unconvert
}

func removeImmutable(fname string) error {
	// Reset FS_XFLAG_IMMUTABLE/FS_XFLAG_APPEND.
	fd, err := syscall.Open(fname, syscall.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return unix.IoctlSetPointerInt(fd, unix.FS_IOC_SETFLAGS, 0)
}

func Sandbox(cmd *exec.Cmd, user, net bool) error {
	enabled, uid, gid, err := initSandbox()
	if err != nil || !enabled {
		return err
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = new(syscall.SysProcAttr)
	}
	if net {
		cmd.SysProcAttr.Cloneflags = syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC |
			syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID
	}
	if user {
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid: uid,
			Gid: gid,
		}
	}
	return nil
}

func SandboxChown(files ...string) error {
	enabled, uid, gid, err := initSandbox()
	if err != nil || !enabled {
		return err
	}
	for _, file := range files {
		if err := os.Chown(file, int(uid), int(gid)); err != nil {
			return err
		}
		abs, err := filepath.Abs(file)
		if err != nil {
			return err
		}
		for dir := filepath.Dir(abs); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
			info, err := os.Stat(dir)
			if err != nil {
				return err
			}
			if info.Mode()&0111 != 0111 {
				if err := os.Chmod(dir, info.Mode()|0111); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

var (
	sandboxOnce     sync.Once
	sandboxUsername = "syzkaller"
	sandboxUID      = ^uint32(0)
	sandboxGID      = ^uint32(0)
)

func initSandbox() (bool, uint32, uint32, error) {
	if syscall.Getuid() != 0 || os.Getenv("CI") != "" || os.Getenv("SYZ_DISABLE_SANDBOXING") == "yes" {
		return false, 0, 0, nil
	}
	sandboxOnce.Do(func() {
		if u, err := user.Lookup(sandboxUsername); err == nil {
			uid, err1 := strconv.ParseUint(u.Uid, 10, 32)
			gid, err2 := strconv.ParseUint(u.Gid, 10, 32)
			if err1 == nil && err2 == nil {
				sandboxUID = uint32(uid)
				sandboxGID = uint32(gid)
			}
		}
	})
	if sandboxUID == ^uint32(0) {
		return false, 0, 0, fmt.Errorf("user %q is not found, can't sandbox command", sandboxUsername)
	}
	return true, sandboxUID, sandboxGID, nil
}

// RequireSandbox enables osutil.Sandbox for the test.
// Similar to production setups, HOME points to the sandbox user's home directory.
// The test is skipped if sandboxing is not available (not running as root or
// no syzkaller user), unless CI is set: on CI sandboxing must be available,
// so the test fails instead.
func RequireSandbox(t *testing.T) {
	t.Helper()
	skip := func(msg string) {
		t.Helper()
		if os.Getenv("CI") != "" {
			t.Fatalf("sandbox tests must run on CI: %v", msg)
		}
		t.Skipf("skipping sandbox test: %v", msg)
	}
	if syscall.Getuid() != 0 {
		skip("requires root")
	}
	u, err := user.Lookup(sandboxUsername)
	if err != nil {
		skip(err.Error())
	}
	t.Setenv("HOME", u.HomeDir)
	t.Setenv("CI", "")
	t.Setenv("SYZ_DISABLE_SANDBOXING", "")
}

func setPdeathsig(cmd *exec.Cmd, hardKill bool) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = new(syscall.SysProcAttr)
	}
	if hardKill {
		cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
	} else {
		cmd.SysProcAttr.Pdeathsig = syscall.SIGTERM
	}
	// We will kill the whole process group.
	cmd.SysProcAttr.Setpgid = true
}

func killPgroup(cmd *exec.Cmd) {
	syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

func prolongPipe(r, w *os.File) {
	for sz := 128 << 10; sz <= 2<<20; sz *= 2 {
		syscall.Syscall(syscall.SYS_FCNTL, w.Fd(), syscall.F_SETPIPE_SZ, uintptr(sz))
	}
}

func sysDiskUsage(info fs.FileInfo) uint64 {
	stat := info.Sys().(*syscall.Stat_t)
	blocks := uint64(max(0, stat.Blocks))
	if blocks == 0 && stat.Size > 0 && (info.Mode().IsRegular() || info.IsDir()) {
		// This is what du does in this case: small files stored inline, still take some blocks.
		blksize := uint64(stat.Blksize)
		if blksize == 0 {
			blksize = 4096
		}
		return (uint64(stat.Size) + blksize - 1) / blksize * blksize
	}
	return blocks * 512
}
