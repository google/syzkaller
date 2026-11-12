// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
)

// SandboxRoot provides access to a directory whose contents may be controlled by untrusted
// (e.g. sandboxed) code. On top of the os.Root guarantees (no escaping from the directory
// via ".." or symlinks), it never reads from or writes through anything but regular files.
type SandboxRoot struct {
	root *os.Root
}

func OpenSandboxRoot(dir string) (*SandboxRoot, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &SandboxRoot{root: root}, nil
}

func (r *SandboxRoot) Close() error {
	return r.root.Close()
}

func (r *SandboxRoot) Remove(name string) error {
	return r.root.Remove(name)
}

// WalkDir walks the file tree rooted at dir similarly to fs.WalkDir.
func (r *SandboxRoot) WalkDir(dir string, fn fs.WalkDirFunc) error {
	return fs.WalkDir(r.root.FS(), dir, fn)
}

// ReadFile reads a regular file.
func (r *SandboxRoot) ReadFile(name string) ([]byte, error) {
	f, err := r.root.OpenFile(name, openRegularFlags, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := regularFileStat(f); err != nil {
		return nil, err
	}
	return io.ReadAll(f)
}

// CopyFileTo atomically copies a regular file name to dst outside of the directory.
// Unlike CopyFile, it does not preserve untrusted permissions or modification time.
func (r *SandboxRoot) CopyFileTo(name, dst string) error {
	f, err := r.root.OpenFile(name, openRegularFlags, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return copyFile(f, dst, false)
}

// WriteFile atomically replaces name with a regular file owned by the sandbox user
// (see SandboxChown), so that sandboxed code can modify it. If name is a symlink or a hard link,
// the link itself is replaced, and its target is left intact.
func (r *SandboxRoot) WriteFile(name string, data []byte) error {
	tmpFile := fmt.Sprintf("%v.%x.tmp", name, rand.Uint64())
	// O_EXCL guarantees that we create a new file rather than open an existing one or follow a symlink.
	f, err := r.root.OpenFile(tmpFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, DefaultFilePerm)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = sandboxChownFile(f)
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = r.root.Rename(tmpFile, name)
	}
	if err != nil {
		r.root.Remove(tmpFile)
	}
	return err
}
