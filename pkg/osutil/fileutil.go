// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"syscall"
)

// CopyFile atomically copies a regular file oldFile to newFile preserving permissions and modification time.
func CopyFile(oldFile, newFile string) error {
	oldf, err := os.OpenFile(oldFile, openRegularFlags, 0)
	if err != nil {
		return err
	}
	defer oldf.Close()
	return copyFile(oldf, newFile, true)
}

func copyFile(oldf *os.File, newFile string, preserveMeta bool) error {
	stat, err := regularFileStat(oldf)
	if err != nil {
		return err
	}
	perm := os.FileMode(DefaultFilePerm)
	if preserveMeta {
		perm = stat.Mode() & os.ModePerm
	}
	tmpFile := fmt.Sprintf("%v.%x.tmp", newFile, rand.Uint64())
	newf, err := os.OpenFile(tmpFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	_, err = io.Copy(newf, oldf)
	if closeErr := newf.Close(); err == nil {
		err = closeErr
	}
	if err == nil && preserveMeta {
		err = os.Chtimes(tmpFile, stat.ModTime(), stat.ModTime())
	}
	if err == nil {
		err = os.Rename(tmpFile, newFile)
	}
	if err != nil {
		os.Remove(tmpFile)
	}
	return err
}

// openRegularFlags are used to open files that are expected to be regular for reading.
// O_NONBLOCK prevents hanging on FIFOs, and it has no effect on regular files.
const openRegularFlags = os.O_RDONLY | syscall.O_NONBLOCK

// regularFileStat returns information about f, or an error if f is not a regular file.
func regularFileStat(f *os.File) (os.FileInfo, error) {
	stat, err := f.Stat()
	switch {
	case err != nil:
		return nil, err
	case stat.Mode().IsRegular():
		return stat, nil
	case stat.IsDir():
		// Return the same error as reading the directory would (some callers check for it).
		return nil, &fs.PathError{Op: "read", Path: f.Name(), Err: syscall.EISDIR}
	default:
		return nil, fmt.Errorf("%v is not a regular file", f.Name())
	}
}

// Rename is similar to os.Rename but handles cross-device renaming (by copying).
func Rename(oldFile, newFile string) error {
	err := os.Rename(oldFile, newFile)
	if err != nil {
		// Can't use syscall.EXDEV because this is used in appengine app.
		err = CopyFile(oldFile, newFile)
		os.Remove(oldFile)
	}
	return err
}

// FillDirectory is used to fill in directory structure for tests.
func FillDirectory(dir string, fileContent map[string]string) error {
	for path, content := range fileContent {
		fullPath := filepath.Join(dir, path)
		dirPath := filepath.Dir(fullPath)
		if err := MkdirAll(dirPath); err != nil {
			return fmt.Errorf("mkdir %q failed: %w", dirPath, err)
		}
		if err := WriteFile(fullPath, []byte(content)); err != nil {
			return fmt.Errorf("write file failed: %w", err)
		}
	}
	return nil
}

// WriteTempFile writes data to a temp file and returns its name.
func WriteTempFile(data []byte) (string, error) {
	// Note: pkg/report knows about "syzkaller" prefix as it appears in crashes as process name.
	f, err := os.CreateTemp("", "syzkaller")
	if err != nil {
		return "", fmt.Errorf("failed to create a temp file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("failed to write a temp file: %w", err)
	}
	f.Close()
	return f.Name(), nil
}
