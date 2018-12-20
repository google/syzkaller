// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

// CopyFile atomically copies oldFile to newFile preserving permissions and modification time.
func CopyFile(oldFile, newFile string) error {
	oldf, err := os.Open(oldFile)
	if err != nil {
		return err
	}
	defer oldf.Close()
	stat, err := oldf.Stat()
	if err != nil {
		return err
	}
	tmpFile := newFile + ".tmp"
	newf, err := os.OpenFile(tmpFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, stat.Mode()&os.ModePerm)
	if err != nil {
		return err
	}
	defer newf.Close()
	_, err = io.Copy(newf, oldf)
	if err != nil {
		return err
	}
	if err := newf.Close(); err != nil {
		return err
	}
	if err := os.Chtimes(tmpFile, stat.ModTime(), stat.ModTime()); err != nil {
		return err
	}
	return os.Rename(tmpFile, newFile)
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

// WriteTempFile writes data to a temp file and returns its name.
func WriteTempFile(data []byte) (string, error) {
	// Note: pkg/report knows about "syzkaller" prefix as it appears in crashes as process name.
	f, err := ioutil.TempFile("", "syzkaller")
	if err != nil {
		return "", fmt.Errorf("failed to create a temp file: %v", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("failed to write a temp file: %v", err)
	}
	f.Close()
	return f.Name(), nil
}
