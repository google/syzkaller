// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
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

// GrepFiles returns the list of files (relative to root) that include target.
// If ext is not empty, the files will be filtered by the extension.
// The function assumes that the files are not too big and may fit in memory.
func GrepFiles(root, ext string, target []byte) ([]string, error) {
	var ret []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ext {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to open %s: %w", path, err)
		}
		if bytes.Contains(content, target) {
			rel, _ := filepath.Rel(root, path)
			ret = append(ret, rel)
		}
		return nil
	})
	return ret, err
}
