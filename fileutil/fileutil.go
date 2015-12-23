// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fileutil

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func CopyFile(oldFile, newFile string) error {
	oldf, err := os.Open(oldFile)
	if err != nil {
		return err
	}
	defer oldf.Close()
	newf, err := os.Create(newFile)
	if err != nil {
		return err
	}
	defer newf.Close()
	_, err = io.Copy(newf, oldf)
	if err != nil {
		return err
	}
	return nil
}

// WriteTempFile writes data to a temp file and returns its name.
func WriteTempFile(data []byte) (string, error) {
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
