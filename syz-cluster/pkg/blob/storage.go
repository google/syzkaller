// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package blob

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Storage is not assumed to be used for partciularly large objects (e.g. GB of size),
// but rather for blobs that risk overwhelming Spanner column size limits.
type Storage interface {
	// Store returns a URI to use later.
	Store(source io.Reader) (string, error)
	Read(uri string) (io.ReadCloser, error)
}

var _ Storage = (*LocalStorage)(nil)

type LocalStorage struct {
	baseFolder string
}

func NewLocalStorage(baseFolder string) *LocalStorage {
	return &LocalStorage{baseFolder: baseFolder}
}

const localStoragePrefix = "local://"

func (ls *LocalStorage) Store(source io.Reader) (string, error) {
	name := fmt.Sprint(time.Now().UnixNano())
	file, err := os.Create(filepath.Join(ls.baseFolder, name))
	if err != nil {
		return "", err
	}
	defer file.Close()
	_, err = io.Copy(file, source)
	if err != nil {
		return "", fmt.Errorf("failed to save data: %w", err)
	}
	return localStoragePrefix + name, nil
}

func (ls *LocalStorage) Read(uri string) (io.ReadCloser, error) {
	if !strings.HasPrefix(uri, localStoragePrefix) {
		return nil, fmt.Errorf("unsupported URI type")
	}
	// TODO: add some other URI validation checks?
	path := filepath.Join(ls.baseFolder, strings.TrimPrefix(uri, localStoragePrefix))
	return os.Open(path)
}
