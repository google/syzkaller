// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package blob

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// Storage is not assumed to be used for partciularly large objects (e.g. GB of size),
// but rather for blobs that risk overwhelming Spanner column size limits.
type Storage interface {
	// Store returns a URI to use later.
	Store(source io.Reader) (string, error)
	Update(key string, source io.Reader) error
	Read(uri string) (io.ReadCloser, error)
}

var _ Storage = (*LocalStorage)(nil)

// LocalStorage keeps objets in the specified local directory.
// It's intended to be used only for unit tests.
type LocalStorage struct {
	baseFolder string
}

func NewLocalStorage(baseFolder string) *LocalStorage {
	return &LocalStorage{baseFolder: baseFolder}
}

const localStoragePrefix = "local://"

func (ls *LocalStorage) Store(source io.Reader) (string, error) {
	name := uuid.NewString()
	err := ls.writeFile(name, source)
	if err != nil {
		return "", err
	}
	return localStoragePrefix + name, nil
}

func (ls *LocalStorage) Update(uri string, source io.Reader) error {
	if !strings.HasPrefix(uri, localStoragePrefix) {
		return fmt.Errorf("unsupported URI type")
	}
	return ls.writeFile(strings.TrimPrefix(uri, localStoragePrefix), source)
}

func (ls *LocalStorage) Read(uri string) (io.ReadCloser, error) {
	if !strings.HasPrefix(uri, localStoragePrefix) {
		return nil, fmt.Errorf("unsupported URI type")
	}
	// TODO: add some other URI validation checks?
	path := filepath.Join(ls.baseFolder, strings.TrimPrefix(uri, localStoragePrefix))
	return os.Open(path)
}

func (ls *LocalStorage) writeFile(name string, source io.Reader) error {
	file, err := os.Create(filepath.Join(ls.baseFolder, name))
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(file, source)
	if err != nil {
		return fmt.Errorf("failed to save data: %w", err)
	}
	return nil
}

func ReadAllBytes(storage Storage, uri string) ([]byte, error) {
	if uri == "" {
		return nil, nil
	}
	reader, err := storage.Read(uri)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}
