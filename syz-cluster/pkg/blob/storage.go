// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package blob

import (
	"bytes"
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
	// Returns a random URI to use later.
	NewURI() (string, error)
	Write(uri string, source io.Reader) error
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

func (ls *LocalStorage) NewURI() (string, error) {
	key, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return localStoragePrefix + key.String(), nil
}

func (ls *LocalStorage) Write(uri string, source io.Reader) error {
	path, err := ls.uriToPath(uri)
	if err != nil {
		return err
	}
	file, err := os.Create(path)
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

func (ls *LocalStorage) Read(uri string) (io.ReadCloser, error) {
	path, err := ls.uriToPath(uri)
	if err != nil {
		return nil, err
	}
	return os.Open(path)
}

func (ls *LocalStorage) uriToPath(uri string) (string, error) {
	if !strings.HasPrefix(uri, localStoragePrefix) {
		return "", fmt.Errorf("unsupported URI type")
	}
	return filepath.Join(ls.baseFolder, strings.TrimPrefix(uri, localStoragePrefix)), nil
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

func StoreBytes(storage Storage, data []byte) (string, error) {
	uri, err := storage.NewURI()
	if err != nil {
		return "", fmt.Errorf("failed to generate URI: %w", err)
	}
	err = storage.Write(uri, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	return uri, nil
}
