// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package blob

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Storage is not assumed to be used for partciularly large objects (e.g. GB of size),
// but rather for blobs that risk overwhelming Spanner column size limits.
type Storage interface {
	// Write stores the object uniquely identified by a set of IDs (parts).
	// If it already exists, it will be overwritten.
	// The first argument is the URI which can be used to later retrieve it with Read.
	Write(source io.Reader, parts ...string) (string, error)
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

func (ls *LocalStorage) Write(source io.Reader, parts ...string) (string, error) {
	// A whatever approach that can handle arbitrary inputs.
	name := base64.StdEncoding.EncodeToString([]byte(filepath.Join(parts...)))
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
