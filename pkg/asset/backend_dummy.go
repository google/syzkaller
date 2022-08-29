// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package asset

import (
	"fmt"
	"strings"
	"time"
)

type objectUploadCallback func(req *uploadRequest) (*uploadResponse, error)
type objectRemoveCallback func(url string) error

type dummyObject struct {
	createdAt       time.Time
	contentType     string
	contentEncoding string
}

type dummyStorageBackend struct {
	currentTime  time.Time
	objects      map[string]*dummyObject
	objectUpload objectUploadCallback
	objectRemove objectRemoveCallback
}

func makeDummyStorageBackend() *dummyStorageBackend {
	return &dummyStorageBackend{
		currentTime: time.Now(),
		objects:     make(map[string]*dummyObject),
	}
}

type dummyWriteCloser struct {
}

func (dwc *dummyWriteCloser) Write(p []byte) (int, error) {
	return len(p), nil
}

func (dwc *dummyWriteCloser) Close() error {
	return nil
}

func (be *dummyStorageBackend) upload(req *uploadRequest) (*uploadResponse, error) {
	be.objects[req.savePath] = &dummyObject{
		createdAt:       be.currentTime,
		contentType:     req.contentType,
		contentEncoding: req.contentEncoding,
	}
	if be.objectUpload != nil {
		return be.objectUpload(req)
	}
	return &uploadResponse{writer: &dummyWriteCloser{}, path: req.savePath}, nil
}

func (be *dummyStorageBackend) downloadURL(path string, publicURL bool) (string, error) {
	return "http://download/" + path, nil
}

func (be *dummyStorageBackend) getPath(url string) (string, error) {
	return strings.TrimPrefix(url, "http://download/"), nil
}

func (be *dummyStorageBackend) list() ([]storedObject, error) {
	ret := []storedObject{}
	for path, obj := range be.objects {
		ret = append(ret, storedObject{
			path:      path,
			createdAt: obj.createdAt,
		})
	}
	return ret, nil
}

func (be *dummyStorageBackend) remove(path string) error {
	if be.objectRemove != nil {
		if err := be.objectRemove(path); err != nil {
			return err
		}
	}
	if _, ok := be.objects[path]; !ok {
		return ErrAssetDoesNotExist
	}
	delete(be.objects, path)
	return nil
}

func (be *dummyStorageBackend) hasOnly(paths []string) error {
	makeError := func() error {
		return fmt.Errorf("object sets are not equal; needed: %#v; uploaded: %#v", paths, be.objects)
	}
	if len(paths) != len(be.objects) {
		return makeError()
	}
	for _, path := range paths {
		if be.objects[path] == nil {
			return makeError()
		}
	}
	return nil
}
