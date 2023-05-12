// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package asset

import (
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/gcs"
)

type cloudStorageBackend struct {
	client *gcs.Client
	bucket string
	tracer debugtracer.DebugTracer
}

func makeCloudStorageBackend(bucket string, tracer debugtracer.DebugTracer) (*cloudStorageBackend, error) {
	tracer.Log("created gcs backend for bucket '%s'", bucket)
	client, err := gcs.NewClient()
	if err != nil {
		return nil, fmt.Errorf("the call to NewClient failed: %w", err)
	}
	return &cloudStorageBackend{
		client: client,
		bucket: bucket,
		tracer: tracer,
	}, nil
}

// Actual write errors might be hidden, so we wrap the writer here
// to ensure that they get logged.
type writeErrorLogger struct {
	writeCloser io.WriteCloser
	tracer      debugtracer.DebugTracer
}

func (wel *writeErrorLogger) Write(p []byte) (n int, err error) {
	n, err = wel.writeCloser.Write(p)
	if err != nil {
		wel.tracer.Log("cloud storage write error: %s", err)
	}
	return
}

func (wel *writeErrorLogger) Close() error {
	err := wel.writeCloser.Close()
	if err != nil {
		wel.tracer.Log("cloud storage writer close error: %s", err)
	}
	return err
}

func (csb *cloudStorageBackend) upload(req *uploadRequest) (*uploadResponse, error) {
	path := fmt.Sprintf("%s/%s", csb.bucket, req.savePath)
	// Best-effort check only. In the worst case we'll just overwite the file.
	// The alternative would be to add an If-precondition, but it'd require
	// complicated error-during-write handling.
	exists, err := csb.client.FileExists(path)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, &FileExistsError{req.savePath}
	}
	w, err := csb.client.FileWriterExt(path, req.contentType, req.contentEncoding)
	csb.tracer.Log("gcs upload: obtained a writer for %s, error %s", path, err)
	if err != nil {
		return nil, err
	}
	return &uploadResponse{
		writer: &writeErrorLogger{
			writeCloser: w,
			tracer:      csb.tracer,
		},
		path: req.savePath,
	}, nil
}

func (csb *cloudStorageBackend) downloadURL(path string, publicURL bool) (string, error) {
	return csb.client.GetDownloadURL(fmt.Sprintf("%s/%s", csb.bucket, path), publicURL), nil
}

var allowedDomainsRe = regexp.MustCompile(`^storage\.googleapis\.com|storage\.cloud\.google\.com$`)

func (csb *cloudStorageBackend) getPath(downloadURL string) (string, error) {
	u, err := url.Parse(downloadURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse the URL: %w", err)
	}
	if !allowedDomainsRe.MatchString(u.Host) {
		return "", fmt.Errorf("not allowed host: %s", u.Host)
	}
	prefix := "/" + csb.bucket + "/"
	if !strings.HasPrefix(u.Path, prefix) {
		return "", ErrUnknownBucket
	}
	return u.Path[len(prefix):], nil
}

func (csb *cloudStorageBackend) list() ([]storedObject, error) {
	list, err := csb.client.ListObjects(csb.bucket)
	if err != nil {
		return nil, err
	}
	ret := []storedObject{}
	for _, obj := range list {
		ret = append(ret, storedObject{
			path:      obj.Path,
			createdAt: obj.CreatedAt,
		})
	}
	return ret, nil
}

func (csb *cloudStorageBackend) remove(path string) error {
	path = fmt.Sprintf("%s/%s", csb.bucket, path)
	err := csb.client.DeleteFile(path)
	if err == gcs.ErrFileNotFound {
		return ErrAssetDoesNotExist
	}
	return err
}
