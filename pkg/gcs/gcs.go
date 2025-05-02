// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package gcs provides wrappers around Google Cloud Storage (GCS) APIs.
// Package uses Application Default Credentials assuming that the program runs on GCE.
//
// See the following links for details and API reference:
// https://cloud.google.com/go/getting-started/using-cloud-storage
// https://godoc.org/cloud.google.com/go/storage

package gcs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

type Client interface {
	Close() error
	FileReader(path string) (io.ReadCloser, error)
	FileWriter(path string, contentType string, contentEncoding string) (io.WriteCloser, error)
	DeleteFile(path string) error
	FileExists(path string) (bool, error)
	ListObjects(path string) ([]*Object, error)

	Publish(path string) error
}

type UploadOptions struct {
	Publish         bool
	ContentEncoding string
	GCSClientMock   Client
}

func UploadFile(ctx context.Context, srcFile io.Reader, destURL string, opts UploadOptions) error {
	destURL = strings.TrimPrefix(destURL, "gs://")
	var err error
	gcsClient := opts.GCSClientMock
	if gcsClient == nil {
		if gcsClient, err = NewClient(ctx); err != nil {
			return fmt.Errorf("func NewClient: %w", err)
		}
	}
	defer gcsClient.Close()
	gcsWriter, err := gcsClient.FileWriter(destURL, "", opts.ContentEncoding)
	if err != nil {
		return fmt.Errorf("client.FileWriter: %w", err)
	}
	if _, err := io.Copy(gcsWriter, srcFile); err != nil {
		gcsWriter.Close()
		return fmt.Errorf("io.Copy: %w", err)
	}
	if err := gcsWriter.Close(); err != nil {
		return fmt.Errorf("gcsWriter.Close: %w", err)
	}
	if opts.Publish {
		return gcsClient.Publish(destURL)
	}
	return nil
}

type client struct {
	client *storage.Client
	ctx    context.Context
}

func NewClient(ctx context.Context) (Client, error) {
	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	c := &client{
		client: storageClient,
		ctx:    ctx,
	}
	return c, nil
}

func (c *client) Close() error {
	return c.client.Close()
}

func (c *client) FileReader(gcsFile string) (io.ReadCloser, error) {
	bucket, filename, err := split(gcsFile)
	if err != nil {
		return nil, err
	}
	bkt := c.client.Bucket(bucket)
	f := bkt.Object(filename)
	attrs, err := f.Attrs(c.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read %v attributes: %w", gcsFile, err)
	}
	if !attrs.Deleted.IsZero() {
		return nil, fmt.Errorf("file %v is deleted", gcsFile)
	}
	handle := f.If(storage.Conditions{
		GenerationMatch:     attrs.Generation,
		MetagenerationMatch: attrs.Metageneration,
	})
	return handle.NewReader(c.ctx)
}

func (c *client) FileWriter(gcsFile, contentType, contentEncoding string) (io.WriteCloser, error) {
	bucket, filename, err := split(gcsFile)
	if err != nil {
		return nil, err
	}
	bkt := c.client.Bucket(bucket)
	f := bkt.Object(filename)
	w := f.NewWriter(c.ctx)
	if contentType != "" {
		w.ContentType = contentType
	}
	if contentEncoding != "" {
		w.ContentEncoding = contentEncoding
	}
	return w, nil
}

// Publish lets any user read gcsFile.
func (c *client) Publish(gcsFile string) error {
	bucket, filename, err := split(gcsFile)
	if err != nil {
		return err
	}
	obj := c.client.Bucket(bucket).Object(filename)
	return obj.ACL().Set(c.ctx, storage.AllUsers, storage.RoleReader)
}

var ErrFileNotFound = errors.New("the requested files does not exist")

func (c *client) DeleteFile(gcsFile string) error {
	bucket, filename, err := split(gcsFile)
	if err != nil {
		return err
	}
	err = c.client.Bucket(bucket).Object(filename).Delete(c.ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return ErrFileNotFound
	}
	return err
}

func (c *client) FileExists(gcsFile string) (bool, error) {
	bucket, filename, err := split(gcsFile)
	if err != nil {
		return false, err
	}
	_, err = c.client.Bucket(bucket).Object(filename).Attrs(c.ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}

// Where things get published.
const (
	PublicPrefix        = "https://storage.googleapis.com/"
	AuthenticatedPrefix = "https://storage.cloud.google.com/"
)

func GetDownloadURL(gcsFile string, publicURL bool) string {
	gcsFile = strings.TrimPrefix(gcsFile, "/")
	if publicURL {
		return PublicPrefix + gcsFile
	}
	return AuthenticatedPrefix + gcsFile
}

type Object struct {
	Path      string
	CreatedAt time.Time
}

// ListObjects expects "bucket/path" or "bucket" as input.
func (c *client) ListObjects(bucketObjectPath string) ([]*Object, error) {
	bucket, objectPath, err := split(bucketObjectPath)
	if err != nil { // no path specified
		bucket = bucketObjectPath
	}
	query := &storage.Query{Prefix: objectPath}
	it := c.client.Bucket(bucket).Objects(c.ctx, query)
	ret := []*Object{}
	for {
		objAttrs, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to query GCS objects: %w", err)
		}
		ret = append(ret, &Object{
			Path:      objAttrs.Name,
			CreatedAt: objAttrs.Created,
		})
	}
	return ret, nil
}

func split(file string) (bucket, filename string, err error) {
	pos := strings.IndexByte(file, '/')
	if pos == -1 {
		return "", "", fmt.Errorf("invalid GCS file name: %v", file)
	}
	return file[:pos], file[pos+1:], nil
}
