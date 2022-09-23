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
	"os"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"
)

type Client struct {
	client *storage.Client
	ctx    context.Context
}

type File struct {
	Updated time.Time

	ctx    context.Context
	handle *storage.ObjectHandle
}

func (file *File) Reader() (io.ReadCloser, error) {
	return file.handle.NewReader(file.ctx)
}

func NewClient() (*Client, error) {
	ctx := context.Background()
	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	client := &Client{
		client: storageClient,
		ctx:    ctx,
	}
	return client, nil
}

func (client *Client) Close() {
	client.client.Close()
}

func (client *Client) Read(gcsFile string) (*File, error) {
	bucket, filename, err := split(gcsFile)
	if err != nil {
		return nil, err
	}
	bkt := client.client.Bucket(bucket)
	f := bkt.Object(filename)
	attrs, err := f.Attrs(client.ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read %v attributes: %v", gcsFile, err)
	}
	if !attrs.Deleted.IsZero() {
		return nil, fmt.Errorf("file %v is deleted", gcsFile)
	}
	handle := f.If(storage.Conditions{
		GenerationMatch:     attrs.Generation,
		MetagenerationMatch: attrs.Metageneration,
	})
	file := &File{
		Updated: attrs.Updated,
		ctx:     client.ctx,
		handle:  handle,
	}
	return file, nil
}

func (client *Client) UploadFile(localFile, gcsFile, contentType, contentEncoding string) error {
	local, err := os.Open(localFile)
	if err != nil {
		return err
	}
	defer local.Close()

	w, err := client.FileWriterExt(gcsFile, contentType, contentEncoding)
	if err != nil {
		return err
	}
	defer w.Close()

	_, err = io.Copy(w, local)
	return err
}

func (client *Client) FileWriterExt(gcsFile, contentType, contentEncoding string) (io.WriteCloser, error) {
	bucket, filename, err := split(gcsFile)
	if err != nil {
		return nil, err
	}
	bkt := client.client.Bucket(bucket)
	f := bkt.Object(filename)
	w := f.NewWriter(client.ctx)
	if contentType != "" {
		w.ContentType = contentType
	}
	if contentEncoding != "" {
		w.ContentEncoding = contentEncoding
	}
	return w, nil
}

func (client *Client) FileWriter(gcsFile string) (io.WriteCloser, error) {
	return client.FileWriterExt(gcsFile, "", "")
}

// Publish lets any user read gcsFile.
func (client *Client) Publish(gcsFile string) error {
	bucket, filename, err := split(gcsFile)
	if err != nil {
		return err
	}
	obj := client.client.Bucket(bucket).Object(filename)
	return obj.ACL().Set(client.ctx, storage.AllUsers, storage.RoleReader)
}

var ErrFileNotFound = errors.New("the requested files does not exist")

func (client *Client) DeleteFile(gcsFile string) error {
	bucket, filename, err := split(gcsFile)
	if err != nil {
		return err
	}
	err = client.client.Bucket(bucket).Object(filename).Delete(client.ctx)
	if err == storage.ErrObjectNotExist {
		return ErrFileNotFound
	}
	return err
}

func (client *Client) FileExists(gcsFile string) (bool, error) {
	bucket, filename, err := split(gcsFile)
	if err != nil {
		return false, err
	}
	_, err = client.client.Bucket(bucket).Object(filename).Attrs(client.ctx)
	if err == storage.ErrObjectNotExist {
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

func (client *Client) GetDownloadURL(gcsFile string, publicURL bool) string {
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

func (client *Client) ListObjects(bucket string) ([]*Object, error) {
	ctx := context.Background()
	it := client.client.Bucket(bucket).Objects(ctx, nil)
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
