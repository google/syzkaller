// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package blob

import (
	"context"
	"fmt"
	"io"
	"regexp"

	"github.com/google/syzkaller/pkg/gcs"
	"github.com/google/uuid"
)

type gcsDriver struct {
	bucket string
	client *gcs.Client
}

func NewGCSClient(ctx context.Context, bucket string) (Storage, error) {
	client, err := gcs.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	return &gcsDriver{
		bucket: bucket,
		client: client,
	}, nil
}

func (gcs *gcsDriver) Store(source io.Reader) (string, error) {
	object := uuid.NewString()
	err := gcs.writeObject(object, source)
	if err != nil {
		return "", err
	}
	return gcs.objectURI(object), nil
}

func (gcs *gcsDriver) Update(uri string, source io.Reader) error {
	object, err := gcs.objectName(uri)
	if err != nil {
		return err
	}
	return gcs.writeObject(object, source)
}

func (gcs *gcsDriver) Read(uri string) (io.ReadCloser, error) {
	object, err := gcs.objectName(uri)
	if err != nil {
		return nil, err
	}
	file, err := gcs.client.Read(fmt.Sprintf("%s/%s", gcs.bucket, object))
	if err != nil {
		return nil, err
	}
	return file.Reader()
}

var gcsObjectRe = regexp.MustCompile(`^gcs://([\w-]+)/([\w-]+)$`)

func (gcs *gcsDriver) objectName(uri string) (string, error) {
	match := gcsObjectRe.FindStringSubmatch(uri)
	if len(match) == 0 {
		return "", fmt.Errorf("invalid GCS URI")
	} else if match[1] != gcs.bucket {
		return "", fmt.Errorf("unexpected GCS bucket")
	}
	return match[2], nil
}

func (gcs *gcsDriver) objectURI(object string) string {
	return fmt.Sprintf("gcs://%s/%s", gcs.bucket, object)
}

func (gcs *gcsDriver) writeObject(object string, source io.Reader) error {
	w, err := gcs.client.FileWriterExt(fmt.Sprintf("%s/%s", gcs.bucket, object), "", "")
	if err != nil {
		return err
	}
	defer w.Close()

	_, err = io.Copy(w, source)
	return err
}
