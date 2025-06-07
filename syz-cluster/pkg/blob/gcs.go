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
	client gcs.Client
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

func (gcs *gcsDriver) NewURI() (string, error) {
	key, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("gcs://%s/%s", gcs.bucket, key.String()), nil
}

func (gcs *gcsDriver) Write(uri string, source io.Reader) error {
	bucket, object, err := gcs.parseURI(uri)
	if err != nil {
		return err
	}
	w, err := gcs.client.FileWriter(fmt.Sprintf("%s/%s", bucket, object), "", "")
	if err != nil {
		return err
	}
	defer w.Close()

	_, err = io.Copy(w, source)
	return err
}

func (gcs *gcsDriver) Read(uri string) (io.ReadCloser, error) {
	bucket, object, err := gcs.parseURI(uri)
	if err != nil {
		return nil, err
	}
	return gcs.client.FileReader(fmt.Sprintf("%s/%s", bucket, object))
}

var gcsObjectRe = regexp.MustCompile(`^gcs://([\w-]+)/([\w-]+)$`)

func (gcs *gcsDriver) parseURI(uri string) (string, string, error) {
	match := gcsObjectRe.FindStringSubmatch(uri)
	if len(match) == 0 {
		return "", "", fmt.Errorf("invalid GCS URI")
	} else if match[1] != gcs.bucket {
		return "", "", fmt.Errorf("unexpected GCS bucket")
	}
	return gcs.bucket, match[2], nil
}
