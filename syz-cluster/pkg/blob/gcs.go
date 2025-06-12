// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package blob

import (
	"context"
	"fmt"
	"io"
	"path"
	"regexp"

	"github.com/google/syzkaller/pkg/gcs"
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

func (gcs *gcsDriver) Write(source io.Reader, parts ...string) (string, error) {
	if len(parts) == 0 {
		return "", fmt.Errorf("no identifiers for the object were passed to Write")
	}
	object := path.Join(gcs.bucket, path.Join(parts...))
	w, err := gcs.client.FileWriter(object, "", "")
	if err != nil {
		return "", err
	}
	defer w.Close()
	_, err = io.Copy(w, source)
	if err != nil {
		return "", err
	}
	return "gcs://" + object, nil
}

func (gcs *gcsDriver) Read(uri string) (io.ReadCloser, error) {
	bucket, object, err := gcs.parseURI(uri)
	if err != nil {
		return nil, err
	}
	return gcs.client.FileReader(path.Join(bucket, object))
}

var gcsObjectRe = regexp.MustCompile(`^gcs://([\w-]+)/(.+)$`)

func (gcs *gcsDriver) parseURI(uri string) (string, string, error) {
	match := gcsObjectRe.FindStringSubmatch(uri)
	if len(match) == 0 {
		return "", "", fmt.Errorf("invalid GCS URI")
	} else if match[1] != gcs.bucket {
		return "", "", fmt.Errorf("unexpected GCS bucket")
	}
	return gcs.bucket, match[2], nil
}
