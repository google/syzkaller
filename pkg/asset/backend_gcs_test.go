// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package asset

import (
	"testing"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/stretchr/testify/assert"
)

func TestCloudGetPaths(t *testing.T) {
	obj := &cloudStorageBackend{
		client: nil, // we won't need it
		bucket: "my_bucket",
		tracer: &debugtracer.NullTracer{},
	}
	// Test a public download URL.
	url, _ := obj.downloadURL("folder/file.txt", true)
	assert.Equal(t, `https://storage.googleapis.com/my_bucket/folder/file.txt`, url)
	// Test a non-public download URL.
	url, _ = obj.downloadURL("folder/file.txt", false)
	assert.Equal(t, `https://storage.cloud.google.com/my_bucket/folder/file.txt`, url)
}

func TestCloudParsePaths(t *testing.T) {
	obj := &cloudStorageBackend{
		client: nil, // we won't need it
		bucket: `my_bucket`,
		tracer: &debugtracer.NullTracer{},
	}
	// Parse a public download URL.
	path, err := obj.getPath(`https://storage.googleapis.com/my_bucket/folder/file.txt`)
	assert.NoError(t, err)
	assert.Equal(t, `folder/file.txt`, path)
	// Parse a non-public download URL.
	path, err = obj.getPath(`https://storage.cloud.google.com/my_bucket/folder/file.txt`)
	assert.NoError(t, err)
	assert.Equal(t, `folder/file.txt`, path)
	// Error: unknown domain.
	_, err = obj.getPath(`https://unknown-host.com/my_bucket/folder/file.txt`)
	assert.ErrorContains(t, err, `not allowed host: unknown-host.com`)
	// Error: unknown bucket.
	_, err = obj.getPath(`https://storage.cloud.google.com/not_my_bucket/folder/file.txt`)
	assert.ErrorIs(t, err, ErrUnknownBucket)
}
