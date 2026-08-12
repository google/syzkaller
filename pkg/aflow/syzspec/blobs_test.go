// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzspec

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBlobPlaceholders(t *testing.T) {
	var store BlobStore
	input := `syz_mount_image$btrfs(&AUTO='btrfs\x00', &AUTO='./file0\x00', 0x0, &AUTO, 0x1, AUTO, &AUTO="$` +
		`eJzs3W2MXFX9B/Azs9tt2f8/ZosBAV/ULpCgpLRsLLpUdgcSiqSBTAAToEALWqG2` +
		`PENQHsJQCVqxYbVWUwOKbCIuQWgTbSUUGWEp2LRhu4AWi1QUFUJAI1LQQjTcuWd2` +
		`5s7O7gZDW+DzaWbOPfM759xzLzdh+uI7DQ==")`

	// Test ReplaceBlobs.
	replaced := store.ReplaceBlobs(input)
	// The length of the output should be much smaller.
	require.Less(t, len(replaced), len(input))
	require.Contains(t, replaced, "$BLOB_")
	require.NotContains(t, replaced, "$eJ")

	// Test RestoreBlobs.
	restored := store.RestoreBlobs(replaced)
	require.Equal(t, input, restored)
}

func TestMultipleBlobs(t *testing.T) {
	var store BlobStore
	input := `syz_mount_image$btrfs(&AUTO="$` +
		`eJzs3W2MXFX9B/Azs9tt2f8/ZosBAV/ULpCgpLRsLLpUdgcSiqSBTAAToEALWqG2` +
		`PENQHsJQCVqxYbVWUwOKbCIuQWgTbSUUGWEp2LRhu4AWi1QUFUJAI1LQQjTcuWd2` +
		`5s7O7gZDW+DzaWbOPfM759xzLzdh+uI7DQ==")
syz_mount_image$f2fs(&AUTO="$` +
		`eJzs3D9vG2UcB/DfNbQCWkqEGNh4JEByJGKd7aSCskRUVQdIFdEyMji2Y7lN7ChO` +
		`nNCJhT8vgg0m3gMvgI2lQ98BEhsSS4UE8t0FoYqhgInB+Xyku+/dc9ffc491y+9U` +
		`JYBzazn9/FMWV+O5iFiKiCsRxXFWbYWNMl6JiFcj4sIftqwa/33gUkQ8HxFXp8XL` +
		`mll16atvP/vo6x/ee+PLb75byr/4/Mf5rRqYt9cjYm+/PD7eK3PUL/NeNd6eDIrc` +
		`W5tUWV7Yu1+dj8o87m0XFY7bp/e1i2z1y/tH+0fjae7stjvT7A92ivH9YTnheNI/` +
		`rVP8g3vtg+K829sucjAeFdl/UD7XSZUPxodlnW5V7+OifBwenmY53jvplevZv19k` +
		`Z3hYjZd1R93eyTQnVVbTRXf77/++/xfvD4ZHJ2nSOxgPRsO0Xm/k9Xz1oHNtNc8b` +
		`b7dW+932Tudar7nWbe+spVpvYzzaXUm1fqeTardu3FhJjbzerOdvplu3P0y73VSb` +
		`5ruD4dHhYHe8kpr11nq9sZJea6Q7m1tp64ObNze37qbN0TDdHk1SK0+N1vX15vXW` +
		`2nrzt3UzJu59Z+p7IznY8F4gQD+Mv0/MA/6f/1/6H/P/fq1b/wjXi==")`

	replaced := store.ReplaceBlobs(input)
	require.Contains(t, replaced, "$BLOB_")

	restored := store.RestoreBlobs(replaced)
	require.Equal(t, input, restored)
}

func TestNonCompressedBase64Blob(t *testing.T) {
	var store BlobStore
	// Non-compressed base64 blob >= 128 chars.
	nonCompressedB64 := `"$SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IG9mIGEgbm9uLWNvbXByZXNzZWQg` +
		`YmFzZTY0IGJsb2IgdGhhdCBpcyBsb25nIGVub3VnaCB0byBleGNlZWQgdGhlIDEyOCBjaGFyYWN0ZXIgdGhyZXNob2xkLi4u"`
	input := `syz_mount_image$ext4(&AUTO=` + nonCompressedB64 + `)`

	replaced := store.ReplaceBlobs(input)
	require.Contains(t, replaced, "$BLOB_")
	require.NotContains(t, replaced, "SGVsbG8gV29ybGQh")

	restored := store.RestoreBlobs(replaced)
	require.Equal(t, input, restored)
}

func TestShortStringNotReplaced(t *testing.T) {
	var store BlobStore
	// String shorter than minBlobLen (128) should be kept as-is.
	input := `syz_mount_image$btrfs(&AUTO='btrfs\x00', &AUTO="./short_file_path\x00")`
	replaced := store.ReplaceBlobs(input)
	require.Equal(t, input, replaced)
}

func TestZeroValueBlobStore(t *testing.T) {
	var store BlobStore
	input := `syz_mount_image$btrfs(&AUTO="$` +
		`eJzs3W2MXFX9B/Azs9tt2f8/ZosBAV/ULpCgpLRsLLpUdgcSiqSBTAAToEALWqG2` +
		`PENQHsJQCVqxYbVWUwOKbCIuQWgTbSUUGWEp2LRhu4AWi1QUFUJAI1LQQjTcuWd2` +
		`5s7O7gZDW+DzaWbOPfM759xzLzdh+uI7DQ==")`

	// Should work safely with empty/nil map on RestoreBlobs.
	require.Equal(t, "unrelated text", store.RestoreBlobs("unrelated text"))

	// Should lazily initialize on ReplaceBlobs.
	replaced := store.ReplaceBlobs(input)
	require.Contains(t, replaced, "$BLOB_")

	restored := store.RestoreBlobs(replaced)
	require.Equal(t, input, restored)
}
