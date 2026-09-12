// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package gvisor contains helpers for working with gVisor images.
package gvisor

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

// Extract extracts the image into `dir` and returns the path to `runsc` in it.
func Extract(image, dir string) (string, error) {
	if err := osutil.MkdirAll(dir); err != nil {
		return "", err
	}
	if _, err := osutil.RunCmd(10*time.Minute, "", "tar", "-xf", image, "-C", dir); err != nil {
		return "", fmt.Errorf("failed to extract gVisor image %v (must be a gVisor release tarball): %w", image, err)
	}
	runsc := filepath.Join(dir, "runsc")
	if !osutil.IsExist(runsc) {
		return "", fmt.Errorf("gVisor image %v does not contain expected `runsc` binary", image)
	}
	return runsc, nil
}
