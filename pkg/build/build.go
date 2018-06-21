// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package build contains helper functions for building kernels/images.
package build

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

func CompilerIdentity(compiler string) (string, error) {
	arg := "--version"
	if strings.HasSuffix(compiler, "bazel") {
		arg = ""
	}
	output, err := osutil.RunCmd(time.Minute, "", compiler, arg)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "Extracting Bazel") {
			continue
		}
		return strings.TrimSpace(line), nil
	}
	return "", fmt.Errorf("no output from compiler --version")
}
