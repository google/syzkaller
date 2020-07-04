// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build tools

// tools is not a normal package, it's only purpose is tools dependency management.
// It allows us to vendor all used tools, ensure that all contributors have the same versions of tools,
// and have custom golangci-lint checkers.
package tools

import (
	_ "github.com/dvyukov/go-fuzz/go-fuzz-build"
	_ "github.com/dvyukov/go-fuzz/go-fuzz-dep"
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
)
