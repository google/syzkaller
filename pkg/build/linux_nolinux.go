// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !linux
// +build !linux

package build

import (
	"errors"
)

func embedLinuxKernel(params Params, kernelPath string) error {
	return errors.New("building linux image is only supported on linux")
}

func embedFiles(params Params, callback func(mountDir string) error) error {
	return errors.New("building linux image is only supported on linux")
}
