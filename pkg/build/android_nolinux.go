// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !linux
// +build !linux

package build

import (
	"errors"
)

func buildCuttlefishImage(params Params, bzImage, vmlinux, initramfs string) error {
	return errors.New("building android cuttlefish image is only supported on linux")
}
