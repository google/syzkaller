// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
)

type android struct{}

func (a android) build(params Params) (ImageDetails, error) {
	return ImageDetails{}, fmt.Errorf("not implemented for Android")
}

func (a android) clean(kernelDir, targetArch string) error {
	return fmt.Errorf("not implemented for Android")
}
