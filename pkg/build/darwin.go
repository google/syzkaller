// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
)

type darwin struct{}

func (ctx darwin) build(params Params) (ImageDetails, error) {
	// TODO(HerrSpace): Implement this.
	return ImageDetails{}, fmt.Errorf("pkg/build: darwin.build not implemented")
}

func (ctx darwin) clean(kernelDir, targetArch string) error {
	// TODO(HerrSpace): Implement this.
	return fmt.Errorf("pkg/build: darwin.build not implemented")
}
