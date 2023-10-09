// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

type test struct{}

func (tb test) build(params Params) (ImageDetails, error) {
	return ImageDetails{}, nil
}

func (tb test) clean(string, string) error {
	return nil
}
