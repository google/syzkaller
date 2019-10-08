// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

// TypeBuilder implements the builder interface.
type testBuilder struct{}

func (tb testBuilder) build(targetArch, vmType, kernelDir, outputDir, compiler, userspaceDir,
	cmdlineFile, sysctlFile string, config []byte) error {
	return nil
}

func (tb testBuilder) clean(string, string) error {
	return nil
}
