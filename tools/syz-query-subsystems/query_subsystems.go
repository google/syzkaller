// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-query-subsystems generates and saves the subsystem lists in the format syzkaller understands.
// An example how to generate the linux subsystem list (for the upstream kernel).
// `./syz-query-subsystems -os linux -kernel ~/linux -syzkaller ~/syzkaller -name linux`.

package main

import (
	"flag"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/subsystem/linux"
	"github.com/google/syzkaller/pkg/tool"
)

var (
	flagOS            = flag.String("os", "", "target OS type")
	flagKernelRepo    = flag.String("kernel", "", "path to the OS kernel source directory")
	flagSyzkallerRepo = flag.String("syzkaller", "", "path to the syzkaller repo")
	flagName          = flag.String("name", "", "the name under which the list should be saved")
)

var nameRe = regexp.MustCompile(`^[a-z]\w*$`)

func main() {
	defer tool.Init()()
	// Validate the input.
	if strings.ToLower(*flagOS) != "linux" {
		tool.Failf("only Linux is supported at the moment")
	}
	if !osutil.IsExist(*flagKernelRepo) {
		tool.Failf("the specified kernel repo does not exist")
	}
	if !osutil.IsExist(*flagSyzkallerRepo) {
		tool.Failf("the specified syzkaller repo does not exist")
	}
	if !nameRe.MatchString(*flagName) {
		tool.Failf("the name is not acceptable")
	}
	// Query the subsystems.
	list, err := linux.ListFromRepo(*flagKernelRepo)
	if err != nil {
		tool.Failf("failed to query subsystems: %v", err)
	}
	// Save the list.
	folder := filepath.Join(*flagSyzkallerRepo, "pkg", "subsystem", "lists")
	if err = osutil.MkdirAll(folder); err != nil {
		tool.Failf("failed to create %s: %v", folder, err)
	}
	code, err := generateSubsystemsFile(*flagName, list)
	if err != nil {
		tool.Failf("failed to generate code: %s", err)
	}
	err = osutil.WriteFile(filepath.Join(folder, *flagName+".go"), code)
	if err != nil {
		tool.Failf("failed to save the code: %s", err)
	}
}
