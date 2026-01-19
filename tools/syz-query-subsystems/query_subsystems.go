// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-query-subsystems generates and saves the subsystem lists in the format syzkaller understands.
// An example how to generate the linux subsystem list (for the upstream kernel).
// `./syz-query-subsystems -os linux -kernel ~/linux -syzkaller ~/syzkaller -name linux`.

package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/subsystem"
	"github.com/google/syzkaller/pkg/subsystem/linux"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/vcs"
)

var (
	flagOS            = flag.String("os", "", "target OS type")
	flagKernelRepo    = flag.String("kernel", "", "path to the OS kernel source directory")
	flagSyzkallerRepo = flag.String("syzkaller", "", "path to the syzkaller repo")
	flagName          = flag.String("name", "", "the name under which the list should be saved")
	flagFilter        = flag.String("filter", "", "comma-separated list of subsystems to keep")
	flagEmails        = flag.Bool("emails", true, "save lists and maintainer fields")
	flagDebug         = flag.Bool("debug", false, "print the debugging information")
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
	list, debugInfo, err := linux.ListFromRepo(*flagKernelRepo)
	if err != nil {
		tool.Failf("failed to query subsystems: %v", err)
	}
	printDebugInfo(debugInfo)
	list = postProcessList(list)
	// Save the list.
	folder := filepath.Join(*flagSyzkallerRepo, "pkg", "subsystem", "lists")
	if err = osutil.MkdirAll(folder); err != nil {
		tool.Failf("failed to create %s: %v", folder, err)
	}
	commitInfo, err := determineCommitInfo(*flagKernelRepo)
	if err != nil {
		tool.Failf("failed to fetch commit info: %v", err)
	}
	code, err := generateSubsystemsFile(*flagName, list, commitInfo, debugInfo)
	if err != nil {
		tool.Failf("failed to generate code: %s", err)
	}
	err = osutil.WriteFile(filepath.Join(folder, *flagName+".go"), code)
	if err != nil {
		tool.Failf("failed to save the code: %s", err)
	}
}

func printDebugInfo(info *subsystem.DebugInfo) {
	if !*flagDebug {
		return
	}
	for item, list := range info.FileLists {
		fmt.Printf("****\n")
		fmt.Printf("Subsystem %q (%d paths)\n", item.Name, len(list))
		for _, path := range list {
			fmt.Printf("%s\n", path)
		}
	}
}

func postProcessList(list []*subsystem.Subsystem) []*subsystem.Subsystem {
	if *flagFilter != "" {
		list = subsystem.FilterList(list, prepareFilter())
	}
	if !*flagEmails {
		for _, item := range list {
			item.Lists = nil
			item.Maintainers = nil
		}
	}
	return list
}

func prepareFilter() func(*subsystem.Subsystem) bool {
	keep := map[string]bool{}
	for _, name := range strings.Split(*flagFilter, ",") {
		name = strings.TrimSpace(name)
		if name != "" {
			keep[name] = true
		}
	}
	return func(s *subsystem.Subsystem) bool {
		return keep[s.Name]
	}
}

func determineCommitInfo(dir string) (*vcs.Commit, error) {
	repo, err := vcs.NewRepo(*flagOS, "", dir, vcs.OptPrecious, vcs.OptDontSandbox)
	if err != nil {
		return nil, fmt.Errorf("failed to open repo: %w", err)
	}
	commit, err := repo.Commit(vcs.HEAD)
	if err != nil {
		return nil, fmt.Errorf("failed to get HEAD commit: %w", err)
	}
	return commit, err
}
