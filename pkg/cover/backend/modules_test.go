// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"flag"
	"testing"
)

var flagModuleDir = flag.String("module_dir", "", "directory to discover modules")

func TestLocateModules(t *testing.T) {
	// Dump modules discovered in a dir, not really an automated test, use as:
	// go test -run TestLocateModules -v ./pkg/cover/backend -module_dir=/linux/build/dir
	if *flagModuleDir == "" {
		t.Skip("no module dir specified")
	}
	paths, err := locateModules([]string{*flagModuleDir})
	if err != nil {
		t.Fatal(err)
	}
	for name, path := range paths {
		t.Logf("%32v -> %v", name, path)
	}
}
