// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package layout

import (
	"fmt"
	"path/filepath"
	"strings"
)

// FidlLibrary is the fully-qualified name of a FIDL library.
type FidlLibrary []string

// AllFidlLibraries lists all FIDL libraries.
var AllFidlLibraries = []FidlLibrary{
	{"fuchsia", "cobalt"},
	{"fuchsia", "devicesettings"},
	{"fuchsia", "hardware", "ethernet"},
	{"fuchsia", "io"},
	{"fuchsia", "ldsvc"},
	{"fuchsia", "mem"},
	{"fuchsia", "net"},
	{"fuchsia", "process"},
	{"fuchsia", "scpi"},
}

func (fidlLib FidlLibrary) dirName() string {
	return strings.Join(fidlLib, ".")
}

// PathToJSONIr provides the path to the JSON IR, relative to the out/<arch>
// directory.
func (fidlLib FidlLibrary) PathToJSONIr() string {
	return filepath.Join(
		fidlLib.PathToCompiledDir(),
		fmt.Sprintf("%s.fidl.json", fidlLib.dirName()))
}

// PathToCompiledDir provides the path to compiled headers, relative to the
// out/<arch> directory.
func (fidlLib FidlLibrary) PathToCompiledDir() string {
	return filepath.Join("fidling", "gen", "sdk", "fidl", fidlLib.dirName())
}
