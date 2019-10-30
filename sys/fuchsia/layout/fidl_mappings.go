// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package layout

import (
	"fmt"
	"path/filepath"
	"strings"
)

// layer indicates at which layer a FidlLibrary lives in the Fuchsia build
// system.
type layer int

const (
	_ layer = iota
	zircon
	garnet
)

// FidlLibrary describes a FIDL library. It captures required details such as
// build location, header generation, etc.
type FidlLibrary struct {
	layer layer

	// FqName stores the fully-qualified name of the library in parts, e.g.
	// the `fuchsia.mem` library is `fuchsia`, `mem`.
	FqName []string
}

// AllFidlLibraries lists all FIDL libraries.
var AllFidlLibraries = []FidlLibrary{
	{zircon, []string{"fuchsia", "mem"}},
	{zircon, []string{"fuchsia", "cobalt"}},
	{zircon, []string{"fuchsia", "ldsvc"}},
	{zircon, []string{"fuchsia", "process"}},
	{zircon, []string{"fuchsia", "io"}},
	{zircon, []string{"fuchsia", "net"}},
	{zircon, []string{"fuchsia", "hardware", "ethernet"}},
	{garnet, []string{"fuchsia", "devicesettings"}},
	{garnet, []string{"fuchsia", "net", "stack"}},
	{garnet, []string{"fuchsia", "timezone"}},
	{garnet, []string{"fuchsia", "scpi"}},
}

func (fidlLib FidlLibrary) dirName() string {
	switch fidlLib.layer {
	case zircon:
		return strings.Join(fidlLib.FqName, "-")
	case garnet:
		return strings.Join(fidlLib.FqName, ".")
	default:
		panic(fmt.Sprintf("unknown layer %v", fidlLib.layer))
	}
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
	switch fidlLib.layer {
	case zircon:
		return filepath.Join("fidling", "gen", "zircon", "system", "fidl", fidlLib.dirName())
	case garnet:
		return filepath.Join("fidling", "gen", "sdk", "fidl", fidlLib.dirName())
	default:
		panic(fmt.Sprintf("unknown layer %v", fidlLib.layer))
	}
}
