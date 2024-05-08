// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package executor

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"regexp"
)

//go:embed common*.h kvm*.h android/*.h
var src embed.FS

// CommonHeader contains all executor common headers used by pkg/csource to generate C reproducers.
// All includes in common.h are transitively replaced with their contents so that it's just a single blob.
var CommonHeader = func() []byte {
	data, err := src.ReadFile("common.h")
	if err != nil {
		panic(err)
	}
	headers := make(map[string]bool)
	for _, glob := range []string{"*.h", "android/*.h"} {
		files, err := fs.Glob(src, glob)
		if err != nil {
			panic(err)
		}
		for _, file := range files {
			if file == "common.h" || file == "common_ext_example.h" {
				continue
			}
			headers[file] = true
		}
	}
	// To not hardcode concrete order in which headers need to be replaced
	// we just iteratively try to replace whatever headers can be replaced.
	unused := maps.Clone(headers)
	for {
		relacedSomething := false
		for file := range headers {
			replace := []byte("#include \"" + path.Base(file) + "\"")
			if !bytes.Contains(data, replace) {
				replace = []byte("#include \"android/" + path.Base(file) + "\"")
				if !bytes.Contains(data, replace) {
					continue
				}
			}
			contents, err := src.ReadFile(file)
			if err != nil {
				panic(err)
			}
			data = bytes.ReplaceAll(data, replace, contents)
			delete(unused, file)
			relacedSomething = true
		}
		if !relacedSomething {
			break
		}
	}
	if len(unused) != 0 {
		panic(fmt.Sprintf("can't find includes for %v", unused))
	}
	// Remove `//` comments, but keep lines which start with `//%`.
	for _, remove := range []string{
		"(\n|^)\\s*//$",
		"(\n|^)\\s*//[^%].*",
		"\\s*//$",
		"\\s*//[^%].*",
	} {
		data = regexp.MustCompile(remove).ReplaceAll(data, nil)
	}
	return data
}()
