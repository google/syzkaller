// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
)

// CleanPath normalizes the raw file path from DWARF and returns its relative display path
// and its absolute path on the host. It attempts to strip build prefixes such as
// the object directory or the build source directory, falling back to treating it
// as relative to the source directory. It also handles special Android build paths.
func CleanPath(path string, kernelDirs *mgrconfig.KernelDirs, splitBuildDelimiters []string) (relPath, absPath string) {
	path = filepath.Clean(path)
	aname, apath := cleanPathAndroid(path, kernelDirs.Src, splitBuildDelimiters, osutil.IsExist)
	if aname != "" {
		return aname, apath
	}
	abs := osutil.Abs(path)
	objDir := kernelDirs.Obj
	if objDir == "" {
		objDir = kernelDirs.Src
	}
	switch {
	case objDir != "" && strings.HasPrefix(abs, objDir):
		// Assume the file was built there.
		path = strings.TrimPrefix(abs, objDir)
		absPath = filepath.Join(objDir, path)
	case kernelDirs.Src != "" && strings.HasPrefix(abs, kernelDirs.Src):
		path = strings.TrimPrefix(abs, kernelDirs.Src)
		absPath = filepath.Join(kernelDirs.Src, path)
	case kernelDirs.BuildSrc != "" && strings.HasPrefix(abs, kernelDirs.BuildSrc):
		// Assume the file was moved from buildDir to srcDir.
		path = strings.TrimPrefix(abs, kernelDirs.BuildSrc)
		absPath = filepath.Join(kernelDirs.Src, path)
	default:
		// Assume this is relative path.
		if filepath.IsAbs(path) {
			absPath = path
		} else {
			absPath = filepath.Join(kernelDirs.Src, path)
		}
	}
	relPath = strings.TrimLeft(filepath.Clean(path), "/\\")
	return relPath, absPath
}

// Source files for Android may be split between two subdirectories: the common AOSP kernel
// and the device-specific drivers: https://source.android.com/docs/setup/build/building-pixel-kernels.
// Android build system references these subdirectories in various ways, which often results in
// paths to non-existent files being recorded in the debug info.
//
// cleanPathAndroid() assumes that the subdirectories reside in `srcDir`, with their names being listed in
// `delimiters`.
// If one of the `delimiters` occurs in the `path`, it is stripped together with the path prefix, and the
// remaining file path is appended to `srcDir + delimiter`.
// If none of the `delimiters` occur in the `path`, `path` is treated as a relative path that needs to be
// looked up in `srcDir + delimiters[i]`.
func cleanPathAndroid(path, srcDir string, delimiters []string, existFn func(string) bool) (string, string) {
	if len(delimiters) == 0 {
		return "", ""
	}
	reStr := "(" + strings.Join(delimiters, "|") + ")(.*)"
	re := regexp.MustCompile(reStr)
	match := re.FindStringSubmatch(path)
	if match != nil {
		delimiter := match[1]
		filename := match[2]
		path := filepath.Clean(srcDir + delimiter + filename)
		return filename, path
	}
	// None of the delimiters found in `path`: it is probably a relative path to the source file.
	// Try to look it up in every subdirectory of srcDir.
	for _, delimiter := range delimiters {
		absPath := filepath.Clean(srcDir + delimiter + path)
		if existFn(absPath) {
			return path, absPath
		}
	}
	return "", ""
}
