// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/sys/targets"
)

func DiscoverModules(target *targets.Target, objDir string, moduleObj []string) (
	[]*vminfo.KernelModule, error) {
	module := &vminfo.KernelModule{
		Path: filepath.Join(objDir, target.KernelObject),
	}
	textRange, err := elfReadTextSecRange(module)
	if err != nil {
		return nil, err
	}
	modules := []*vminfo.KernelModule{
		// A dummy module representing the kernel itself.
		{
			Path: module.Path,
			Size: textRange.End - textRange.Start,
		},
	}
	if target.OS == targets.Linux {
		modules1, err := discoverModulesLinux(append([]string{objDir}, moduleObj...))
		if err != nil {
			return nil, err
		}
		modules = append(modules, modules1...)
	} else if len(modules) != 1 {
		return nil, fmt.Errorf("%v coverage does not support modules", target.OS)
	}
	return modules, nil
}

func discoverModulesLinux(dirs []string) ([]*vminfo.KernelModule, error) {
	paths, err := locateModules(dirs)
	if err != nil {
		return nil, err
	}
	var modules []*vminfo.KernelModule
	for name, path := range paths {
		if path == "" {
			continue
		}
		log.Logf(2, "module %v -> %v", name, path)
		module := &vminfo.KernelModule{
			Name: name,
			Path: path,
		}
		textRange, err := elfReadTextSecRange(module)
		if err != nil {
			return nil, err
		}
		module.Size = textRange.End - textRange.Start
		modules = append(modules, module)
	}
	return modules, nil
}

func locateModules(dirs []string) (map[string]string, error) {
	paths := make(map[string]string)
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || filepath.Ext(path) != ".ko" {
				return err
			}
			name, err := getModuleName(path)
			if err != nil {
				// Extracting module name involves parsing ELF and binary data,
				// let's not fail on it, we still have the file name,
				// which is usually the right module name.
				log.Logf(0, "failed to get %v module name: %v", path, err)
				name = strings.TrimSuffix(filepath.Base(path), "."+filepath.Ext(path))
			}
			// Order of dirs determine priority, so don't overwrite already discovered names.
			if name != "" && paths[name] == "" {
				paths[name] = path
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return paths, nil
}

func getModuleName(path string) (string, error) {
	file, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	section := file.Section(".modinfo")
	if section == nil {
		return "", fmt.Errorf("no .modinfo section")
	}
	data, err := section.Data()
	if err != nil {
		return "", fmt.Errorf("failed to read .modinfo: %w", err)
	}
	if name := searchModuleName(data); name != "" {
		return name, nil
	}
	section = file.Section(".gnu.linkonce.this_module")
	if section == nil {
		return "", fmt.Errorf("no .gnu.linkonce.this_module section")
	}
	data, err = section.Data()
	if err != nil {
		return "", fmt.Errorf("failed to read .gnu.linkonce.this_module: %w", err)
	}
	return string(data), nil
}

func searchModuleName(data []byte) string {
	data = append([]byte{0}, data...)
	key := []byte("\x00name=")
	pos := bytes.Index(data, key)
	if pos == -1 {
		return ""
	}
	end := bytes.IndexByte(data[pos+len(key):], 0)
	if end == -1 {
		return ""
	}
	end = pos + len(key) + end
	if end > len(data) {
		return ""
	}
	return string(data[pos+len(key) : end])
}

func getKaslrOffset(modules []*vminfo.KernelModule, pcBase uint64) uint64 {
	for _, mod := range modules {
		if mod.Name == "" {
			return mod.Addr - pcBase
		}
	}
	return 0
}

// when CONFIG_RANDOMIZE_BASE=y, pc from kcov already removed kaslr_offset.
func FixModules(localModules, modules []*vminfo.KernelModule, pcBase uint64) []*vminfo.KernelModule {
	kaslrOffset := getKaslrOffset(modules, pcBase)
	var modules1 []*vminfo.KernelModule
	for _, mod := range modules {
		size := uint64(0)
		path := ""
		for _, modA := range localModules {
			if modA.Name == mod.Name {
				size = modA.Size
				path = modA.Path
				break
			}
		}
		if path == "" {
			continue
		}
		addr := mod.Addr - kaslrOffset
		modules1 = append(modules1, &vminfo.KernelModule{
			Name: mod.Name,
			Size: size,
			Addr: addr,
			Path: path,
		})
	}
	return modules1
}
