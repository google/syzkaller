// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/sys/targets"
)

type KernelModule struct {
	Name string
	Addr uint64
	Size uint64
}

func discoverModules(target *targets.Target, objDir string, moduleObj []string,
	hostModules []KernelModule) (
	[]*Module, error) {
	modules := []*Module{
		// A dummy module representing the kernel itself.
		{Path: filepath.Join(objDir, target.KernelObject)},
	}
	if target.OS == targets.Linux {
		modules1, err := discoverModulesLinux(append([]string{objDir}, moduleObj...),
			hostModules)
		if err != nil {
			return nil, err
		}
		modules = append(modules, modules1...)
	} else if len(hostModules) != 0 {
		return nil, fmt.Errorf("%v coverage does not support modules", target.OS)
	}
	return modules, nil
}

func discoverModulesLinux(dirs []string, hostModules []KernelModule) ([]*Module, error) {
	paths, err := locateModules(dirs)
	if err != nil {
		return nil, err
	}
	var modules []*Module
	for _, mod := range hostModules {
		path := paths[mod.Name]
		if path == "" {
			log.Logf(0, "failed to discover module %v", mod.Name)
			continue
		}
		log.Logf(0, "module %v -> %v", mod.Name, path)
		modules = append(modules, &Module{
			Name: mod.Name,
			Addr: mod.Addr,
			Path: path,
		})
	}
	return modules, nil
}

func locateModules(dirs []string) (map[string]string, error) {
	paths := make(map[string]string)
	for _, dir := range dirs {
		err := filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {
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
