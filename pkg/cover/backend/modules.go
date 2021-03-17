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

	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/sys/targets"
)

func discoverModules(target *targets.Target, objDir string, moduleObj []string, hostModules []host.KernelModule) (
	[]*Module, error) {
	modules := []*Module{
		{Path: filepath.Join(objDir, target.KernelObject)},
	}
	if target.OS == targets.Linux {
		modules1, err := discoverModulesLinux(append([]string{objDir}, moduleObj...), hostModules)
		if err != nil {
			return nil, err
		}
		modules = append(modules, modules1...)
	} else if len(hostModules) != 0 {
		return nil, fmt.Errorf("%v coverage does not support modules", target.OS)
	}
	return modules, nil
}

func discoverModulesLinux(dirs []string, hostModules []host.KernelModule) ([]*Module, error) {
	byName := make(map[string]host.KernelModule)
	for _, mod := range hostModules {
		byName[mod.Name] = mod
	}
	var modules []*Module
	files := findModulePaths(dirs)
	for _, path := range files {
		name := strings.TrimSuffix(filepath.Base(path), ".ko")
		if mod, ok := byName[name]; ok {
			delete(byName, name)
			modules = append(modules, &Module{
				Name: mod.Name,
				Addr: mod.Addr,
				Path: path,
			})
			continue
		}
		name, err := getModuleName(path)
		if err != nil {
			log.Logf(0, "failed to get module name for %v: %v", path, err)
			continue
		}
		if name == "" {
			continue
		}
		if mod, ok := byName[name]; ok {
			delete(byName, name)
			modules = append(modules, &Module{
				Name: mod.Name,
				Addr: mod.Addr,
				Path: path,
			})
		}
	}
	log.Logf(0, "kernel modules: %v", modules)
	return modules, nil
}

func findModulePaths(dirs []string) []string {
	var files []string
	for _, path := range dirs {
		mfiles, err := walkModulePath(path)
		if err != nil {
			log.Logf(0, "failed to find modules in %v: %v", path, err)
			continue
		}
		files = append(files, mfiles...)
	}
	return files
}

func walkModulePath(dir string) ([]string, error) {
	files := []string{}
	err := filepath.Walk(dir, func(path string, f os.FileInfo, err error) error {
		if filepath.Ext(path) == ".ko" {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func getModuleName(path string) (string, error) {
	file, err := elf.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open %v: %v", path, err)
	}
	defer file.Close()
	section := file.Section(".modinfo")
	if section == nil {
		return "", fmt.Errorf("no .modinfo section")
	}
	data, err := section.Data()
	if err != nil {
		return "", fmt.Errorf("failed to read .modinfo")
	}
	name := searchModuleName(data)
	if name == "" {
		section = file.Section(".gnu.linkonce.this_module")
		if section == nil {
			return "", fmt.Errorf("no .gnu.linkonce.this_module section")
		}
		data, err = section.Data()
		if err != nil {
			return "", fmt.Errorf("failed to read .gnu.linkonce.this_module: %v", err)
		}
		name = string(data)
	}
	return name, nil
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
