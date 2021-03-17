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
)

func getModules(dirs []string, modules []*Module) {
	byName := make(map[string]*Module)
	for _, mod := range modules {
		byName[mod.Name] = mod
	}
	files := findModulePaths(dirs)
	for _, path := range files {
		name := strings.TrimSuffix(filepath.Base(path), ".ko")
		if module := byName[name]; module != nil {
			if module.Path != "" {
				continue
			}
			module.Path = path
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
		if module := byName[name]; module != nil {
			if module.Path != "" {
				continue
			}
			module.Path = path
		}
	}
	log.Logf(0, "kernel modules: %v", modules)
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
