// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"path/filepath"
	"strings"
)

func init() {
	machineGlobsInfo = getGlobsInfo
}

func getGlobsInfo(globs map[string]bool) (map[string][]string, error) {
	var err error
	files := make(map[string][]string, len(globs))
	for glob := range globs {
		var (
			addglobs []string
			subglobs []string
			matches  []string
		)
		tokens := strings.Split(glob, ":")
		for _, tok := range tokens {
			if strings.HasPrefix(tok, "-") {
				subglobs = append(subglobs, tok[1:])
			} else {
				addglobs = append(addglobs, tok)
			}
		}
		for _, g := range addglobs {
			m, err := filepath.Glob(g)
			if err != nil {
				return nil, err
			}
			matches = append(matches, m...)
		}
		files[glob], err = excludeGlobs(removeDupValues(matches), subglobs)
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}

func excludeGlobs(items, subglobs []string) ([]string, error) {
	var results []string
	excludes := make(map[string]bool)
	for _, glob := range subglobs {
		matches, err := filepath.Glob(glob)
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			excludes[m] = true
		}
	}

	for _, item := range items {
		if !excludes[item] {
			results = append(results, item)
		}
	}
	return results, nil
}

func removeDupValues(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if !keys[entry] {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
