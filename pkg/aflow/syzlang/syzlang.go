// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package syzlang provides utilities and actions for parsing and analyzing syzlang descriptions.
package syzlang

import (
	"strings"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type BaseTestSeed struct {
	Path string
	Data string
}

func (s *BaseTestSeed) Load(syzkallerDir, osTarget string) error {
	if s.Path == "" {
		return nil
	}
	sysFS := NewSyzFS(syzkallerDir, osTarget)
	data, err := sysFS.ReadFile(s.Path)
	if err != nil {
		return err
	}
	s.Data = string(data)
	return nil
}

// CombineSyzPrograms concatenates a base test seed and a generated syz program.
// It returns the combined program, the number of lines in the base seed.
func CombineSyzPrograms(baseTestSeedData, generatedSyz string) (string, int) {
	if baseTestSeedData == "" {
		return generatedSyz, 0
	}
	baseLines := len(strings.Split(baseTestSeedData, "\n"))
	return baseTestSeedData + "\n" + generatedSyz, baseLines
}

// BaseSeedCallCount parses the base test seed data and returns the number of calls it contains.
func BaseSeedCallCount(baseTestSeedData []byte, targetArch string) (int, error) {
	if len(baseTestSeedData) == 0 {
		return 0, nil
	}
	pt, err := prog.GetTarget(targets.Linux, targetArch)
	if err != nil {
		return 0, err
	}
	p, err := pt.Deserialize(baseTestSeedData, prog.NonStrict)
	if err != nil {
		return 0, err
	}
	return len(p.Calls), nil
}
