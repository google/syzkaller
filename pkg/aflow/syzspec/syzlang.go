// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzspec

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func init() {
	// Used externally - do not remove.
	runtime.KeepAlive(CombineSyzPrograms)
	runtime.KeepAlive(BaseSeedCallCount)
	runtime.KeepAlive((*BaseTestSeed).Load)
}

type BaseTestSeed struct {
	Path string
	Data string
}

// Load populates Data by reading the test seed file from syzFS.
func (s *BaseTestSeed) Load(syzFS *SyzFS) error {
	if syzFS == nil {
		return fmt.Errorf("missing required argument: syzFS")
	}
	if s.Path == "" {
		return nil
	}
	data, err := syzFS.ReadFile(s.Path)
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
	baseLines := strings.Count(baseTestSeedData, "\n") + 1
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
