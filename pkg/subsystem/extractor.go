// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

// Extractor deduces the subsystems from the list of crashes.
type Extractor struct {
	raw rawExtractorInterface
}

// Crash represents the subset of the available crash information that's required for
// subsystem inference.
type Crash struct {
	GuiltyPath string
	SyzRepro   []byte
}

// rawExtractorInterface simplifies testing.
type rawExtractorInterface interface {
	FromPath(path string) []*Subsystem
	FromProg(progBytes []byte) []*Subsystem
}

func MakeExtractor(list []*Subsystem) *Extractor {
	return &Extractor{raw: makeRawExtractor(list)}
}

func (e *Extractor) Extract(crashes []*Crash) []*Subsystem {
	// First put all subsystems to the same list.
	subsystems := []*Subsystem{}
	for _, crash := range crashes {
		if crash.GuiltyPath != "" {
			subsystems = append(subsystems, e.raw.FromPath(crash.GuiltyPath)...)
		}
		if len(crash.SyzRepro) > 0 {
			subsystems = append(subsystems, e.raw.FromProg(crash.SyzRepro)...)
		}
	}

	// If there are both parents and children, remove parents.
	ignore := make(map[*Subsystem]struct{})
	for _, entry := range subsystems {
		for p := range entry.ReachableParents() {
			ignore[p] = struct{}{}
		}
	}

	// And calculate counts.
	counts := make(map[*Subsystem]int)
	maxCount := 0
	for _, entry := range subsystems {
		if _, ok := ignore[entry]; ok {
			continue
		}
		counts[entry]++
		if counts[entry] > maxCount {
			maxCount = counts[entry]
		}
	}

	// Pick the most prevalent ones.
	ret := []*Subsystem{}
	for entry, count := range counts {
		if count < maxCount {
			continue
		}
		ret = append(ret, entry)
	}
	return ret
}
