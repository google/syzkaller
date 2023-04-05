// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import "math"

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
	reproCount := 0
	for _, crash := range crashes {
		if crash.GuiltyPath != "" {
			subsystems = append(subsystems, e.raw.FromPath(crash.GuiltyPath)...)
		}
		if len(crash.SyzRepro) != 0 {
			reproCount++
		}
	}
	subsystems = removeParents(subsystems)
	counts := make(map[*Subsystem]int)
	for _, entry := range subsystems {
		counts[entry]++
	}

	// If all reproducers hint at the same subsystem, take it as well.
	reproCounts := map[*Subsystem]int{}
	fromRepro := []*Subsystem{}
	for _, crash := range crashes {
		if len(crash.SyzRepro) == 0 {
			continue
		}
		for _, subsystem := range e.raw.FromProg(crash.SyzRepro) {
			reproCounts[subsystem]++
			if reproCounts[subsystem] == reproCount {
				fromRepro = append(fromRepro, subsystem)
			}
		}
	}
	// It can be the case that guilty paths point to several subsystems, but the reproducer
	// can clearly point to one of them.
	// Let's consider it to be the strongest singal.
	if len(fromRepro) > 0 {
		fromRepro = removeParents(fromRepro)
		newSubsystems := []*Subsystem{}
		for _, reproSubsystem := range fromRepro {
			parents := reproSubsystem.ReachableParents()
			parents[reproSubsystem] = struct{}{} // also include the subsystem itself
			for _, subsystem := range subsystems {
				if _, ok := parents[subsystem]; ok {
					newSubsystems = append(newSubsystems, reproSubsystem)
					break
				}
			}
		}
		if len(newSubsystems) > 0 {
			// Just pick those subsystems.
			return newSubsystems
		}

		// If there are sufficiently many reproducers that point to subsystems other than
		// those from guilty paths, there's a chance we just didn't parse report correctly.
		const cutOff = 3
		if reproCount >= cutOff {
			// But if the guilty paths are non-controversial, also take the leading candidate.
			return append(fromRepro, mostVoted(counts, 0.66)...)
		}
	}

	// Take subsystems from reproducers into account.
	for _, entry := range fromRepro {
		counts[entry] += reproCount
	}

	// Let's pick all subsystems that received >= 33% of votes (thus no more than 3).
	return removeParents(mostVoted(counts, 0.33))
}

// mostVoted picks subsystems that have received >= share votes.
func mostVoted(counts map[*Subsystem]int, share float64) []*Subsystem {
	total := 0
	for _, count := range counts {
		total += count
	}
	cutOff := int(math.Ceil(share * float64(total)))
	ret := []*Subsystem{}
	for entry, count := range counts {
		if count < cutOff {
			continue
		}
		ret = append(ret, entry)
	}
	return ret
}

func removeParents(subsystems []*Subsystem) []*Subsystem {
	// If there are both parents and children, remove parents.
	ignore := make(map[*Subsystem]struct{})
	for _, entry := range subsystems {
		for p := range entry.ReachableParents() {
			ignore[p] = struct{}{}
		}
	}
	var ret []*Subsystem
	for _, entry := range subsystems {
		if _, ok := ignore[entry]; ok {
			continue
		}
		ret = append(ret, entry)
	}
	return ret
}
