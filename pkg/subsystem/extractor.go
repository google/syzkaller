// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// TODO: on the bug page, add a [debug subsystem assignment] link.
// Only show it for admins.
// The link runs subsystem assignment for the bug and returns the output.

package subsystem

import (
	"math"
	"strings"

	"github.com/google/syzkaller/pkg/debugtracer"
)

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
	return e.TracedExtract(crashes, &debugtracer.NullTracer{})
}

func (e *Extractor) TracedExtract(crashes []*Crash, tracer debugtracer.DebugTracer) []*Subsystem {
	// First put all subsystems to the same list.
	subsystems := []*Subsystem{}
	reproCount := 0
	for i, crash := range crashes {
		if crash.GuiltyPath != "" {
			extracted := e.raw.FromPath(crash.GuiltyPath)
			tracer.Log("Crash #%d: guilty=%s subsystems=%s", i+1,
				crash.GuiltyPath, e.readableSubsystems(extracted))
			subsystems = append(subsystems, extracted...)
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
	for i, crash := range crashes {
		if len(crash.SyzRepro) == 0 {
			continue
		}
		reproSubsystems := e.raw.FromProg(crash.SyzRepro)
		tracer.Log("Crash #%d: repro subsystems=%s", i+1, e.readableSubsystems(reproSubsystems))
		for _, subsystem := range reproSubsystems {
			reproCounts[subsystem]++
			if reproCounts[subsystem] == reproCount {
				tracer.Log("Subsystem %s exists in all reproducers", subsystem.Name)
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
					tracer.Log("Picking %s because %s is one of its parents",
						reproSubsystem.Name, subsystem.Name)
					newSubsystems = append(newSubsystems, reproSubsystem)
					break
				}
			}
		}
		if len(newSubsystems) > 0 {
			// Just pick those subsystems.
			tracer.Log("Set %s because they appear both in repros and stack tracex",
				e.readableSubsystems(newSubsystems))
			return newSubsystems
		}

		// If there are sufficiently many reproducers that point to subsystems other than
		// those from guilty paths, there's a chance we just didn't parse report correctly.
		const cutOff = 3
		if reproCount >= cutOff {
			// But if the guilty paths are non-controversial, also take the leading candidate.
			fromStacks := mostVoted(counts, 0.66)
			tracer.Log("There are %d reproducers, so take %s from them and %s from stack traces",
				reproCount, e.readableSubsystems(fromRepro), e.readableSubsystems(fromStacks))
			return append(fromRepro, fromStacks...)
		}
	}

	// Take subsystems from reproducers into account.
	for _, entry := range fromRepro {
		counts[entry] += reproCount
	}

	// Let's pick all subsystems that received >= 33% of votes (thus no more than 3).
	afterVoting := mostVoted(counts, 0.33)
	tracer.Log("Take %s from voting results", e.readableSubsystems(afterVoting))
	return removeParents(afterVoting)
}

func (e *Extractor) readableSubsystems(list []*Subsystem) string {
	var names []string
	for _, item := range list {
		names = append(names, item.Name)
	}
	return strings.Join(names, ", ")
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
