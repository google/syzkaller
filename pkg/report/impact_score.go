
package report

import (
	"sort"

	"github.com/google/syzkaller/pkg/report/crash"
)

// impactOrder represent an ordering of bug impact severity. The earlier
// entries are considered more severe.
var impactOrder = []crash.Type{
	// Highest Priority (Direct Memory Corruption - Write)
	crash.KASANUseAfterFreeWrite,
	crash.KASANWrite,
	// High Priority (Memory Corruption)
	crash.KASANInvalidFree,
	crash.KFENCEInvalidFree,
	crash.KFENCEMemoryCorruption,
	crash.KASANUseAfterFreeRead,
	crash.KMSANUseAfterFreeRead,
	crash.KASANRead,
	crash.KFENCERead,
	crash.MemorySafetyUBSAN, // array-index-out-of-bounds, at least Read.
	crash.KCSANAssert,
	crash.RefcountWARNING, // we had a few UAFs in the past
	crash.KASANNullPtrDerefWrite,
	crash.KASANNullPtrDerefRead,
	crash.NullPtrDerefBUG,
	// Medium Priority (Infoleaks, Uninitialized Memory, Corruptions)
	crash.KMSANInfoLeak,
	crash.MemorySafetyBUG,
	crash.KMSANUninitValue,
	// Medium Priority (Concurrency and Severe Instability)
	crash.KCSANDataRace,
	crash.AtomicSleep, // high potential for system-wide deadlocks
	crash.LockdepBug,  // indicates potential deadlocks and hangs
	// Lower-Medium Priority (Denial of Service and General Bugs)
	crash.MemoryLeak, // a form of DoS
	crash.DoS,
	crash.Hang,
	// Unknown types shouldn't be mentioned here. If bug goes to Unknown it means we need better parsing/processing.
	// You can find them at the end of the scored list on the bug enumeration pages.
	// crash.KMSANUnknown
	// crash.KASANUnknown
	// crash.KCSANUnknown
}

// TitlesToImpact converts a bug title(s) to an impact score.
// If several titles provided, it returns the highest score.
// A higher score indicates a more severe impact.
// -1 means unknown.
func TitlesToImpact(title string, otherTitles ...string) int {
	maxImpact := -1
	for _, t := range append([]string{title}, otherTitles...) {
		typ := TitleToCrashType(t)
		for i, t := range impactOrder {
			if typ == t {
				maxImpact = max(maxImpact, len(impactOrder)-i)
			}
		}
	}
	return maxImpact
}

type TitleFreqRank struct {
	Title string
	Count int
	Total int
	Rank  int
}

func ExplainTitleStat(ts *titleStat) []*TitleFreqRank {
	titleCount := map[string]int{}
	var totalCount int
	ts.visit(func(count int, titles ...string) {
		uniq := map[string]bool{}
		for _, title := range titles {
			uniq[title] = true
		}
		for title := range uniq {
			titleCount[title] += count
		}
		totalCount += count
	})
	var res []*TitleFreqRank
	for title, count := range titleCount {
		res = append(res, &TitleFreqRank{
			Title: title,
			Count: count,
			Total: totalCount,
			Rank:  TitlesToImpact(title),
		})
	}
	sort.Slice(res, func(l, r int) bool {
		if res[l].Rank != res[r].Rank {
			return res[l].Rank > res[r].Rank
		}
		lTitle, rTitle := res[l].Title, res[r].Title
		if titleCount[lTitle] != titleCount[rTitle] {
			return titleCount[lTitle] > titleCount[rTitle]
		}
		return lTitle < rTitle
	})
	return res
}
