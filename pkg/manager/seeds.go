// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

type Seeds struct {
	CorpusDB   *db.DB
	Fresh      bool
	Candidates []fuzzer.Candidate
}

func LoadSeeds(cfg *mgrconfig.Config, immutable bool) Seeds {
	var info Seeds
	var err error
	info.CorpusDB, err = db.Open(filepath.Join(cfg.Workdir, "corpus.db"), !immutable)
	if err != nil {
		if info.CorpusDB == nil {
			log.Fatalf("failed to open corpus database: %v", err)
		}
		log.Errorf("read %v inputs from corfpus and got error: %v", len(info.CorpusDB.Records), err)
	}
	info.Fresh = len(info.CorpusDB.Records) == 0
	corpusFlags := versionToFlags(info.CorpusDB.Version)
	type Input struct {
		IsSeed bool
		Key    string
		Data   []byte
		Prog   *prog.Prog
	}
	procs := runtime.GOMAXPROCS(0)
	inputs := make(chan *Input, procs)
	outputs := make(chan *Input, procs)
	var wg sync.WaitGroup
	wg.Add(procs)
	for p := 0; p < procs; p++ {
		go func() {
			defer wg.Done()
			for inp := range inputs {
				inp.Prog, _ = LoadProg(cfg.Target, inp.Data)
				outputs <- inp
			}
		}()
	}
	go func() {
		wg.Wait()
		close(outputs)
	}()
	go func() {
		for key, rec := range info.CorpusDB.Records {
			inputs <- &Input{
				Key:  key,
				Data: rec.Val,
			}
		}
		seedDir := filepath.Join(cfg.Syzkaller, "sys", cfg.TargetOS, "test")
		if osutil.IsExist(seedDir) {
			seeds, err := os.ReadDir(seedDir)
			if err != nil {
				log.Fatalf("failed to read seeds dir: %v", err)
			}
			for _, seed := range seeds {
				data, err := os.ReadFile(filepath.Join(seedDir, seed.Name()))
				if err != nil {
					log.Fatalf("failed to read seed %v: %v", seed.Name(), err)
				}
				inputs <- &Input{
					IsSeed: true,
					Data:   data,
				}
			}
		}
		close(inputs)
	}()
	brokenSeeds := 0
	var brokenCorpus []string
	var candidates []fuzzer.Candidate
	for inp := range outputs {
		if inp.Prog == nil {
			if inp.IsSeed {
				brokenSeeds++
			} else {
				brokenCorpus = append(brokenCorpus, inp.Key)
			}
			continue
		}
		flags := corpusFlags
		if inp.IsSeed {
			if _, ok := info.CorpusDB.Records[hash.String(inp.Prog.Serialize())]; ok {
				continue
			}
			// Seeds are not considered "from corpus" (won't be rerun multiple times)
			// b/c they are tried on every start anyway.
			flags = fuzzer.ProgMinimized
		}
		candidates = append(candidates, fuzzer.Candidate{
			Prog:  inp.Prog,
			Flags: flags,
		})
	}
	if len(brokenCorpus)+brokenSeeds != 0 {
		log.Logf(0, "broken programs in the corpus: %v, broken seeds: %v", len(brokenCorpus), brokenSeeds)
	}
	if !immutable {
		// This needs to be done outside of the loop above to not race with corpusDB reads.
		for _, sig := range brokenCorpus {
			info.CorpusDB.Delete(sig)
		}
		if err := info.CorpusDB.Flush(); err != nil {
			log.Fatalf("failed to save corpus database: %v", err)
		}
	}
	// Switch database to the mode when it does not keep records in memory.
	// We don't need them anymore and they consume lots of memory.
	info.CorpusDB.DiscardData()
	info.Candidates = candidates
	return info
}

const CurrentDBVersion = 5

func versionToFlags(version uint64) fuzzer.ProgFlags {
	// By default we don't re-minimize/re-smash programs from corpus,
	// it takes lots of time on start and is unnecessary.
	// However, on version bumps we can selectively re-minimize/re-smash.
	corpusFlags := fuzzer.ProgFromCorpus | fuzzer.ProgMinimized | fuzzer.ProgSmashed
	switch version {
	case 0:
		// Version 0 had broken minimization, so we need to re-minimize.
		corpusFlags &= ^fuzzer.ProgMinimized
		fallthrough
	case 1:
		// Version 1->2: memory is preallocated so lots of mmaps become unnecessary.
		corpusFlags &= ^fuzzer.ProgMinimized
		fallthrough
	case 2:
		// Version 2->3: big-endian hints.
		corpusFlags &= ^fuzzer.ProgSmashed
		fallthrough
	case 3:
		// Version 3->4: to shake things up.
		corpusFlags &= ^fuzzer.ProgMinimized
		fallthrough
	case 4:
		// Version 4->5: fix for comparison argument sign extension.
		// Introduced in 1ba0279d74a35e96e81de87073212d2b20256e8f.

		// Update (July 2024):
		// We used to reset the fuzzer.ProgSmashed flag here, but it has led to
		// perpetual corpus retriage on slow syzkaller instances. By now, all faster
		// instances must have already bumped their corpus versions, so let's just
		// increase the version to let all others go past the corpus triage stage.
		fallthrough
	case CurrentDBVersion:
	}
	return corpusFlags
}

func LoadProg(target *prog.Target, data []byte) (*prog.Prog, error) {
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		return nil, err
	}
	if len(p.Calls) > prog.MaxCalls {
		return nil, fmt.Errorf("longer than %d calls", prog.MaxCalls)
	}
	// For some yet unknown reasons, programs with fail_nth > 0 may sneak in. Ignore them.
	for _, call := range p.Calls {
		if call.Props.FailNth > 0 {
			return nil, fmt.Errorf("input has fail_nth > 0")
		}
	}
	return p, nil
}

type FilteredCandidates struct {
	Candidates     []fuzzer.Candidate
	ModifiedHashes []string
	SeedCount      int
}

func FilterCandidates(candidates []fuzzer.Candidate, syscalls map[*prog.Syscall]bool,
	dropMinimize bool) FilteredCandidates {
	var ret FilteredCandidates
	for _, item := range candidates {
		if !item.Prog.OnlyContains(syscalls) {
			ret.ModifiedHashes = append(ret.ModifiedHashes, hash.String(item.Prog.Serialize()))
			// We cut out the disabled syscalls and retriage/minimize what remains from the prog.
			// The original prog will be deleted from the corpus.
			if dropMinimize {
				item.Flags &= ^fuzzer.ProgMinimized
			}
			item.Prog.FilterInplace(syscalls)
			if len(item.Prog.Calls) == 0 {
				continue
			}
		}
		if item.Flags&fuzzer.ProgFromCorpus == 0 {
			ret.SeedCount++
		}
		ret.Candidates = append(ret.Candidates, item)
	}
	return ret
}

// Programs that do more than 15 system calls are to be treated with suspicion and re-minimized.
const ReminimizeThreshold = 15

// ReminimizeSubset clears the fuzzer.ProgMinimized flag of a small subset of seeds.
// The ultimate objective is to gradually clean up the poorly minimized corpus programs.
// ReminimizeSubset assumes that candidates are sorted in the order of ascending len(Prog.Calls).
func (fc *FilteredCandidates) ReminimizeSubset() int {
	if len(fc.Candidates) == 0 {
		return 0
	}
	// Focus on the top 10% of the largest programs in the corpus.
	threshold := max(ReminimizeThreshold, len(fc.Candidates[len(fc.Candidates)*9/10].Prog.Calls))
	var resetIndices []int
	for i, info := range fc.Candidates {
		if info.Flags&fuzzer.ProgMinimized == 0 {
			continue
		}
		if len(info.Prog.Calls) >= threshold {
			resetIndices = append(resetIndices, i)
		}
	}
	// Reset ProgMinimized for up to 1% of the seed programs.
	reset := min(50, len(resetIndices), max(1, len(fc.Candidates)/100))
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	for _, i := range rnd.Perm(len(resetIndices))[:reset] {
		fc.Candidates[resetIndices[i]].Flags &= ^fuzzer.ProgMinimized
	}
	return reset
}

// resmashSubset clears fuzzer.ProgSmashes for a subset of seeds.
// We smash the program only once after we add it to the corpus, but it can be that
// either it did not finish before the instance was restarted, or the fuzzing algorithms
// have become smarter over time, or just that kernel code changed over time.
// It would be best to track it in pkg/db, but until it's capable of that, let's just
// re-smash some corpus subset on each syz-manager restart.
func (fc *FilteredCandidates) ResmashSubset() int {
	var indices []int
	for i, info := range fc.Candidates {
		if info.Flags&fuzzer.ProgSmashed == 0 {
			continue
		}
		indices = append(indices, i)
	}
	// Reset ProgSmashed for up to 0.5% of the seed programs.
	reset := min(25, len(indices), max(1, len(fc.Candidates)/200))
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	for _, i := range rnd.Perm(len(indices))[:reset] {
		fc.Candidates[indices[i]].Flags &= ^fuzzer.ProgSmashed
	}
	return reset
}
