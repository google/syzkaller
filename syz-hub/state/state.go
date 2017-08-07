// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package state

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/hash"
	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

// State holds all internal syz-hub state including corpus and information about managers.
// It is persisted to and can be restored from a directory.
type State struct {
	seq      uint64
	dir      string
	Corpus   *db.DB
	Managers map[string]*Manager
}

// Manager represents one syz-manager instance.
type Manager struct {
	name      string
	seq       uint64
	dir       string
	Connected time.Time
	Added     int
	Deleted   int
	New       int
	Repros    int
	Calls     map[string]struct{}
	Corpus    *db.DB
}

// Make creates State and initializes it from dir.
func Make(dir string) (*State, error) {
	st := &State{
		dir:      dir,
		Managers: make(map[string]*Manager),
	}

	osutil.MkdirAll(st.dir)
	var err error
	Logf(0, "reading corpus...")
	st.Corpus, err = db.Open(filepath.Join(st.dir, "corpus.db"))
	if err != nil {
		Fatalf("failed to open corpus database: %v", err)
	}
	Logf(0, "read %v programs", len(st.Corpus.Records))
	for key, rec := range st.Corpus.Records {
		if _, err := prog.CallSet(rec.Val); err != nil {
			Logf(0, "bad file in corpus: can't parse call set: %v", err)
			st.Corpus.Delete(key)
			continue
		}
		if sig := hash.Hash(rec.Val); sig.String() != key {
			Logf(0, "bad file in corpus: hash %v, want hash %v", key, sig.String())
			st.Corpus.Delete(key)
			continue
		}
		if st.seq < rec.Seq {
			st.seq = rec.Seq
		}
	}
	if err := st.Corpus.Flush(); err != nil {
		Fatalf("failed to flush corpus database: %v", err)
	}

	managersDir := filepath.Join(st.dir, "manager")
	osutil.MkdirAll(managersDir)
	managers, err := ioutil.ReadDir(managersDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read %v dir: %v", managersDir, err)
	}
	for _, manager := range managers {
		mgr := &Manager{
			name: manager.Name(),
		}
		st.Managers[mgr.name] = mgr
		mgr.dir = filepath.Join(managersDir, mgr.name)
		seqStr, _ := ioutil.ReadFile(filepath.Join(mgr.dir, "seq"))
		mgr.seq, _ = strconv.ParseUint(string(seqStr), 10, 64)
		if st.seq < mgr.seq {
			st.seq = mgr.seq
		}
		Logf(0, "reading %v corpus...", mgr.name)
		mgr.Corpus, err = db.Open(filepath.Join(mgr.dir, "corpus.db"))
		if err != nil {
			return nil, fmt.Errorf("failed to open manager corpus database %v: %v", mgr.dir, err)
		}
		Logf(0, "read %v programs", len(mgr.Corpus.Records))
	}
	Logf(0, "purging corpus...")
	st.purgeCorpus()
	Logf(0, "done, %v programs", len(st.Corpus.Records))

	return st, err
}

func (st *State) Connect(name string, fresh bool, calls []string, corpus, repros [][]byte) error {
	mgr := st.Managers[name]
	if mgr == nil {
		mgr = new(Manager)
		st.Managers[name] = mgr
		mgr.dir = filepath.Join(st.dir, "manager", name)
		osutil.MkdirAll(mgr.dir)
	}
	mgr.Connected = time.Now()
	if fresh {
		mgr.seq = 0
	}
	writeFile(filepath.Join(mgr.dir, "seq"), []byte(fmt.Sprint(mgr.seq)))

	mgr.Calls = make(map[string]struct{})
	for _, c := range calls {
		mgr.Calls[c] = struct{}{}
	}

	corpusFile := filepath.Join(mgr.dir, "corpus.db")
	os.Remove(corpusFile)
	var err error
	mgr.Corpus, err = db.Open(corpusFile)
	if err != nil {
		Logf(0, "failed to open corpus database: %v", err)
		return err
	}
	st.addInputs(mgr, corpus, false)
	st.addInputs(mgr, repros, true)
	st.purgeCorpus()
	return nil
}

func (st *State) Sync(name string, add [][]byte, del []string, repros [][]byte) ([][]byte, [][]byte, int, error) {
	mgr := st.Managers[name]
	if mgr == nil || mgr.Connected.IsZero() {
		return nil, nil, 0, fmt.Errorf("unconnected manager %v", name)
	}
	if len(del) != 0 {
		for _, sig := range del {
			mgr.Corpus.Delete(sig)
		}
		if err := mgr.Corpus.Flush(); err != nil {
			Logf(0, "failed to flush corpus database: %v", err)
		}
		st.purgeCorpus()
	}
	st.addInputs(mgr, add, false)
	st.addInputs(mgr, repros, true)
	progs, repros, more, err := st.pendingInputs(mgr)
	mgr.Added += len(add)
	mgr.Deleted += len(del)
	mgr.New += len(progs)
	mgr.Repros += len(repros)
	return progs, repros, more, err
}

func (st *State) pendingInputs(mgr *Manager) ([][]byte, [][]byte, int, error) {
	if mgr.seq == st.seq {
		return nil, nil, 0, nil
	}
	var records []db.Record
	for key, rec := range st.Corpus.Records {
		if mgr.seq >= rec.Seq {
			continue
		}
		if _, ok := mgr.Corpus.Records[key]; ok {
			continue
		}
		calls, err := prog.CallSet(rec.Val)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("failed to extract call set: %v\nprogram: %s", err, rec.Val)
		}
		if !managerSupportsAllCalls(mgr.Calls, calls) {
			continue
		}
		records = append(records, rec)
	}
	maxSeq := st.seq
	more := 0
	// Send at most that many records (rounded up to next seq number).
	const maxRecords = 1000
	if len(records) > maxRecords {
		sort.Sort(recordSeqSorter(records))
		pos := maxRecords
		maxSeq = records[pos].Seq
		for pos+1 < len(records) && records[pos+1].Seq == maxSeq {
			pos++
		}
		pos++
		more = len(records) - pos
		records = records[:pos]
	}
	var progs [][]byte
	var repros [][]byte
	for _, rec := range records {
		if rec.Repro {
			repros = append(repros, rec.Val)
		} else {
			progs = append(progs, rec.Val)
		}
	}
	mgr.seq = maxSeq
	writeFile(filepath.Join(mgr.dir, "seq"), []byte(fmt.Sprint(mgr.seq)))
	return progs, repros, more, nil
}

func (st *State) addInputs(mgr *Manager, inputs [][]byte, repro bool) {
	if len(inputs) == 0 {
		return
	}
	st.seq++
	for _, input := range inputs {
		st.addInput(mgr, input, repro)
	}
	if err := mgr.Corpus.Flush(); err != nil {
		Logf(0, "failed to flush corpus database: %v", err)
	}
	if err := st.Corpus.Flush(); err != nil {
		Logf(0, "failed to flush corpus database: %v", err)
	}
}

func (st *State) addInput(mgr *Manager, input []byte, repro bool) {
	if _, err := prog.CallSet(input); err != nil {
		Logf(0, "manager %v: failed to extract call set: %v, program:\n%v", mgr.name, err, string(input))
		return
	}
	sig := hash.String(input)
	mgr.Corpus.Save(sig, nil, 0, false)
	if _, ok := st.Corpus.Records[sig]; !ok {
		st.Corpus.Save(sig, input, st.seq, repro)
	}
}

func writeFile(name string, data []byte) {
	if err := osutil.WriteFile(name, data); err != nil {
		Logf(0, "failed to write file %v: %v", name, err)
	}
}

func (st *State) purgeCorpus() {
	used := make(map[string]bool)
	for _, mgr := range st.Managers {
		for sig := range mgr.Corpus.Records {
			used[sig] = true
		}
	}
	for key := range st.Corpus.Records {
		if used[key] {
			continue
		}
		st.Corpus.Delete(key)
	}
	if err := st.Corpus.Flush(); err != nil {
		Logf(0, "failed to flush corpus database: %v", err)
	}
}

func managerSupportsAllCalls(mgr, prog map[string]struct{}) bool {
	for c := range prog {
		if _, ok := mgr[c]; !ok {
			return false
		}
	}
	return true
}

type recordSeqSorter []db.Record

func (a recordSeqSorter) Len() int {
	return len(a)
}

func (a recordSeqSorter) Less(i, j int) bool {
	return a[i].Seq < a[j].Seq
}

func (a recordSeqSorter) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
