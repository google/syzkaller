// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package state

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
)

// State holds all internal syz-hub state including corpus,
// reproducers and information about managers.
// It is persisted to and can be restored from a directory.
type State struct {
	corpusSeq uint64
	reproSeq  uint64
	dir       string
	Corpus    *db.DB
	Repros    *db.DB
	Managers  map[string]*Manager
}

// Manager represents one syz-manager instance.
type Manager struct {
	name          string
	dir           string
	Domain        string
	corpusSeq     uint64
	reproSeq      uint64
	corpusFile    string
	corpusSeqFile string
	reproSeqFile  string
	domainFile    string
	ownRepros     map[string]bool
	Connected     time.Time
	Added         int
	Deleted       int
	New           int
	SentRepros    int
	RecvRepros    int
	Calls         map[string]struct{}
	Corpus        *db.DB
}

// Make creates State and initializes it from dir.
func Make(dir string) (*State, error) {
	st := &State{
		dir:      dir,
		Managers: make(map[string]*Manager),
	}

	osutil.MkdirAll(st.dir)
	var err error
	st.Corpus, st.corpusSeq, err = loadDB(filepath.Join(st.dir, "corpus.db"), "corpus", true)
	if err != nil {
		log.Fatal(err)
	}
	st.Repros, st.reproSeq, err = loadDB(filepath.Join(st.dir, "repro.db"), "repro", true)
	if err != nil {
		log.Fatal(err)
	}

	managersDir := filepath.Join(st.dir, "manager")
	osutil.MkdirAll(managersDir)
	managers, err := os.ReadDir(managersDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read %v dir: %w", managersDir, err)
	}
	for _, manager := range managers {
		if strings.HasSuffix(manager.Name(), purgedSuffix) {
			continue
		}
		_, err := st.createManager(manager.Name())
		if err != nil {
			return nil, err
		}
	}
	if err := st.PurgeOldManagers(); err != nil {
		return nil, err
	}
	log.Logf(0, "purging corpus...")
	st.purgeCorpus()
	log.Logf(0, "done, %v programs", len(st.Corpus.Records))
	return st, err
}

func (st *State) Flush() {
	if err := st.Corpus.Flush(); err != nil {
		log.Logf(0, "failed to flush corpus database: %v", err)
	}
	for _, mgr := range st.Managers {
		if err := mgr.Corpus.Flush(); err != nil {
			log.Logf(0, "failed to flush corpus database: %v", err)
		}
	}
}

func loadDB(file, name string, progs bool) (*db.DB, uint64, error) {
	log.Logf(0, "reading %v...", name)
	db, err := db.Open(file, true)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to open %v database: %w", name, err)
	}
	log.Logf(0, "read %v programs", len(db.Records))
	var maxSeq uint64
	for key, rec := range db.Records {
		if progs {
			_, ncalls, err := prog.CallSet(rec.Val)
			if err != nil {
				log.Logf(0, "bad file: can't parse call set: %v\n%q", err, rec.Val)
				db.Delete(key)
				continue
			}
			if ncalls > prog.MaxCalls {
				log.Logf(0, "bad file: too many calls: %v", ncalls)
				db.Delete(key)
				continue
			}
			if sig := hash.Hash(rec.Val); sig.String() != key {
				log.Logf(0, "bad file: hash %v, want hash %v", key, sig.String())
				db.Delete(key)
				continue
			}
		}
		maxSeq = max(maxSeq, rec.Seq)
	}
	if err := db.Flush(); err != nil {
		return nil, 0, fmt.Errorf("failed to flush corpus database: %w", err)
	}
	return db, maxSeq, nil
}

func (st *State) createManager(name string) (*Manager, error) {
	dir := filepath.Join(st.dir, "manager", name)
	osutil.MkdirAll(dir)
	mgr := &Manager{
		name:          name,
		dir:           dir,
		corpusFile:    filepath.Join(dir, "corpus.db"),
		corpusSeqFile: filepath.Join(dir, "seq"),
		reproSeqFile:  filepath.Join(dir, "repro.seq"),
		domainFile:    filepath.Join(dir, "domain"),
		ownRepros:     make(map[string]bool),
	}
	mgr.corpusSeq = loadSeqFile(mgr.corpusSeqFile)
	st.corpusSeq = max(st.corpusSeq, mgr.corpusSeq)
	mgr.reproSeq = loadSeqFile(mgr.reproSeqFile)
	if mgr.reproSeq == 0 {
		mgr.reproSeq = st.reproSeq
	}
	st.reproSeq = max(st.reproSeq, mgr.reproSeq)
	domainData, _ := os.ReadFile(mgr.domainFile)
	mgr.Domain = string(domainData)
	corpus, _, err := loadDB(mgr.corpusFile, name, false)
	if err != nil {
		return nil, fmt.Errorf("failed to open manager corpus %v: %w", mgr.corpusFile, err)
	}
	mgr.Corpus = corpus
	log.Logf(0, "created manager %v: domain=%v corpus=%v, corpusSeq=%v, reproSeq=%v",
		mgr.name, mgr.Domain, len(mgr.Corpus.Records), mgr.corpusSeq, mgr.reproSeq)
	st.Managers[name] = mgr
	return mgr, nil
}

const purgedSuffix = ".purged"

func (st *State) PurgeOldManagers() error {
	const (
		timeDay     = 24 * time.Hour
		purgePeriod = 30 * timeDay
	)
	purgedSomething := false
	for _, mgr := range st.Managers {
		info, err := os.Stat(mgr.corpusSeqFile)
		if err != nil {
			return err
		}
		if time.Since(info.ModTime()) < purgePeriod {
			continue
		}
		log.Logf(0, "purging manager %v as it was inactive for %v days", mgr.name, int(purgePeriod/timeDay))
		oldDir := mgr.dir + purgedSuffix
		os.RemoveAll(oldDir)
		if err := os.Rename(mgr.dir, oldDir); err != nil {
			return err
		}
		delete(st.Managers, mgr.name)
		purgedSomething = true
	}
	if !purgedSomething {
		return nil
	}
	corpus := len(st.Corpus.Records)
	st.purgeCorpus()
	log.Logf(0, "reduced corpus from %v to %v programs", corpus, len(st.Corpus.Records))
	return nil
}

func (st *State) Connect(name, domain string, fresh bool, calls []string, corpus [][]byte) error {
	mgr := st.Managers[name]
	if mgr == nil {
		var err error
		mgr, err = st.createManager(name)
		if err != nil {
			return err
		}
	}
	mgr.Connected = time.Now()
	mgr.Domain = domain
	writeFile(mgr.domainFile, []byte(mgr.Domain))
	if fresh {
		mgr.corpusSeq = 0
		mgr.reproSeq = st.reproSeq
	}
	saveSeqFile(mgr.corpusSeqFile, mgr.corpusSeq)
	saveSeqFile(mgr.reproSeqFile, mgr.reproSeq)

	mgr.Calls = make(map[string]struct{})
	for _, c := range calls {
		mgr.Calls[c] = struct{}{}
	}

	os.Remove(mgr.corpusFile)
	var err error
	mgr.Corpus, err = db.Open(mgr.corpusFile, true)
	if err != nil {
		log.Logf(0, "failed to open corpus database: %v", err)
		return err
	}
	st.addInputs(mgr, corpus)
	st.purgeCorpus()
	return nil
}

func (st *State) Sync(name string, add [][]byte, del []string) (string, []rpctype.HubInput, int, error) {
	mgr := st.Managers[name]
	if mgr == nil || mgr.Connected.IsZero() {
		return "", nil, 0, fmt.Errorf("unconnected manager %v", name)
	}
	if len(del) != 0 {
		for _, sig := range del {
			mgr.Corpus.Delete(sig)
		}
		if err := mgr.Corpus.Flush(); err != nil {
			log.Logf(0, "failed to flush corpus database: %v", err)
		}
		st.purgeCorpus()
	}
	st.addInputs(mgr, add)
	progs, more, err := st.pendingInputs(mgr)
	mgr.Added += len(add)
	mgr.Deleted += len(del)
	mgr.New += len(progs)
	// Update seq file b/c PurgeOldManagers looks at it to detect inactive managers.
	saveSeqFile(mgr.corpusSeqFile, mgr.corpusSeq)
	return mgr.Domain, progs, more, err
}

func (st *State) AddRepro(name string, repro []byte) error {
	mgr := st.Managers[name]
	if mgr == nil || mgr.Connected.IsZero() {
		return fmt.Errorf("unconnected manager %v", name)
	}
	if _, _, err := prog.CallSet(repro); err != nil {
		log.Logf(0, "manager %v: failed to extract call set: %v, program:\n%v",
			mgr.name, err, string(repro))
		return nil
	}
	sig := hash.String(repro)
	if _, ok := st.Repros.Records[sig]; ok {
		return nil
	}
	mgr.ownRepros[sig] = true
	mgr.SentRepros++
	if mgr.reproSeq == st.reproSeq {
		mgr.reproSeq++
		saveSeqFile(mgr.reproSeqFile, mgr.reproSeq)
	}
	st.reproSeq++
	st.Repros.Save(sig, repro, st.reproSeq)
	if err := st.Repros.Flush(); err != nil {
		log.Logf(0, "failed to flush repro database: %v", err)
	}
	return nil
}

func (st *State) PendingRepro(name string) ([]byte, error) {
	mgr := st.Managers[name]
	if mgr == nil || mgr.Connected.IsZero() {
		return nil, fmt.Errorf("unconnected manager %v", name)
	}
	if mgr.reproSeq == st.reproSeq {
		return nil, nil
	}
	var repro []byte
	minSeq := ^uint64(0)
	for key, rec := range st.Repros.Records {
		if mgr.reproSeq >= rec.Seq {
			continue
		}
		if mgr.ownRepros[key] {
			continue
		}
		calls, _, err := prog.CallSet(rec.Val)
		if err != nil {
			return nil, fmt.Errorf("failed to extract call set: %w\nprogram: %s", err, rec.Val)
		}
		if !managerSupportsAllCalls(mgr.Calls, calls) {
			continue
		}
		if minSeq > rec.Seq {
			minSeq = rec.Seq
			repro = rec.Val
		}
	}
	if repro == nil {
		mgr.reproSeq = st.reproSeq
		saveSeqFile(mgr.reproSeqFile, mgr.reproSeq)
		return nil, nil
	}
	mgr.RecvRepros++
	mgr.reproSeq = minSeq
	saveSeqFile(mgr.reproSeqFile, mgr.reproSeq)
	return repro, nil
}

func (st *State) pendingInputs(mgr *Manager) ([]rpctype.HubInput, int, error) {
	if mgr.corpusSeq == st.corpusSeq {
		return nil, 0, nil
	}
	type Record struct {
		Key string
		Val []byte
		Seq uint64
	}
	var records []Record
	for key, rec := range st.Corpus.Records {
		if mgr.corpusSeq >= rec.Seq {
			continue
		}
		if _, ok := mgr.Corpus.Records[key]; ok {
			continue
		}
		calls, _, err := prog.CallSet(rec.Val)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to extract call set: %w\nprogram: %s", err, rec.Val)
		}
		if !managerSupportsAllCalls(mgr.Calls, calls) {
			continue
		}
		records = append(records, Record{key, rec.Val, rec.Seq})
	}
	maxSeq := st.corpusSeq
	more := 0
	const (
		// Send at most that many records (rounded up to next seq number).
		maxRecords = 100
		// If we have way too many records to send (more than capRecords),
		// cap total number to capRecords and give up sending all.
		// Otherwise new managers will never chew all this on a busy hub.
		capRecords = 100000
	)
	if len(records) > maxRecords {
		sort.Slice(records, func(i, j int) bool {
			return records[i].Seq < records[j].Seq
		})
		if len(records) > capRecords {
			records = records[len(records)-capRecords:]
		}
		pos := maxRecords
		maxSeq = records[pos].Seq
		for pos+1 < len(records) && records[pos+1].Seq == maxSeq {
			pos++
		}
		pos++
		more = len(records) - pos
		records = records[:pos]
	}
	progs := make([]rpctype.HubInput, 0, len(records))
	for _, rec := range records {
		progs = append(progs, rpctype.HubInput{
			Domain: st.inputDomain(rec.Key, mgr.Domain),
			Prog:   rec.Val,
		})
	}
	mgr.corpusSeq = maxSeq
	saveSeqFile(mgr.corpusSeqFile, mgr.corpusSeq)
	return progs, more, nil
}

func (st *State) inputDomain(key, self string) string {
	domain := ""
	for _, mgr := range st.Managers {
		same := mgr.Domain == self
		if !same && domain != "" {
			continue
		}
		if _, ok := mgr.Corpus.Records[key]; !ok {
			continue
		}
		domain = mgr.Domain
		if same {
			break
		}
	}
	return domain
}

func (st *State) addInputs(mgr *Manager, inputs [][]byte) {
	if len(inputs) == 0 {
		return
	}
	st.corpusSeq++
	for _, input := range inputs {
		st.addInput(mgr, input)
	}
	if err := mgr.Corpus.Flush(); err != nil {
		log.Logf(0, "failed to flush corpus database: %v", err)
	}
	if err := st.Corpus.Flush(); err != nil {
		log.Logf(0, "failed to flush corpus database: %v", err)
	}
}

func (st *State) addInput(mgr *Manager, input []byte) {
	_, ncalls, err := prog.CallSet(input)
	if err != nil {
		log.Logf(0, "manager %v: failed to extract call set: %v, program:\n%v", mgr.name, err, string(input))
		return
	}
	if want := prog.MaxCalls; ncalls > want {
		log.Logf(0, "manager %v: too long program, ignoring (%v/%v)", mgr.name, ncalls, want)
		return
	}
	sig := hash.String(input)
	mgr.Corpus.Save(sig, nil, 0)
	if _, ok := st.Corpus.Records[sig]; !ok {
		st.Corpus.Save(sig, input, st.corpusSeq)
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
		log.Logf(0, "failed to flush corpus database: %v", err)
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

func writeFile(name string, data []byte) {
	if err := osutil.WriteFile(name, data); err != nil {
		log.Logf(0, "failed to write file %v: %v", name, err)
	}
}

func saveSeqFile(filename string, seq uint64) {
	writeFile(filename, []byte(fmt.Sprint(seq)))
}

func loadSeqFile(filename string) uint64 {
	str, _ := os.ReadFile(filename)
	seq, _ := strconv.ParseUint(string(str), 10, 64)
	return seq
}
