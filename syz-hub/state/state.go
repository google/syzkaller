// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package state manages persistent state for syz-hub including corpus, reproducers, and connected managers.
package state

import (
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
	corpusSeq   uint64
	reproSeq    uint64
	dir         string
	Corpus      *db.DB
	Repros      *db.DB
	Managers    map[string]*Manager
	callIDs     map[string]uint32
	corpusMeta  map[string]corpusMeta
	corpusOrder []seqEntry
	reproCalls  map[string][]uint32
	reproOrder  []seqEntry
}

type corpusMeta struct {
	// key holds the canonical signature string from st.Corpus so per-manager Corpus
	// maps can share the same underlying string bytes instead of duplicating them.
	key   string
	calls []uint32
	refs  int
}

type seqEntry struct {
	key string
	seq uint64
}

// Manager represents one syz-manager instance.
type Manager struct {
	name          string
	dir           string
	HTTP          string
	Domain        string
	corpusSeq     uint64
	capCheckedSeq uint64
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
	calls         []bool
	Corpus        *db.DB
}

// Make creates State and initializes it from dir.
func Make(dir string) (*State, error) {
	st := &State{
		dir:      dir,
		Managers: make(map[string]*Manager),
		callIDs:  make(map[string]uint32),
	}

	osutil.MkdirAll(st.dir)
	var err error
	var corpusCalls map[string][]uint32
	st.Corpus, st.corpusSeq, corpusCalls, err = st.loadProgsDB(filepath.Join(st.dir, "corpus.db"), "corpus")
	if err != nil {
		return nil, err
	}
	st.corpusMeta = make(map[string]corpusMeta, len(corpusCalls))
	for key, calls := range corpusCalls {
		st.corpusMeta[key] = corpusMeta{
			key:   key,
			calls: calls,
		}
	}
	st.Repros, st.reproSeq, st.reproCalls, err = st.loadProgsDB(filepath.Join(st.dir, "repro.db"), "repro")
	if err != nil {
		return nil, err
	}
	st.reproOrder = sortedEntries(st.Repros.Records)

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
	// purgeCorpus initializes corpusMeta reference counts before PurgeOldManagers
	// releases keys held by expired managers.
	log.Logf(0, "purging corpus...")
	st.purgeCorpus()
	log.Logf(0, "done, %v programs", len(st.Corpus.Records))
	if err := st.PurgeOldManagers(); err != nil {
		return nil, err
	}
	return st, nil
}

func (st *State) Flush() {
	if err := st.Corpus.Flush(); err != nil {
		log.Logf(0, "failed to flush corpus database: %v", err)
	}
	if err := st.Repros.Flush(); err != nil {
		log.Logf(0, "failed to flush repro database: %v", err)
	}
	for _, mgr := range st.Managers {
		if err := mgr.Corpus.Flush(); err != nil {
			log.Logf(0, "failed to flush corpus database: %v", err)
		}
	}
}

func (st *State) loadProgsDB(file, name string) (*db.DB, uint64, map[string][]uint32, error) {
	log.Logf(0, "reading %v...", name)
	db, err := db.Open(file, true)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to open %v database: %w", name, err)
	}
	log.Logf(0, "read %v programs", len(db.Records))
	var maxSeq uint64
	progCalls := make(map[string][]uint32, len(db.Records))
	for key, rec := range db.Records {
		calls, ncalls, err := prog.CallSet(rec.Val)
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
		progCalls[key] = st.internCalls(calls)
		maxSeq = max(maxSeq, rec.Seq)
	}
	if err := db.Flush(); err != nil {
		return nil, 0, nil, fmt.Errorf("failed to flush %v database: %w", name, err)
	}
	return db, maxSeq, progCalls, nil
}

func (st *State) callID(name string) uint32 {
	if id, ok := st.callIDs[name]; ok {
		return id
	}
	id := uint32(len(st.callIDs))
	st.callIDs[name] = id
	return id
}

func (st *State) internCalls(calls map[string]struct{}) []uint32 {
	ids := make([]uint32, 0, len(calls))
	for c := range calls {
		ids = append(ids, st.callID(c))
	}
	slices.Sort(ids)
	return ids
}

var managerNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-_.]{0,100}$`)

func IsValidManagerName(name string) bool {
	return managerNameRe.MatchString(name)
}

func (st *State) createManager(name string) (*Manager, error) {
	if !IsValidManagerName(name) {
		return nil, fmt.Errorf("invalid manager name %q", name)
	}
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
	log.Logf(0, "reading %v...", name)
	corpus, err := db.Open(mgr.corpusFile, true)
	if err != nil {
		return nil, fmt.Errorf("failed to open manager corpus %v: %w", mgr.corpusFile, err)
	}
	log.Logf(0, "read %v programs", len(corpus.Records))
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
	corpus := len(st.Corpus.Records)
	purgedSomething := false
	deletedFromHub := false
	defer func() {
		if deletedFromHub {
			st.maybeCompactCorpusOrder()
			if err := st.Corpus.Flush(); err != nil {
				log.Logf(0, "failed to flush corpus database: %v", err)
			}
		}
		if purgedSomething {
			log.Logf(0, "reduced corpus from %v to %v programs", corpus, len(st.Corpus.Records))
		}
	}()
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
		for sig := range mgr.Corpus.Records {
			if st.releaseCorpusKey(sig) {
				deletedFromHub = true
			}
		}
	}
	return nil
}

func (st *State) Connect(name, http, domain string, fresh bool, calls []string, corpus [][]byte) error {
	mgr := st.Managers[name]
	var oldRecords map[string]db.Record
	if mgr == nil {
		var err error
		mgr, err = st.createManager(name)
		if err != nil {
			return err
		}
	} else {
		oldRecords = mgr.Corpus.Records
		os.Remove(mgr.corpusFile)
		corpusDB, err := db.Open(mgr.corpusFile, true)
		if err != nil {
			log.Logf(0, "failed to open corpus database: %v", err)
			return err
		}
		mgr.Corpus = corpusDB
	}
	mgr.HTTP = http
	mgr.Connected = time.Now()
	mgr.Domain = domain
	writeFile(mgr.domainFile, []byte(mgr.Domain))
	mgr.capCheckedSeq = 0
	if fresh {
		mgr.corpusSeq = 0
		mgr.reproSeq = st.reproSeq
	}
	saveSeqFile(mgr.corpusSeqFile, mgr.corpusSeq)
	saveSeqFile(mgr.reproSeqFile, mgr.reproSeq)

	for _, c := range calls {
		st.callID(c)
	}
	mgr.calls = make([]bool, len(st.callIDs))
	for _, c := range calls {
		mgr.calls[st.callIDs[c]] = true
	}

	for _, input := range corpus {
		st.addInput(mgr, input)
	}
	for sig := range oldRecords {
		st.releaseCorpusKey(sig)
	}
	st.maybeCompactCorpusOrder()
	if err := mgr.Corpus.Flush(); err != nil {
		log.Logf(0, "failed to flush corpus database: %v", err)
	}
	if err := st.Corpus.Flush(); err != nil {
		log.Logf(0, "failed to flush corpus database: %v", err)
	}
	return nil
}

func (st *State) Sync(name string, add [][]byte, del []string) (string, []rpctype.HubInput, int, error) {
	mgr := st.Managers[name]
	if mgr == nil || mgr.Connected.IsZero() {
		return "", nil, 0, fmt.Errorf("unconnected manager %v", name)
	}
	if len(del) != 0 {
		deletedFromHub := false
		for _, sig := range del {
			if _, ok := mgr.Corpus.Records[sig]; !ok {
				continue
			}
			mgr.Corpus.Delete(sig)
			if st.releaseCorpusKey(sig) {
				deletedFromHub = true
			}
		}
		if err := mgr.Corpus.Flush(); err != nil {
			log.Logf(0, "failed to flush corpus database: %v", err)
		}
		if deletedFromHub {
			st.maybeCompactCorpusOrder()
			if err := st.Corpus.Flush(); err != nil {
				log.Logf(0, "failed to flush corpus database: %v", err)
			}
		}
	}
	st.addInputs(mgr, add)
	progs, more := st.pendingInputs(mgr)
	mgr.Added += len(add)
	mgr.Deleted += len(del)
	mgr.New += len(progs)
	// Update seq file b/c PurgeOldManagers looks at it to detect inactive managers.
	saveSeqFile(mgr.corpusSeqFile, mgr.corpusSeq)
	return mgr.Domain, progs, more, nil
}

func (st *State) AddRepro(name string, repro []byte) error {
	mgr := st.Managers[name]
	if mgr == nil || mgr.Connected.IsZero() {
		return fmt.Errorf("unconnected manager %v", name)
	}
	sig := hash.String(repro)
	if _, ok := st.Repros.Records[sig]; ok {
		return nil
	}
	calls, ncalls, err := prog.CallSet(repro)
	if err != nil {
		log.Logf(0, "manager %v: failed to extract call set: %v, program:\n%v",
			mgr.name, err, string(repro))
		return nil
	}
	if want := prog.MaxCalls; ncalls > want {
		log.Logf(0, "manager %v: too long repro, ignoring (%v/%v)", mgr.name, ncalls, want)
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
	st.reproCalls[sig] = st.internCalls(calls)
	st.reproOrder = append(st.reproOrder, seqEntry{key: sig, seq: st.reproSeq})
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
	start := findSeqStart(st.reproOrder, mgr.reproSeq+1)
	for _, entry := range st.reproOrder[start:] {
		if mgr.ownRepros[entry.key] {
			continue
		}
		if !managerSupportsAllCalls(mgr.calls, st.reproCalls[entry.key]) {
			continue
		}
		rec := st.Repros.Records[entry.key]
		mgr.RecvRepros++
		mgr.reproSeq = rec.Seq
		saveSeqFile(mgr.reproSeqFile, mgr.reproSeq)
		return rec.Val, nil
	}
	mgr.reproSeq = st.reproSeq
	saveSeqFile(mgr.reproSeqFile, mgr.reproSeq)
	return nil, nil
}

func (st *State) pendingInputs(mgr *Manager) ([]rpctype.HubInput, int) {
	if mgr.corpusSeq == st.corpusSeq {
		return nil, 0
	}
	const (
		// Send at most that many records (rounded up to next seq number).
		maxRecords = 100
		// If we have way too many records to send (more than capRecords),
		// cap total number to capRecords and give up sending all.
		// Otherwise new managers will never chew all this on a busy hub.
		capRecords = 100000
	)
	start := findSeqStart(st.corpusOrder, mgr.corpusSeq+1)
	capStart := findSeqStart(st.corpusOrder, max(mgr.corpusSeq, mgr.capCheckedSeq)+1)
	if len(st.corpusOrder)-capStart > capRecords {
		mgr.capCheckedSeq = st.corpusSeq
		var matched int
		for i := len(st.corpusOrder) - 1; i >= start; i-- {
			if _, ok := st.matchesManager(mgr, st.corpusOrder[i]); !ok {
				continue
			}
			if matched++; matched == capRecords {
				start = i
				for start > 0 && st.corpusOrder[start-1].seq == st.corpusOrder[start].seq {
					start--
				}
				break
			}
		}
	}
	progs := make([]rpctype.HubInput, 0, maxRecords)
	var lastSeq uint64
	maxSeq := st.corpusSeq
	var more int
	for i := start; i < len(st.corpusOrder); i++ {
		entry := st.corpusOrder[i]
		rec, ok := st.matchesManager(mgr, entry)
		if !ok {
			continue
		}
		// Legacy corpus.db files may have multiple records sharing a sequence number;
		// wait for entry.seq > lastSeq so a sequence group is never split across batches.
		// Advance maxSeq to entry.seq - 1 so any non-matching entries between lastSeq and
		// entry.seq are not re-scanned on the next Sync call.
		if len(progs) >= maxRecords && entry.seq > lastSeq {
			maxSeq = entry.seq - 1
			more = len(st.corpusOrder) - i
			break
		}
		progs = append(progs, rpctype.HubInput{
			Domain: st.inputDomain(entry.key, mgr.Domain),
			Prog:   rec.Val,
		})
		lastSeq = rec.Seq
	}
	mgr.corpusSeq = maxSeq
	return progs, more
}

func (st *State) matchesManager(mgr *Manager, entry seqEntry) (db.Record, bool) {
	rec, ok := st.Corpus.Records[entry.key]
	if !ok || rec.Seq != entry.seq {
		return db.Record{}, false
	}
	if _, ok := mgr.Corpus.Records[entry.key]; ok {
		return db.Record{}, false
	}
	meta := st.corpusMeta[entry.key]
	if !managerSupportsAllCalls(mgr.calls, meta.calls) {
		return db.Record{}, false
	}
	return rec, true
}

func findSeqStart(entries []seqEntry, minSeq uint64) int {
	start, _ := slices.BinarySearchFunc(entries, minSeq, func(e seqEntry, target uint64) int {
		return cmp.Compare(e.seq, target)
	})
	return start
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
	sig := hash.String(input)
	meta, inHub := st.corpusMeta[sig]
	if inHub {
		// Reuse the canonical key string from st.corpusMeta so mgr.Corpus.Records
		// shares the same backing byte array.
		sig = meta.key
	} else {
		calls, ncalls, err := prog.CallSet(input)
		if err != nil {
			log.Logf(0, "manager %v: failed to extract call set: %v, program:\n%v", mgr.name, err, string(input))
			return
		}
		if want := prog.MaxCalls; ncalls > want {
			log.Logf(0, "manager %v: too long program, ignoring (%v/%v)", mgr.name, ncalls, want)
			return
		}
		st.corpusSeq++
		st.Corpus.Save(sig, input, st.corpusSeq)
		meta = corpusMeta{
			key:   sig,
			calls: st.internCalls(calls),
		}
		st.corpusOrder = append(st.corpusOrder, seqEntry{key: sig, seq: st.corpusSeq})
	}
	if _, hadInMgr := mgr.Corpus.Records[sig]; !hadInMgr {
		mgr.Corpus.Save(sig, nil, 0)
		meta.refs++
		st.corpusMeta[sig] = meta
	}
}

func (st *State) releaseCorpusKey(sig string) bool {
	meta, ok := st.corpusMeta[sig]
	if !ok {
		return false
	}
	meta.refs--
	if meta.refs > 0 {
		st.corpusMeta[sig] = meta
		return false
	}
	delete(st.corpusMeta, sig)
	st.Corpus.Delete(sig)
	return true
}

func (st *State) maybeCompactCorpusOrder() {
	if len(st.corpusOrder)-len(st.corpusMeta) > max(1024, len(st.corpusMeta)/10) {
		st.compactCorpusOrder()
	}
}

func (st *State) compactCorpusOrder() {
	st.corpusOrder = slices.DeleteFunc(st.corpusOrder, func(e seqEntry) bool {
		rec, ok := st.Corpus.Records[e.key]
		return !ok || rec.Seq != e.seq
	})
}

func (st *State) purgeCorpus() {
	for _, mgr := range st.Managers {
		mgrModified := false
		for sig := range mgr.Corpus.Records {
			meta, ok := st.corpusMeta[sig]
			if !ok {
				mgr.Corpus.Delete(sig)
				mgrModified = true
				continue
			}
			meta.refs++
			st.corpusMeta[sig] = meta
		}
		if mgrModified {
			if err := mgr.Corpus.Flush(); err != nil {
				log.Logf(0, "failed to flush corpus database: %v", err)
			}
		}
	}
	for key := range st.Corpus.Records {
		if meta := st.corpusMeta[key]; meta.refs > 0 {
			continue
		}
		delete(st.corpusMeta, key)
		st.Corpus.Delete(key)
	}
	if err := st.Corpus.Flush(); err != nil {
		log.Logf(0, "failed to flush corpus database: %v", err)
	}
	st.corpusOrder = sortedEntries(st.Corpus.Records)
}

func sortedEntries(records map[string]db.Record) []seqEntry {
	entries := make([]seqEntry, 0, len(records))
	for key, rec := range records {
		entries = append(entries, seqEntry{key: key, seq: rec.Seq})
	}
	slices.SortFunc(entries, func(a, b seqEntry) int {
		if a.seq != b.seq {
			return cmp.Compare(a.seq, b.seq)
		}
		return cmp.Compare(a.key, b.key)
	})
	return entries
}

func managerSupportsAllCalls(mgrCalls []bool, progCalls []uint32) bool {
	for _, id := range progCalls {
		if int(id) >= len(mgrCalls) || !mgrCalls[id] {
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
	writeFile(filename, strconv.AppendUint(nil, seq, 10))
}

func loadSeqFile(filename string) uint64 {
	str, _ := os.ReadFile(filename)
	seq, _ := strconv.ParseUint(string(str), 10, 64)
	return seq
}
