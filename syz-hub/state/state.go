// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package state

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/hash"
	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/prog"
)

// State holds all internal syz-hub state including corpus and information about managers.
// It is persisted to and can be restored from a directory.
type State struct {
	seq      uint64
	dir      string
	Corpus   map[hash.Sig]*Input
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
	Calls     map[string]struct{}
	Corpus    map[hash.Sig]bool
}

// Input holds info about a single corpus program.
type Input struct {
	seq  uint64
	prog []byte
}

// Make creates State and initializes it from dir.
func Make(dir string) (*State, error) {
	st := &State{
		dir:      dir,
		Corpus:   make(map[hash.Sig]*Input),
		Managers: make(map[string]*Manager),
	}

	corpusDir := filepath.Join(st.dir, "corpus")
	os.MkdirAll(corpusDir, 0700)
	inputs, err := ioutil.ReadDir(corpusDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read %v dir: %v", corpusDir, err)
	}
	for _, inp := range inputs {
		data, err := ioutil.ReadFile(filepath.Join(corpusDir, inp.Name()))
		if err != nil {
			return nil, err
		}
		if _, err := prog.CallSet(data); err != nil {
			return nil, err
		}
		parts := strings.Split(inp.Name(), "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("bad file in corpus: %v", inp.Name())
		}
		seq, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("bad file in corpus: %v", inp.Name())
		}
		sig := hash.Hash(data)
		if sig.String() != parts[0] {
			return nil, fmt.Errorf("bad file in corpus: %v, want hash %v", inp.Name(), sig.String())
		}
		st.Corpus[sig] = &Input{
			seq:  seq,
			prog: data,
		}
		if st.seq < seq {
			st.seq = seq
		}
	}

	managersDir := filepath.Join(st.dir, "manager")
	os.MkdirAll(managersDir, 0700)
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

		mgr.Corpus = make(map[hash.Sig]bool)
		corpusDir := filepath.Join(mgr.dir, "corpus")
		os.MkdirAll(corpusDir, 0700)
		corpus, err := ioutil.ReadDir(corpusDir)
		if err != nil {
			return nil, fmt.Errorf("failed to read %v dir: %v", corpusDir, err)
		}
		for _, input := range corpus {
			sig, err := hash.FromString(input.Name())
			if err != nil {
				return nil, fmt.Errorf("bad file in corpus: %v", input.Name())
			}
			mgr.Corpus[sig] = true
		}
	}

	return st, err
}

func (st *State) Connect(name string, fresh bool, calls []string, corpus [][]byte) error {
	st.seq++
	mgr := st.Managers[name]
	if mgr == nil {
		mgr = new(Manager)
		st.Managers[name] = mgr
		mgr.dir = filepath.Join(st.dir, "manager", name)
		os.MkdirAll(mgr.dir, 0700)
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

	corpusDir := filepath.Join(mgr.dir, "corpus")
	os.RemoveAll(corpusDir)
	os.MkdirAll(corpusDir, 0700)
	mgr.Corpus = make(map[hash.Sig]bool)
	for _, prog := range corpus {
		st.addInput(mgr, prog)
	}
	st.purgeCorpus()
	return nil
}

func (st *State) Sync(name string, add [][]byte, del []string) ([][]byte, error) {
	mgr := st.Managers[name]
	if mgr == nil || mgr.Connected.IsZero() {
		return nil, fmt.Errorf("unconnected manager %v", name)
	}
	if len(del) != 0 {
		for _, h := range del {
			sig, err := hash.FromString(h)
			if err != nil {
				Logf(0, "manager %v: bad hash: %v", mgr.name, h)
				continue
			}
			delete(mgr.Corpus, sig)
		}
		st.purgeCorpus()
	}
	if len(add) != 0 {
		st.seq++
		for _, prog := range add {
			st.addInput(mgr, prog)
		}
	}
	inputs, err := st.pendingInputs(mgr)
	mgr.Added += len(add)
	mgr.Deleted += len(del)
	mgr.New += len(inputs)
	return inputs, err
}

func (st *State) pendingInputs(mgr *Manager) ([][]byte, error) {
	if mgr.seq == st.seq {
		return nil, nil
	}
	var inputs [][]byte
	for sig, inp := range st.Corpus {
		if mgr.seq > inp.seq || mgr.Corpus[sig] {
			continue
		}
		calls, err := prog.CallSet(inp.prog)
		if err != nil {
			return nil, fmt.Errorf("failed to extract call set: %v\nprogram: %v", err, string(inp.prog))
		}
		if !managerSupportsAllCalls(mgr.Calls, calls) {
			continue
		}
		inputs = append(inputs, inp.prog)
	}
	mgr.seq = st.seq
	writeFile(filepath.Join(mgr.dir, "seq"), []byte(fmt.Sprint(mgr.seq)))
	return inputs, nil
}

func (st *State) addInput(mgr *Manager, input []byte) {
	if _, err := prog.CallSet(input); err != nil {
		Logf(0, "manager %v: failed to extract call set: %v, program:\n%v", mgr.name, err, string(input))
		return
	}
	sig := hash.Hash(input)
	mgr.Corpus[sig] = true
	fname := filepath.Join(mgr.dir, "corpus", sig.String())
	writeFile(fname, nil)
	if st.Corpus[sig] == nil {
		st.Corpus[sig] = &Input{
			seq:  st.seq,
			prog: input,
		}
		fname := filepath.Join(st.dir, "corpus", fmt.Sprintf("%v-%v", sig.String(), st.seq))
		writeFile(fname, input)
	}
}

func writeFile(name string, data []byte) {
	if err := ioutil.WriteFile(name, data, 0600); err != nil {
		Logf(0, "failed to write file %v: %v", name, err)
	}
}

func (st *State) purgeCorpus() {
	used := make(map[hash.Sig]bool)
	for _, mgr := range st.Managers {
		for sig := range mgr.Corpus {
			used[sig] = true
		}
	}
	for sig, inp := range st.Corpus {
		if used[sig] {
			continue
		}
		delete(st.Corpus, sig)
		os.Remove(filepath.Join(st.dir, "corpus", fmt.Sprintf("%v-%v", sig.String(), inp.seq)))
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
