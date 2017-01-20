// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/db"
	"github.com/google/syzkaller/hash"
	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/prog"
)

// PersistentSet is now superseded by db package that stores corpus in a single file.
// This code is left here to convert old corpuses to the new format.
// It needs to be delete in Mar 2017.
func convertPersistentToDB(persistentDir, dbFilename string) error {
	if _, err := os.Stat(persistentDir); err != nil {
		return nil
	}
	persistentCorpus := newPersistentSet(persistentDir, func(data []byte) bool {
		if _, err := prog.Deserialize(data); err != nil {
			Logf(0, "deleting broken program: %v\n%s", err, data)
			return false
		}
		return true
	})
	tmpDB, err := db.Open(dbFilename)
	if err != nil {
		return fmt.Errorf("failed to create corpus database: %v", err)
	}
	for key, data := range persistentCorpus.m {
		tmpDB.Save(key.String(), data, 0)
	}
	if err := tmpDB.Flush(); err != nil {
		return fmt.Errorf("failed to save corpus database: %v", err)
	}
	Logf(0, "converted %v programs to new corpus database format", len(persistentCorpus.m))
	return nil
}

// PersistentSet is a set of binary blobs with a persistent mirror on disk.
type PersistentSet struct {
	dir string
	m   map[hash.Sig][]byte
	a   [][]byte
}

func newPersistentSet(dir string, verify func(data []byte) bool) *PersistentSet {
	ps := &PersistentSet{
		dir: dir,
		m:   make(map[hash.Sig][]byte),
	}
	os.MkdirAll(dir, 0770)
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			Fatalf("error during dir walk: %v\n", err)
		}
		if info.IsDir() {
			if info.Name() == ".git" {
				return filepath.SkipDir // in case corpus is checked in
			}
			return nil
		}
		data, err := ioutil.ReadFile(path)
		if err != nil {
			Fatalf("error during file read: %v\n", err)
			return nil
		}
		sig := hash.Hash(data)
		if _, ok := ps.m[sig]; ok {
			return nil
		}
		name := info.Name()
		if len(data) == 0 {
			// This can happen is master runs on machine-under-test,
			// and it has crashed midway.
			Logf(0, "removing empty file %v", name)
			os.Remove(path)
			return nil
		}
		if _, err := hash.FromString(name); err != nil {
			Logf(0, "unknown file in persistent dir %v: %v", dir, name)
			return nil
		}
		if verify != nil && !verify(data) {
			os.Remove(path)
			return nil
		}
		if name != sig.String() {
			Logf(0, "bad hash in persistent dir %v for file %v, expect %v", dir, name, sig.String())
			if err := ioutil.WriteFile(filepath.Join(ps.dir, sig.String()), data, 0660); err != nil {
				Fatalf("failed to write file: %v", err)
			}
			os.Remove(path)
		}
		ps.m[sig] = data
		ps.a = append(ps.a, data)
		return nil
	})
	return ps
}

func (ps *PersistentSet) add(data []byte) bool {
	sig := hash.Hash(data)
	if _, ok := ps.m[sig]; ok {
		return false
	}
	ps.m[sig] = data
	ps.a = append(ps.a, data)
	fname := filepath.Join(ps.dir, sig.String())
	if err := ioutil.WriteFile(fname, data, 0660); err != nil {
		Fatalf("failed to write file: %v", err)
	}
	return true
}

func (ps *PersistentSet) minimize(set map[string]bool) {
	ps.a = nil
	for sig, data := range ps.m {
		s := sig.String()
		if set[s] {
			ps.a = append(ps.a, data)
		} else {
			delete(ps.m, sig)
			os.Remove(filepath.Join(ps.dir, s))
		}
	}
}
