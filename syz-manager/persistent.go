// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

type Sig [sha1.Size]byte

// PersistentSet is a set of binary blobs with a persistent mirror on disk.
type PersistentSet struct {
	dir string
	m   map[Sig][]byte
	a   [][]byte
}

func hash(data []byte) Sig {
	return Sig(sha1.Sum(data))
}

func newPersistentSet(dir string, verify func(data []byte) bool) *PersistentSet {
	ps := &PersistentSet{
		dir: dir,
		m:   make(map[Sig][]byte),
	}
	os.MkdirAll(dir, 0770)
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Fatalf("error during dir walk: %v\n", err)
		}
		if info.IsDir() {
			return nil
		}
		data, err := ioutil.ReadFile(path)
		if err != nil {
			log.Fatalf("error during file read: %v\n", err)
			return nil
		}
		sig := hash(data)
		if _, ok := ps.m[sig]; ok {
			return nil
		}
		name := info.Name()
		if len(data) == 0 {
			// This can happen is master runs on machine-under-test,
			// and it has crashed midway.
			log.Printf("removing empty file %v", name)
			os.Remove(path)
			return nil
		}
		const hexLen = 2 * sha1.Size
		if len(name) > hexLen+1 && isHexString(name[:hexLen]) && name[hexLen] == '.' {
			return nil // description file
		}
		if len(name) != hexLen || !isHexString(name) {
			log.Fatalf("unknown file in persistent dir %v: %v", dir, name)
		}
		if verify != nil && !verify(data) {
			os.Remove(path)
			return nil
		}
		if name != hex.EncodeToString(sig[:]) {
			log.Printf("bad hash in persistent dir %v for file %v, expect %v", dir, name, hex.EncodeToString(sig[:]))
			if err := ioutil.WriteFile(filepath.Join(ps.dir, hex.EncodeToString(sig[:])), data, 0660); err != nil {
				log.Fatalf("failed to write file: %v", err)
			}
			os.Remove(path)
		}
		ps.m[sig] = data
		ps.a = append(ps.a, data)
		return nil
	})
	return ps
}

func isHexString(s string) bool {
	for _, v := range []byte(s) {
		if v >= '0' && v <= '9' || v >= 'a' && v <= 'f' {
			continue
		}
		return false
	}
	return true
}

func (ps *PersistentSet) add(data []byte) bool {
	sig := hash(data)
	if _, ok := ps.m[sig]; ok {
		return false
	}
	data = append([]byte{}, data...)
	ps.m[sig] = data
	ps.a = append(ps.a, data)
	fname := filepath.Join(ps.dir, hex.EncodeToString(sig[:]))
	if err := ioutil.WriteFile(fname, data, 0660); err != nil {
		log.Fatalf("failed to write file: %v", err)
	}
	return true
}

// addDescription creates a complementary to data file on disk.
func (ps *PersistentSet) addDescription(data []byte, desc []byte, typ string) {
	sig := hash(data)
	fname := filepath.Join(ps.dir, fmt.Sprintf("%v.%v", hex.EncodeToString(sig[:]), typ))
	if err := ioutil.WriteFile(fname, desc, 0660); err != nil {
		log.Fatalf("failed to write file: %v", err)
	}
}

func (ps *PersistentSet) minimize(set map[string]bool) {
	ps.a = nil
	for sig, data := range ps.m {
		s := hex.EncodeToString(sig[:])
		if set[s] {
			ps.a = append(ps.a, data)
		} else {
			delete(ps.m, sig)
			os.Remove(filepath.Join(ps.dir, s))
		}
	}
}
