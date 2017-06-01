// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"testing"
)

func TestBasic(t *testing.T) {
	fn := tempFile(t)
	defer os.Remove(fn)
	db, err := Open(fn)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	if len(db.Records) != 0 {
		t.Fatalf("empty db contains records")
	}
	db.Save("", nil, 0)
	db.Save("1", []byte("ab"), 1)
	db.Save("23", []byte("abcd"), 2)
	checkContents := func(where string) {
		if len(db.Records) != 3 {
			t.Fatalf("bad record count %v %v, want 3", where, len(db.Records))
		}
		for key, rec := range db.Records {
			switch key {
			case "":
				if len(rec.Val) == 0 && rec.Seq == 0 {
					return
				}
			case "1":
				if bytes.Equal(rec.Val, []byte("ab")) && rec.Seq == 1 {
					return
				}
			case "23":
				if bytes.Equal(rec.Val, []byte("abcd")) && rec.Seq == 2 {
					return
				}
			default:
				t.Fatalf("unknown key: %v", key)
			}
			t.Fatalf("bad record for key %v: %+v", key, rec)
		}
	}
	checkContents("after save")
	if err := db.Flush(); err != nil {
		t.Fatalf("failed to flush db: %v", err)
	}
	checkContents("after flush")
	db, err = Open(fn)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	checkContents("after reopen")
}

func TestModify(t *testing.T) {
	fn := tempFile(t)
	defer os.Remove(fn)
	db, err := Open(fn)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	db.Save("1", []byte("ab"), 0)
	db.Save("23", nil, 1)
	db.Save("456", []byte("abcd"), 1)
	db.Save("7890", []byte("a"), 0)
	db.Delete("23")
	db.Save("1", nil, 5)
	db.Save("456", []byte("ef"), 6)
	db.Delete("7890")
	db.Save("456", []byte("efg"), 0)
	db.Save("7890", []byte("bc"), 0)
	checkContents := func(where string) {
		if len(db.Records) != 3 {
			t.Fatalf("bad record count %v %v, want 3", where, len(db.Records))
		}
		for key, rec := range db.Records {
			switch key {
			case "1":
				if len(rec.Val) == 0 && rec.Seq == 5 {
					return
				}
			case "456":
				if bytes.Equal(rec.Val, []byte("efg")) && rec.Seq == 0 {
					return
				}
			case "7890":
				if bytes.Equal(rec.Val, []byte("bc")) && rec.Seq == 0 {
					return
				}
			default:
				t.Fatalf("unknown key: %v", key)
			}
			t.Fatalf("bad record for key %v: %+v", key, rec)
		}
	}
	checkContents("after modification")
	if err := db.Flush(); err != nil {
		t.Fatalf("failed to flush db: %v", err)
	}
	checkContents("after flush")
	db, err = Open(fn)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	checkContents("after reopen")
}

func TestLarge(t *testing.T) {
	fn := tempFile(t)
	defer os.Remove(fn)
	db, err := Open(fn)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	const nrec = 1000
	val := make([]byte, 1000)
	for i := range val {
		val[i] = byte(rand.Intn(256))
	}
	for i := 0; i < nrec; i++ {
		db.Save(fmt.Sprintf("%v", i), val, 0)
	}
	if err := db.Flush(); err != nil {
		t.Fatalf("failed to flush db: %v", err)
	}
	db, err = Open(fn)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	if len(db.Records) != nrec {
		t.Fatalf("wrong record count: %v, want %v", len(db.Records), nrec)
	}
}

func tempFile(t *testing.T) string {
	f, err := ioutil.TempFile("", "syzkaller.test.db")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	f.Close()
	return f.Name()
}
