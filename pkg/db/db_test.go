// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
)

func TestBasic(t *testing.T) {
	fn := tempFile(t)
	defer os.Remove(fn)
	db, err := Open(fn, false)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	if len(db.Records) != 0 {
		t.Fatalf("empty db contains records")
	}
	db.Save("", nil, 0)
	db.Save("1", []byte("ab"), 1)
	db.Save("23", []byte("abcd"), 2)

	want := map[string]Record{
		"":   {Val: nil, Seq: 0},
		"1":  {Val: []byte("ab"), Seq: 1},
		"23": {Val: []byte("abcd"), Seq: 2},
	}
	if !reflect.DeepEqual(db.Records, want) {
		t.Fatalf("bad db after save: %v, want: %v", db.Records, want)
	}
	if err := db.Flush(); err != nil {
		t.Fatalf("failed to flush db: %v", err)
	}
	if !reflect.DeepEqual(db.Records, want) {
		t.Fatalf("bad db after flush: %v, want: %v", db.Records, want)
	}
	db, err = Open(fn, false)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	if !reflect.DeepEqual(db.Records, want) {
		t.Fatalf("bad db after reopen: %v, want: %v", db.Records, want)
	}
}

func TestModify(t *testing.T) {
	fn := tempFile(t)
	defer os.Remove(fn)
	db, err := Open(fn, false)
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

	want := map[string]Record{
		"1":    {Val: nil, Seq: 5},
		"456":  {Val: []byte("efg"), Seq: 0},
		"7890": {Val: []byte("bc"), Seq: 0},
	}
	if !reflect.DeepEqual(db.Records, want) {
		t.Fatalf("bad db after modification: %v, want: %v", db.Records, want)
	}
	if err := db.Flush(); err != nil {
		t.Fatalf("failed to flush db: %v", err)
	}
	if !reflect.DeepEqual(db.Records, want) {
		t.Fatalf("bad db after flush: %v, want: %v", db.Records, want)
	}
	db, err = Open(fn, false)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	if !reflect.DeepEqual(db.Records, want) {
		t.Fatalf("bad db after reopen: %v, want: %v", db.Records, want)
	}
}

func TestLarge(t *testing.T) {
	fn := tempFile(t)
	defer os.Remove(fn)
	db, err := Open(fn, false)
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
	db, err = Open(fn, false)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	if len(db.Records) != nrec {
		t.Fatalf("wrong record count: %v, want %v", len(db.Records), nrec)
	}
}

func TestOpenInvalid(t *testing.T) {
	f, err := os.CreateTemp("", "syz-db-test")
	if err != nil {
		t.Error(err)
	}

	defer f.Close()
	defer os.Remove(f.Name())
	if _, err := f.Write([]byte(`some invalid data`)); err != nil {
		t.Error(err)
	}
	if db, err := Open(f.Name(), true); err == nil {
		t.Fatal("opened invalid db")
	} else if db == nil {
		t.Fatal("db is nil")
	}
}

func TestOpenInaccessible(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("opening inaccessible file won't fail under root")
	}
	f, err := os.CreateTemp("", "syz-db-test")
	if err != nil {
		t.Error(err)
	}
	f.Close()
	os.Chmod(f.Name(), 0)
	defer os.Chmod(f.Name(), 0777)
	defer os.Remove(f.Name())
	if db, err := Open(f.Name(), false); err == nil {
		t.Fatal("opened inaccessible db")
	} else if db != nil {
		t.Fatal("db is not nil")
	}
}

func TestOpenCorrupted(t *testing.T) {
	fn := tempFile(t)
	defer os.Remove(fn)
	db, err := Open(fn, false)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	// Write 1000 records, then wipe half of the file and test that we
	// (1) get an error, (2) still get 450-550 records.
	for i := 0; i < 1000; i++ {
		db.Save(fmt.Sprintf("%v", i), []byte{byte(i)}, 0)
	}
	if err := db.Flush(); err != nil {
		t.Fatalf("failed to flush db: %v", err)
	}
	data, err := os.ReadFile(fn)
	if err != nil {
		t.Fatalf("failed to read db: %v", err)
	}
	for i := len(data) / 2; i < len(data); i++ {
		data[i] = 0
	}
	if err := osutil.WriteFile(fn, data); err != nil {
		t.Fatalf("failed to write db: %v", err)
	}
	db, err = Open(fn, true)
	if err == nil {
		t.Fatalf("no error for corrutped db")
	}
	t.Logf("records %v, error: %v", len(db.Records), err)
	if len(db.Records) < 450 || len(db.Records) > 550 {
		t.Fatalf("wrong record count: %v", len(db.Records))
	}
}

func tempFile(t *testing.T) string {
	fn, err := osutil.TempFile("syzkaller.test.db")
	if err != nil {
		t.Fatal(err)
	}
	return fn
}
