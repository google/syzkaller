// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package db implements a simple key-value database.
// The database is cached in memory and mirrored on disk.
// It is used to store corpus in syz-manager and syz-hub.
// The database strives to minimize number of disk accesses
// as they can be slow in virtualized environments (GCE).
package db

import (
	"bufio"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

type DB struct {
	Version uint64            // arbitrary user version (0 for new database)
	Records map[string]Record // in-memory cache, must not be modified directly

	filename      string
	uncompacted   int           // number of records in the file
	pending       *bytes.Buffer // pending writes to the file
	dataDiscarded bool
}

type Record struct {
	Val []byte
	Seq uint64
}

// Open opens the specified database file.
// If the database is corrupted and reading failed, then it returns an non-nil db
// with whatever records were recovered and a non-nil error at the same time.
func Open(filename string, repair bool) (*DB, error) {
	db := &DB{
		filename: filename,
	}
	var deserializeErr error
	db.Version, db.Records, db.uncompacted, deserializeErr = deserializeFile(db.filename)
	// Deserialization error is considered a "soft" error if repair == true,
	// but compact below ensures that the file is at least writable.
	if deserializeErr != nil && !repair {
		return nil, deserializeErr
	}
	if err := db.compact(); err != nil {
		return nil, err
	}
	return db, deserializeErr
}

func (db *DB) Save(key string, val []byte, seq uint64) {
	if seq == seqDeleted {
		panic("reserved seq")
	}
	// If data is discarded, we assume key identifies data (data hash).
	if rec, ok := db.Records[key]; ok && seq == rec.Seq && (db.dataDiscarded || bytes.Equal(val, rec.Val)) {
		return
	}
	db.serialize(key, val, seq)
	if db.dataDiscarded {
		val = nil
	}
	db.Records[key] = Record{val, seq}
	db.uncompacted++
}

func (db *DB) Delete(key string) {
	if _, ok := db.Records[key]; !ok {
		return
	}
	delete(db.Records, key)
	db.serialize(key, nil, seqDeleted)
	db.uncompacted++
}

// DiscardData discards all record's values from memory.
// This allows to save memory if values are not needed anymore,
// but in exchange every compaction will need to re-read all data from disk.
func (db *DB) DiscardData() {
	db.dataDiscarded = true
	for key, rec := range db.Records {
		rec.Val = nil
		db.Records[key] = rec
	}
}

func (db *DB) Flush() error {
	if db.pending == nil {
		return nil
	}
	f, err := os.OpenFile(db.filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, osutil.DefaultFilePerm)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(db.pending.Bytes()); err != nil {
		return err
	}
	db.pending = nil
	if db.uncompacted/10*9 < len(db.Records) {
		return nil
	}
	return db.compact()
}

func (db *DB) BumpVersion(version uint64) error {
	if err := db.Flush(); err != nil {
		return err
	}
	if db.Version == version {
		return nil
	}
	db.Version = version
	return db.compact()
}

func (db *DB) compact() error {
	if db.pending != nil {
		panic("compacting with pending records")
	}
	records := db.Records
	if db.dataDiscarded {
		var err error
		_, records, _, err = deserializeFile(db.filename)
		if err != nil {
			return err
		}
	}
	buf := new(bytes.Buffer)
	serializeHeader(buf, db.Version)
	for key, rec := range records {
		serializeRecord(buf, key, rec.Val, rec.Seq)
	}
	f, err := os.Create(db.filename + ".tmp")
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(buf.Bytes()); err != nil {
		return err
	}
	f.Close()
	if err := osutil.Rename(f.Name(), db.filename); err != nil {
		return err
	}
	db.uncompacted = len(records)
	return nil
}

func (db *DB) serialize(key string, val []byte, seq uint64) {
	if db.pending == nil {
		db.pending = new(bytes.Buffer)
	}
	serializeRecord(db.pending, key, val, seq)
}

const (
	dbMagic    = uint32(0xbaddb)
	recMagic   = uint32(0xfee1bad)
	curVersion = uint32(2)
	seqDeleted = ^uint64(0)
)

func serializeHeader(w *bytes.Buffer, version uint64) {
	binary.Write(w, binary.LittleEndian, dbMagic)
	binary.Write(w, binary.LittleEndian, curVersion)
	binary.Write(w, binary.LittleEndian, version)
}

func serializeRecord(w *bytes.Buffer, key string, val []byte, seq uint64) {
	binary.Write(w, binary.LittleEndian, recMagic)
	binary.Write(w, binary.LittleEndian, uint32(len(key)))
	w.WriteString(key)
	binary.Write(w, binary.LittleEndian, seq)
	if seq == seqDeleted {
		if len(val) != 0 {
			panic("deleting record with value")
		}
		return
	}
	if len(val) == 0 {
		binary.Write(w, binary.LittleEndian, uint32(len(val)))
	} else {
		lenPos := len(w.Bytes())
		binary.Write(w, binary.LittleEndian, uint32(0))
		startPos := len(w.Bytes())
		fw, err := flate.NewWriter(w, flate.BestCompression)
		if err != nil {
			panic(err)
		}
		if _, err := fw.Write(val); err != nil {
			panic(err)
		}
		fw.Close()
		binary.Write(bytes.NewBuffer(w.Bytes()[lenPos:lenPos:lenPos+8]), binary.LittleEndian, uint32(len(w.Bytes())-startPos))
	}
}

func deserializeFile(filename string) (version uint64, records map[string]Record, uncompacted int, err error) {
	f, err := os.OpenFile(filename, os.O_RDONLY|os.O_CREATE, osutil.DefaultFilePerm)
	if err != nil {
		return 0, nil, 0, err
	}
	defer f.Close()
	return deserializeDB(bufio.NewReader(f))
}

func deserializeDB(r *bufio.Reader) (version uint64, records map[string]Record, uncompacted int, err0 error) {
	records = make(map[string]Record)
	ver, err := deserializeHeader(r)
	if err != nil {
		err0 = fmt.Errorf("failed to deserialize database header: %w", err)
		return
	}
	version = ver
	for {
		key, val, seq, err := deserializeRecord(r)
		if err == io.EOF {
			return
		}
		if err != nil {
			err0 = fmt.Errorf("failed to deserialize database record: %w", err)
			return
		}
		uncompacted++
		if seq == seqDeleted {
			delete(records, key)
		} else {
			records[key] = Record{val, seq}
		}
	}
}

func deserializeHeader(r *bufio.Reader) (uint64, error) {
	var magic, ver uint32
	if err := binary.Read(r, binary.LittleEndian, &magic); err != nil {
		if err == io.EOF {
			return 0, nil
		}
		return 0, err
	}
	if magic != dbMagic {
		return 0, fmt.Errorf("bad db header: 0x%x", magic)
	}
	if err := binary.Read(r, binary.LittleEndian, &ver); err != nil {
		return 0, err
	}
	if ver == 0 || ver > curVersion {
		return 0, fmt.Errorf("bad db version: %v", ver)
	}
	var userVer uint64
	if ver >= 2 {
		if err := binary.Read(r, binary.LittleEndian, &userVer); err != nil {
			return 0, err
		}
	}
	return userVer, nil
}

func deserializeRecord(r *bufio.Reader) (key string, val []byte, seq uint64, err error) {
	var magic uint32
	if err = binary.Read(r, binary.LittleEndian, &magic); err != nil {
		return
	}
	if magic != recMagic {
		err = fmt.Errorf("bad record header: 0x%x", magic)
		return
	}
	var keyLen uint32
	if err = binary.Read(r, binary.LittleEndian, &keyLen); err != nil {
		return
	}
	keyBuf := make([]byte, keyLen)
	if _, err = io.ReadFull(r, keyBuf); err != nil {
		return
	}
	key = string(keyBuf)
	if err = binary.Read(r, binary.LittleEndian, &seq); err != nil {
		return
	}
	if seq == seqDeleted {
		return
	}
	var valLen uint32
	if err = binary.Read(r, binary.LittleEndian, &valLen); err != nil {
		return
	}
	if valLen != 0 {
		fr := flate.NewReader(&io.LimitedReader{R: r, N: int64(valLen)})
		if val, err = io.ReadAll(fr); err != nil {
			return
		}
		fr.Close()
	}
	return
}

// Create creates a new database in the specified file with the specified records.
func Create(filename string, version uint64, records []Record) error {
	os.Remove(filename)
	db, err := Open(filename, true)
	if err != nil {
		return fmt.Errorf("failed to open database file: %w", err)
	}
	if err := db.BumpVersion(version); err != nil {
		return fmt.Errorf("failed to bump database version: %w", err)
	}
	for _, rec := range records {
		db.Save(hash.String(rec.Val), rec.Val, rec.Seq)
	}
	if err := db.Flush(); err != nil {
		return fmt.Errorf("failed to save database file: %w", err)
	}
	return nil
}

func ReadCorpus(filename string, target *prog.Target) (progs []*prog.Prog, err error) {
	if filename == "" {
		return
	}
	db, err := Open(filename, false)
	if err != nil {
		return nil, fmt.Errorf("failed to open database file: %w", err)
	}
	recordKeys := make([]string, 0, len(db.Records))
	for key := range db.Records {
		recordKeys = append(recordKeys, key)
	}
	sort.Strings(recordKeys)
	for _, key := range recordKeys {
		p, err := target.Deserialize(db.Records[key].Val, prog.NonStrict)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize corpus program: %w", err)
		}
		progs = append(progs, p)
	}
	return progs, nil
}

type DeserializeFailure struct {
	File string
	Err  error
}

func Merge(into string, other []string, target *prog.Target) ([]DeserializeFailure, error) {
	dstDB, err := Open(into, false)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	var failed []DeserializeFailure
	for _, add := range other {
		if addDB, err := Open(add, false); err == nil {
			for key, rec := range addDB.Records {
				dstDB.Save(key, rec.Val, rec.Seq)
			}
			continue
		} else if target == nil {
			return nil, fmt.Errorf("failed to open db %v: %w", add, err)
		}
		data, err := os.ReadFile(add)
		if err != nil {
			return nil, err
		}
		if _, err := target.Deserialize(data, prog.NonStrict); err != nil {
			failed = append(failed, DeserializeFailure{add, err})
		}
		dstDB.Save(hash.String(data), data, 0)
	}
	if err := dstDB.Flush(); err != nil {
		return nil, fmt.Errorf("failed to save db: %w", err)
	}
	return failed, nil
}
