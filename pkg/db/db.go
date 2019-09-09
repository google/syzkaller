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
	"io/ioutil"
	"os"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

type DB struct {
	Version uint64            // arbitrary user version (0 for new database)
	Records map[string]Record // in-memory cache, must not be modified directly

	filename    string
	uncompacted int           // number of records in the file
	pending     *bytes.Buffer // pending writes to the file
}

type Record struct {
	Val []byte
	Seq uint64
}

func Open(filename string) (*DB, error) {
	db := &DB{
		filename: filename,
	}
	f, err := os.OpenFile(db.filename, os.O_RDONLY|os.O_CREATE, osutil.DefaultFilePerm)
	if err != nil {
		return nil, err
	}
	db.Version, db.Records, db.uncompacted = deserializeDB(bufio.NewReader(f))
	f.Close()
	if len(db.Records) == 0 || db.uncompacted/10*9 > len(db.Records) {
		if err := db.compact(); err != nil {
			return nil, err
		}
	}
	return db, nil
}

func (db *DB) Save(key string, val []byte, seq uint64) {
	if seq == seqDeleted {
		panic("reserved seq")
	}
	if rec, ok := db.Records[key]; ok && seq == rec.Seq && bytes.Equal(val, rec.Val) {
		return
	}
	db.Records[key] = Record{val, seq}
	db.serialize(key, val, seq)
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

func (db *DB) Flush() error {
	if db.uncompacted/10*9 > len(db.Records) {
		return db.compact()
	}
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
	return nil
}

func (db *DB) BumpVersion(version uint64) error {
	if db.Version == version {
		return db.Flush()
	}
	db.Version = version
	return db.compact()
}

func (db *DB) compact() error {
	buf := new(bytes.Buffer)
	serializeHeader(buf, db.Version)
	for key, rec := range db.Records {
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
	db.uncompacted = len(db.Records)
	db.pending = nil
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

func deserializeDB(r *bufio.Reader) (version uint64, records map[string]Record, uncompacted int) {
	records = make(map[string]Record)
	ver, err := deserializeHeader(r)
	if err != nil {
		log.Logf(0, "failed to deserialize database header: %v", err)
		return
	}
	version = ver
	for {
		key, val, seq, err := deserializeRecord(r)
		if err == io.EOF {
			return
		}
		if err != nil {
			log.Logf(0, "failed to deserialize database record: %v", err)
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
		if val, err = ioutil.ReadAll(fr); err != nil {
			return
		}
		fr.Close()
	}
	return
}

// Create creates a new database in the specified file with the specified records.
func Create(filename string, version uint64, records []Record) error {
	os.Remove(filename)
	db, err := Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open database file: %v", err)
	}
	if err := db.BumpVersion(version); err != nil {
		return fmt.Errorf("failed to bump database version: %v", err)
	}
	for _, rec := range records {
		db.Save(hash.String(rec.Val), rec.Val, rec.Seq)
	}
	if err := db.Flush(); err != nil {
		return fmt.Errorf("failed to save database file: %v", err)
	}
	return nil
}

func ReadCorpus(filename string, target *prog.Target) (progs []*prog.Prog, err error) {
	if filename == "" {
		return
	}
	db, err := Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open database file: %v", err)
	}
	for _, rec := range db.Records {
		p, err := target.Deserialize(rec.Val, prog.NonStrict)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize corpus program: %v", err)
		}
		progs = append(progs, p)
	}
	return progs, nil
}
