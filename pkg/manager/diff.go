// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
)

type DiffBug struct {
	Title   string
	Base    DiffBugInfo
	Patched DiffBugInfo
}

func (bug DiffBug) PatchedOnly() bool {
	return bug.Base.NotCrashed && bug.Patched.Crashes > 0
}

func (bug DiffBug) AffectsBoth() bool {
	return bug.Base.Crashes > 0 && bug.Patched.Crashes > 0
}

type DiffBugInfo struct {
	Crashes    int  // Count of detected crashes.
	NotCrashed bool // If were proven not to crash by running a repro.

	// File paths.
	Report   string
	Repro    string
	ReproLog string
	CrashLog string
}

// DiffFuzzerStore provides the functionality of a database of the patch fuzzing.
type DiffFuzzerStore struct {
	BasePath string

	mu   sync.Mutex
	bugs map[string]*DiffBug
}

func (s *DiffFuzzerStore) BaseCrashed(title string, report []byte) {
	s.patch(title, func(obj *DiffBug) {
		obj.Base.Crashes++
		if len(report) > 0 {
			obj.Base.Report = s.saveFile(title, "base_report", report)
		}
	})
}

func (s *DiffFuzzerStore) EverCrashedBase(title string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	obj := s.bugs[title]
	return obj != nil && obj.Base.Crashes > 0
}

func (s *DiffFuzzerStore) BaseNotCrashed(title string) {
	s.patch(title, func(obj *DiffBug) {
		if obj.Base.Crashes == 0 {
			obj.Base.NotCrashed = true
		}
	})
}

func (s *DiffFuzzerStore) PatchedCrashed(title string, report, log []byte) {
	s.patch(title, func(obj *DiffBug) {
		obj.Patched.Crashes++
		if len(report) > 0 {
			obj.Patched.Report = s.saveFile(title, "patched_report", report)
		}
		if len(log) > 0 && obj.Patched.CrashLog == "" {
			obj.Patched.CrashLog = s.saveFile(title, "patched_crash_log", log)
		}
	})
}

func (s *DiffFuzzerStore) SaveRepro(result *ReproResult) {
	title := result.Crash.Report.Title
	if result.Repro != nil {
		// If there's a repro, save under the new title.
		title = result.Repro.Report.Title
	}

	now := time.Now().Unix()
	crashLog := fmt.Sprintf("%v.crash.log", now)
	s.saveFile(title, crashLog, result.Crash.Output)
	log.Logf(0, "%q: saved crash log into %s", title, crashLog)

	s.patch(title, func(obj *DiffBug) {
		if result.Repro != nil {
			obj.Patched.Repro = s.saveFile(title, reproFileName, result.Repro.Prog.Serialize())
		}
		if result.Stats != nil {
			reproLog := fmt.Sprintf("%v.repro.log", now)
			obj.Patched.ReproLog = s.saveFile(title, reproLog, result.Stats.FullLog())
			log.Logf(0, "%q: saved repro log into %s", title, reproLog)
		}
	})
}

func (s *DiffFuzzerStore) List() []DiffBug {
	s.mu.Lock()
	defer s.mu.Unlock()
	var list []DiffBug
	for _, obj := range s.bugs {
		list = append(list, *obj)
	}
	return list
}

func (s *DiffFuzzerStore) saveFile(title, name string, data []byte) string {
	hash := crashHash(title)
	path := filepath.Join(s.BasePath, "crashes", hash)
	osutil.MkdirAll(path)
	osutil.WriteFile(filepath.Join(path, name), data)
	return filepath.Join("crashes", hash, name)
}

func (s *DiffFuzzerStore) patch(title string, cb func(*DiffBug)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bugs == nil {
		s.bugs = map[string]*DiffBug{}
	}
	obj, ok := s.bugs[title]
	if !ok {
		obj = &DiffBug{Title: title}
		s.bugs[title] = obj
	}
	cb(obj)
}
