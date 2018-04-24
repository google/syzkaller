// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
)

var flagUpdate = flag.Bool("update", false, "update test files accordingly to current results")

func TestParse(t *testing.T) {
	forEachFile(t, "report", testParseFile)
}

type ParseTest struct {
	FileName  string
	Log       []byte
	Title     string
	StartLine string
	EndLine   string
	Corrupted bool
	HasReport bool
	Report    []byte
}

func testParseFile(t *testing.T, reporter Reporter, fn string) {
	input, err := os.Open(fn)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	const (
		phaseHeaders = iota
		phaseLog
		phaseReport
	)
	phase := phaseHeaders
	test := &ParseTest{
		FileName: fn,
	}
	prevEmptyLine := false
	s := bufio.NewScanner(input)
	for s.Scan() {
		switch phase {
		case phaseHeaders:
			const (
				titlePrefix     = "TITLE: "
				startPrefix     = "START: "
				endPrefix       = "END: "
				corruptedPrefix = "CORRUPTED: "
			)
			switch ln := s.Text(); {
			case strings.HasPrefix(ln, "#"):
			case strings.HasPrefix(ln, titlePrefix):
				test.Title = ln[len(titlePrefix):]
			case strings.HasPrefix(ln, startPrefix):
				test.StartLine = ln[len(startPrefix):]
			case strings.HasPrefix(ln, endPrefix):
				test.EndLine = ln[len(endPrefix):]
			case strings.HasPrefix(ln, corruptedPrefix):
				switch v := ln[len(corruptedPrefix):]; v {
				case "Y":
					test.Corrupted = true
				case "N":
					test.Corrupted = false
				default:
					t.Fatalf("unknown corrupted value %q", v)
				}
			case ln == "":
				phase = phaseLog
			default:
				t.Fatalf("unknown header field %q", ln)
			}
		case phaseLog:
			if prevEmptyLine && string(s.Bytes()) == "REPORT:" {
				test.HasReport = true
				phase = phaseReport
			} else {
				test.Log = append(test.Log, s.Bytes()...)
				test.Log = append(test.Log, '\n')
			}
		case phaseReport:
			test.Report = append(test.Report, s.Bytes()...)
			test.Report = append(test.Report, '\n')
		}
		prevEmptyLine = len(s.Bytes()) == 0
	}
	if s.Err() != nil {
		t.Fatalf("file scanning error: %v", s.Err())
	}
	if len(test.Log) == 0 {
		t.Fatalf("can't find log in input file")
	}
	testParseImpl(t, reporter, test)
	// In some cases we get output with \r\n for line endings,
	// ensure that regexps are not confused by this.
	bytes.Replace(test.Log, []byte{'\n'}, []byte{'\r', '\n'}, -1)
	testParseImpl(t, reporter, test)
}

func testParseImpl(t *testing.T, reporter Reporter, test *ParseTest) {
	rep := reporter.Parse(test.Log)
	containsCrash := reporter.ContainsCrash(test.Log)
	expectCrash := (test.Title != "")
	if expectCrash && !containsCrash {
		t.Fatalf("ContainsCrash did not find crash")
	}
	if !expectCrash && containsCrash {
		t.Fatalf("ContainsCrash found unexpected crash")
	}
	if rep != nil && rep.Title == "" {
		t.Fatalf("found crash, but title is empty")
	}
	title, corrupted, corruptedReason := "", false, ""
	if rep != nil {
		title = rep.Title
		corrupted = rep.Corrupted
		corruptedReason = rep.corruptedReason
	}
	if title != test.Title || corrupted != test.Corrupted {
		if *flagUpdate && test.StartLine == "" && test.EndLine == "" {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "TITLE: %v\n", title)
			if corrupted {
				fmt.Fprintf(buf, "CORRUPTED: Y\n")
			}
			fmt.Fprintf(buf, "\n%s", test.Log)
			if test.HasReport {
				fmt.Fprintf(buf, "REPORT:\n%s", test.Report)
			}
			if err := ioutil.WriteFile(test.FileName, buf.Bytes(), 0640); err != nil {
				t.Logf("failed to update test file: %v", err)
			}
		}
		t.Fatalf("want:\nTITLE: %s\nCORRUPTED: %v\ngot:\nTITLE: %s\nCORRUPTED: %v (%v)\n",
			test.Title, test.Corrupted, title, corrupted, corruptedReason)
	}
	if title != "" && len(rep.Report) == 0 {
		t.Fatalf("found crash message but report is empty")
	}
	if rep != nil {
		if test.HasReport && !bytes.Equal(rep.Report, test.Report) {
			t.Fatalf("extracted wrong report:\n%s\nwant:\n%s", rep.Report, test.Report)
		}
		if !bytes.Equal(rep.Output, test.Log) {
			t.Fatalf("bad Output:\n%s", rep.Output)
		}
		if test.StartLine != "" {
			if test.EndLine == "" {
				test.EndLine = test.StartLine
			}
			startPos := bytes.Index(test.Log, []byte(test.StartLine))
			endPos := bytes.Index(test.Log, []byte(test.EndLine)) + len(test.EndLine)
			if rep.StartPos != startPos || rep.EndPos != endPos {
				t.Fatalf("bad start/end pos %v-%v, want %v-%v, line %q",
					rep.StartPos, rep.EndPos, startPos, endPos,
					string(test.Log[rep.StartPos:rep.EndPos]))
			}
		}
	}
}

func TestGuiltyFile(t *testing.T) {
	forEachFile(t, "guilty", testGuiltyFile)
}

func testGuiltyFile(t *testing.T, reporter Reporter, fn string) {
	data, err := ioutil.ReadFile(fn)
	if err != nil {
		t.Fatal(err)
	}
	for bytes.HasPrefix(data, []byte{'#'}) {
		nl := bytes.Index(data, []byte{'\n'})
		if nl == -1 {
			t.Fatalf("unterminated comment in file")
		}
		data = data[nl+1:]
	}
	const prefix = "FILE: "
	if !bytes.HasPrefix(data, []byte(prefix)) {
		t.Fatalf("no %v prefix in file", prefix)
	}
	nlnl := bytes.Index(data[len(prefix):], []byte{'\n', '\n'})
	if nlnl == -1 {
		t.Fatalf("no \\n\\n in file")
	}
	file := string(data[len(prefix) : len(prefix)+nlnl])
	report := data[len(prefix)+nlnl:]
	if guilty := reporter.(guilter).extractGuiltyFile(report); guilty != file {
		t.Fatalf("got guilty %q, want %q", guilty, file)
	}
}

func forEachFile(t *testing.T, dir string, fn func(t *testing.T, reporter Reporter, fn string)) {
	testFilenameRe := regexp.MustCompile("^[0-9]+$")
	for os := range ctors {
		path := filepath.Join("testdata", os, dir)
		if !osutil.IsExist(path) {
			continue
		}
		files, err := ioutil.ReadDir(path)
		if err != nil {
			t.Fatal(err)
		}
		reporter, err := NewReporter(os, "", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			if !testFilenameRe.MatchString(file.Name()) {
				continue
			}
			t.Run(fmt.Sprintf("%v/%v", os, file.Name()), func(t *testing.T) {
				fn(t, reporter, filepath.Join(path, file.Name()))
			})
		}
	}
}

func TestReplace(t *testing.T) {
	tests := []struct {
		where  string
		start  int
		end    int
		what   string
		result string
	}{
		{"0123456789", 3, 5, "abcdef", "012abcdef56789"},
		{"0123456789", 3, 5, "ab", "012ab56789"},
		{"0123456789", 3, 3, "abcd", "012abcd3456789"},
		{"0123456789", 0, 2, "abcd", "abcd23456789"},
		{"0123456789", 0, 0, "ab", "ab0123456789"},
		{"0123456789", 10, 10, "ab", "0123456789ab"},
		{"0123456789", 8, 10, "ab", "01234567ab"},
		{"0123456789", 5, 5, "", "0123456789"},
		{"0123456789", 3, 8, "", "01289"},
		{"0123456789", 3, 8, "ab", "012ab89"},
		{"0123456789", 0, 5, "a", "a56789"},
		{"0123456789", 5, 10, "ab", "01234ab"},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%+v", test), func(t *testing.T) {
			result := replace([]byte(test.where), test.start, test.end, []byte(test.what))
			if test.result != string(result) {
				t.Errorf("want '%v', got '%v'", test.result, string(result))
			}
		})
	}
}
