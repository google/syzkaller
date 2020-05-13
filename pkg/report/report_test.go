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

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
)

var flagUpdate = flag.Bool("update", false, "update test files accordingly to current results")

func TestParse(t *testing.T) {
	forEachFile(t, "report", testParseFile)
}

type ParseTest struct {
	FileName   string
	Log        []byte
	Title      string
	Type       Type
	Frame      string
	StartLine  string
	EndLine    string
	Corrupted  bool
	Suppressed bool
	HasReport  bool
	Report     []byte
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
			ln := s.Text()
			if ln == "" {
				phase = phaseLog
				continue
			}
			parseHeaderLine(t, test, ln)
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

func parseHeaderLine(t *testing.T, test *ParseTest, ln string) {
	const (
		titlePrefix      = "TITLE: "
		typePrefix       = "TYPE: "
		framePrefix      = "FRAME: "
		startPrefix      = "START: "
		endPrefix        = "END: "
		corruptedPrefix  = "CORRUPTED: "
		suppressedPrefix = "SUPPRESSED: "
	)
	switch {
	case strings.HasPrefix(ln, "#"):
	case strings.HasPrefix(ln, titlePrefix):
		test.Title = ln[len(titlePrefix):]
	case strings.HasPrefix(ln, typePrefix):
		switch v := ln[len(typePrefix):]; v {
		case Hang.String():
			test.Type = Hang
		case MemoryLeak.String():
			test.Type = MemoryLeak
		case DataRace.String():
			test.Type = DataRace
		case UnexpectedReboot.String():
			test.Type = UnexpectedReboot
		default:
			t.Fatalf("unknown TYPE value %q", v)
		}
	case strings.HasPrefix(ln, framePrefix):
		test.Frame = ln[len(framePrefix):]
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
			t.Fatalf("unknown CORRUPTED value %q", v)
		}
	case strings.HasPrefix(ln, suppressedPrefix):
		switch v := ln[len(suppressedPrefix):]; v {
		case "Y":
			test.Suppressed = true
		case "N":
			test.Suppressed = false
		default:
			t.Fatalf("unknown SUPPRESSED value %q", v)
		}
	default:
		t.Fatalf("unknown header field %q", ln)
	}
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
	title, corrupted, corruptedReason, suppressed, typ, frame := "", false, "", false, Unknown, ""
	if rep != nil {
		title = rep.Title
		corrupted = rep.Corrupted
		corruptedReason = rep.CorruptedReason
		suppressed = rep.Suppressed
		typ = rep.Type
		frame = rep.Frame
	}
	if title != test.Title || corrupted != test.Corrupted || suppressed != test.Suppressed ||
		typ != test.Type || test.Frame != "" && frame != test.Frame {
		if *flagUpdate && test.StartLine+test.EndLine == "" {
			updateReportTest(t, test, title, corrupted, suppressed, typ, frame)
		}
		t.Fatalf("want:\nTITLE: %s\nTYPE: %v\nFRAME: %v\nCORRUPTED: %v\nSUPPRESSED: %v\n"+
			"got:\nTITLE: %s\nTYPE: %v\nFRAME: %v\nCORRUPTED: %v (%v)\nSUPPRESSED: %v\n",
			test.Title, test.Type, test.Frame, test.Corrupted, test.Suppressed,
			title, typ, frame, corrupted, corruptedReason, suppressed)
	}
	if title != "" && len(rep.Report) == 0 {
		t.Fatalf("found crash message but report is empty")
	}
	if rep == nil {
		return
	}
	checkReport(t, reporter, rep, test)
}

func checkReport(t *testing.T, reporter Reporter, rep *Report, test *ParseTest) {
	if test.HasReport && !bytes.Equal(rep.Report, test.Report) {
		t.Fatalf("extracted wrong report:\n%s\nwant:\n%s", rep.Report, test.Report)
	}
	if !bytes.Equal(rep.Output, test.Log) {
		t.Fatalf("bad Output:\n%s", rep.Output)
	}
	if rep.StartPos != 0 && rep.EndPos != 0 && rep.StartPos >= rep.EndPos {
		t.Fatalf("StartPos=%v >= EndPos=%v", rep.StartPos, rep.EndPos)
	}
	if rep.EndPos > len(rep.Output) {
		t.Fatalf("EndPos=%v > len(Output)=%v", rep.EndPos, len(rep.Output))
	}
	if rep.SkipPos <= rep.StartPos || rep.SkipPos > rep.EndPos {
		t.Fatalf("bad SkipPos=%v: StartPos=%v EndPos=%v", rep.SkipPos, rep.StartPos, rep.EndPos)
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
	if rep.StartPos != 0 {
		// If we parse from StartPos, we must find the same report.
		rep1 := reporter.Parse(test.Log[rep.StartPos:])
		if rep1 == nil || rep1.Title != rep.Title || rep1.StartPos != 0 {
			t.Fatalf("did not find the same report from rep.StartPos=%v", rep.StartPos)
		}
		// If we parse from EndPos, we must not find the same report.
		rep2 := reporter.Parse(test.Log[rep.EndPos:])
		if rep2 != nil && rep2.Title == rep.Title {
			t.Fatalf("found the same report after rep.EndPos=%v", rep.EndPos)
		}
	}
}

func updateReportTest(t *testing.T, test *ParseTest, title string, corrupted, suppressed bool,
	typ Type, frame string) {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "TITLE: %v\n", title)
	if typ != Unknown {
		fmt.Fprintf(buf, "TYPE: %v\n", typ)
	}
	if test.Frame != "" {
		fmt.Fprintf(buf, "FRAME: %v\n", frame)
	}
	if corrupted {
		fmt.Fprintf(buf, "CORRUPTED: Y\n")
	}
	if suppressed {
		fmt.Fprintf(buf, "SUPPRESSED: Y\n")
	}
	fmt.Fprintf(buf, "\n%s", test.Log)
	if test.HasReport {
		fmt.Fprintf(buf, "REPORT:\n%s", test.Report)
	}
	if err := ioutil.WriteFile(test.FileName, buf.Bytes(), 0640); err != nil {
		t.Logf("failed to update test file: %v", err)
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
	rep := reporter.Parse(report)
	if rep == nil {
		t.Fatalf("did not find crash in the input")
	}
	// Parse doesn't generally run on already symbolized output,
	// but here we run it on symbolized output because we can't symbolize in tests.
	// The problem is with duplicated lines due to inlined frames,
	// Parse can strip such report after first title line because it thinks
	// that the duplicated title line is beginning on another report.
	// In such case we restore whole report, but still keep StartPos that
	// Parse produces at least in some cases.
	if !bytes.HasSuffix(report, rep.Report) {
		rep.Report = report
		rep.StartPos = 0
	}
	if err := reporter.Symbolize(rep); err != nil {
		t.Fatalf("failed to symbolize report: %v", err)
	}
	if rep.guiltyFile != file {
		t.Fatalf("got guilty %q, want %q", rep.guiltyFile, file)
	}
}

func forEachFile(t *testing.T, dir string, fn func(t *testing.T, reporter Reporter, fn string)) {
	for os := range ctors {
		if os == "windows" {
			continue // not implemented
		}
		cfg := &mgrconfig.Config{
			TargetOS:   os,
			TargetArch: "amd64",
		}
		reporter, err := NewReporter(cfg)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range readDir(t, filepath.Join("testdata", os, dir)) {
			t.Run(fmt.Sprintf("%v/%v", os, filepath.Base(file)), func(t *testing.T) {
				fn(t, reporter, file)
			})
		}
		for _, file := range readDir(t, filepath.Join("testdata", "all", dir)) {
			t.Run(fmt.Sprintf("%v/all/%v", os, filepath.Base(file)), func(t *testing.T) {
				fn(t, reporter, file)
			})
		}
	}
}

func readDir(t *testing.T, dir string) (files []string) {
	if !osutil.IsExist(dir) {
		return nil
	}
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	testFilenameRe := regexp.MustCompile("^[0-9]+$")
	for _, ent := range entries {
		if !testFilenameRe.MatchString(ent.Name()) {
			continue
		}
		files = append(files, filepath.Join(dir, ent.Name()))
	}
	return
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

func TestFuzz(t *testing.T) {
	for _, data := range []string{
		"kernel panicType 'help' for a list of commands",
		"0000000000000000000\n\n\n\n\n\nBooting the kernel.",
		"ZIRCON KERNEL PANICHalted",
		"BUG:Disabling lock debugging due to kernel taint",
		"[0.0] WARNING: ? 0+0x0/0",
		"BUG: login: [0.0] ",
		"cleaned vnod\re",
		"kernel\r:",
	} {
		Fuzz([]byte(data)[:len(data):len(data)])
	}
}
