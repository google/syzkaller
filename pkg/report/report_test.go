// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/sys/targets"
)

var flagUpdate = flag.Bool("update", false, "update test files accordingly to current results")

func TestParse(t *testing.T) {
	forEachFile(t, "report", testParseFile)
}

type ParseTest struct {
	FileName   string
	Log        []byte
	Title      string
	AltTitles  []string
	Type       crash.Type
	Frame      string
	StartLine  string
	EndLine    string
	Corrupted  bool
	Suppressed bool
	HasReport  bool
	Report     []byte
	Executor   string
	// Only used in report parsing:
	corruptedReason string
}

func (test *ParseTest) Equal(other *ParseTest) bool {
	if test.Title != other.Title ||
		test.Corrupted != other.Corrupted ||
		test.Suppressed != other.Suppressed ||
		test.Type != other.Type {
		return false
	}
	if !reflect.DeepEqual(test.AltTitles, other.AltTitles) {
		return false
	}
	if test.Frame != "" && test.Frame != other.Frame {
		return false
	}
	return test.Executor == other.Executor
}

func (test *ParseTest) Headers(includeFrame bool) []byte {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "TITLE: %v\n", test.Title)
	for _, t := range test.AltTitles {
		fmt.Fprintf(buf, "ALT: %v\n", t)
	}
	if test.Type != crash.UnknownType {
		fmt.Fprintf(buf, "TYPE: %v\n", test.Type)
	}
	if includeFrame {
		fmt.Fprintf(buf, "FRAME: %v\n", test.Frame)
	}
	if test.Corrupted {
		fmt.Fprintf(buf, "CORRUPTED: Y\n")
	}
	if test.Suppressed {
		fmt.Fprintf(buf, "SUPPRESSED: Y\n")
	}
	if test.Executor != "" {
		fmt.Fprintf(buf, "EXECUTOR: %s\n", test.Executor)
	}
	return buf.Bytes()
}

func testParseFile(t *testing.T, reporter *Reporter, fn string) {
	data, err := os.ReadFile(fn)
	if err != nil {
		t.Fatal(err)
	}
	// Strip all \r from reports because the merger removes it.
	data = bytes.ReplaceAll(data, []byte{'\r'}, nil)
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
	s := bufio.NewScanner(bytes.NewReader(data))
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
	sort.Strings(test.AltTitles)
	testParseImpl(t, reporter, test)
}

func parseHeaderLine(t *testing.T, test *ParseTest, ln string) {
	const (
		titlePrefix      = "TITLE: "
		altTitlePrefix   = "ALT: "
		typePrefix       = "TYPE: "
		framePrefix      = "FRAME: "
		startPrefix      = "START: "
		endPrefix        = "END: "
		corruptedPrefix  = "CORRUPTED: "
		suppressedPrefix = "SUPPRESSED: "
		executorPrefix   = "EXECUTOR: "
	)
	switch {
	case strings.HasPrefix(ln, "#"):
	case strings.HasPrefix(ln, titlePrefix):
		test.Title = ln[len(titlePrefix):]
	case strings.HasPrefix(ln, altTitlePrefix):
		test.AltTitles = append(test.AltTitles, ln[len(altTitlePrefix):])
	case strings.HasPrefix(ln, typePrefix):
		test.Type = crash.Type(ln[len(typePrefix):])
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
	case strings.HasPrefix(ln, executorPrefix):
		test.Executor = ln[len(executorPrefix):]
	default:
		t.Fatalf("unknown header field %q", ln)
	}
}

func testFromReport(rep *Report) *ParseTest {
	if rep == nil {
		return &ParseTest{}
	}
	ret := &ParseTest{
		Title:           rep.Title,
		AltTitles:       rep.AltTitles,
		Corrupted:       rep.Corrupted,
		corruptedReason: rep.CorruptedReason,
		Suppressed:      rep.Suppressed,
		Type:            rep.Type,
		Frame:           rep.Frame,
	}
	if rep.Executor != nil {
		ret.Executor = fmt.Sprintf("proc=%d, id=%d", rep.Executor.ProcID, rep.Executor.ExecID)
	}
	sort.Strings(ret.AltTitles)
	return ret
}

func testParseImpl(t *testing.T, reporter *Reporter, test *ParseTest) {
	rep := reporter.Parse(test.Log)
	containsCrash := reporter.ContainsCrash(test.Log)
	expectCrash := (test.Title != "")
	if expectCrash && !containsCrash {
		t.Fatalf("did not find crash")
	}
	if !expectCrash && containsCrash {
		t.Fatalf("found unexpected crash")
	}
	if rep != nil && rep.Title == "" {
		t.Fatalf("found crash, but title is empty")
	}
	if rep != nil && rep.Type == unspecifiedType {
		t.Fatalf("unspecifiedType leaked outside")
	}
	parsed := testFromReport(rep)
	if !test.Equal(parsed) {
		if *flagUpdate && test.StartLine+test.EndLine == "" {
			updateReportTest(t, test, parsed)
		}
		t.Fatalf("want:\n%s\ngot:\n%sCorrupted reason: %q",
			test.Headers(true), parsed.Headers(true), parsed.corruptedReason)
	}
	if parsed.Title != "" && len(rep.Report) == 0 {
		t.Fatalf("found crash message but report is empty")
	}
	if rep == nil {
		return
	}
	checkReport(t, reporter, rep, test)
}

func checkReport(t *testing.T, reporter *Reporter, rep *Report, test *ParseTest) {
	if test.HasReport && !bytes.Equal(rep.Report, test.Report) {
		t.Fatalf("extracted wrong report:\n%s\nwant:\n%s", rep.Report, test.Report)
	}
	if !bytes.Equal(rep.Output, test.Log) {
		t.Fatalf("bad Output:\n%s", rep.Output)
	}
	if rep.StartPos != 0 && rep.EndPos != 0 && rep.StartPos >= rep.EndPos {
		t.Fatalf("StartPos %v >= EndPos %v", rep.StartPos, rep.EndPos)
	}
	if rep.EndPos > len(rep.Output) {
		t.Fatalf("EndPos %v > len(Output) %v", rep.EndPos, len(rep.Output))
	}
	if rep.SkipPos <= rep.StartPos || rep.SkipPos > rep.EndPos {
		t.Fatalf("bad SkipPos %v: StartPos %v EndPos %v", rep.SkipPos, rep.StartPos, rep.EndPos)
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
		rep1 := reporter.ParseFrom(test.Log, rep.StartPos)
		if rep1 == nil || rep1.Title != rep.Title || rep1.StartPos != rep.StartPos {
			t.Fatalf("did not find the same report from rep.StartPos=%v", rep.StartPos)
		}
		// If we parse from EndPos, we must not find the same report.
		rep2 := reporter.ParseFrom(test.Log, rep.EndPos)
		if rep2 != nil && rep2.Title == rep.Title {
			t.Fatalf("found the same report after rep.EndPos=%v", rep.EndPos)
		}
	}
}

func updateReportTest(t *testing.T, test, parsed *ParseTest) {
	buf := new(bytes.Buffer)
	buf.Write(parsed.Headers(test.Frame != ""))
	fmt.Fprintf(buf, "\n%s", test.Log)
	if test.HasReport {
		fmt.Fprintf(buf, "REPORT:\n%s", test.Report)
	}
	if err := os.WriteFile(test.FileName, buf.Bytes(), 0640); err != nil {
		t.Logf("failed to update test file: %v", err)
	}
}

func TestGuiltyFile(t *testing.T) {
	forEachFile(t, "guilty", testGuiltyFile)
}

func testGuiltyFile(t *testing.T, reporter *Reporter, fn string) {
	vars, report := parseGuiltyTest(t, fn)
	file := vars["FILE"]
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
	if rep.GuiltyFile != file {
		t.Fatalf("got guilty %q, want %q", rep.GuiltyFile, file)
	}
}

func TestRawGuiltyFile(t *testing.T) {
	forEachFile(t, "guilty_raw", testRawGuiltyFile)
}

func testRawGuiltyFile(t *testing.T, reporter *Reporter, fn string) {
	vars, report := parseGuiltyTest(t, fn)
	outFile := reporter.ReportToGuiltyFile(vars["TITLE"], report)
	if outFile != vars["FILE"] {
		t.Fatalf("expected %#v, got %#v", vars["FILE"], outFile)
	}
}

func parseGuiltyTest(t *testing.T, fn string) (map[string]string, []byte) {
	data, err := os.ReadFile(fn)
	if err != nil {
		t.Fatal(err)
	}
	nlnl := bytes.Index(data, []byte{'\n', '\n'})
	if nlnl == -1 {
		t.Fatalf("no \\n\\n in file")
	}
	vars := map[string]string{}
	s := bufio.NewScanner(bytes.NewReader(data[:nlnl]))
	for s.Scan() {
		ln := strings.TrimSpace(s.Text())
		if ln == "" || ln[0] == '#' {
			continue
		}
		colon := strings.IndexByte(ln, ':')
		if colon == -1 {
			t.Fatalf("no : in %s", ln)
		}
		vars[strings.TrimSpace(ln[:colon])] = strings.TrimSpace(ln[colon+1:])
	}
	return vars, data[nlnl+2:]
}

func forEachFile(t *testing.T, dir string, fn func(t *testing.T, reporter *Reporter, fn string)) {
	for os := range ctors {
		if os == targets.Windows {
			continue // not implemented
		}
		cfg := &mgrconfig.Config{
			Derived: mgrconfig.Derived{
				TargetOS:   os,
				TargetArch: targets.AMD64,
				SysTarget:  targets.Get(os, targets.AMD64),
			},
		}
		reporter, err := NewReporter(cfg)
		if err != nil {
			t.Fatal(err)
		}
		// There is little point in re-parsing all test files in race mode.
		// Just make sure there are no obvious races by running few reports from "all" dir.
		if !testutil.RaceEnabled {
			for _, file := range readDir(t, filepath.Join("testdata", os, dir)) {
				t.Run(fmt.Sprintf("%v/%v", os, filepath.Base(file)), func(t *testing.T) {
					fn(t, reporter, file)
				})
			}
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
	entries, err := os.ReadDir(dir)
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
		"cleaned vnode",
		"kernel:",
	} {
		Fuzz([]byte(data)[:len(data):len(data)])
	}
}
