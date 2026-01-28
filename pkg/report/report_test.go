// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bufio"
	"bytes"
	"encoding/json"
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
	"github.com/stretchr/testify/assert"
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

	// HasReport is in charge of both Report and TailReports.
	HasReport   bool
	Report      []byte
	TailReports [][]byte

	Executor   string
	ContextIDs []string
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
	if test.ContextIDs != nil && !reflect.DeepEqual(test.ContextIDs, other.ContextIDs) {
		return false
	}
	if !reflect.DeepEqual(test.AltTitles, other.AltTitles) {
		return false
	}
	if test.Frame != "" && test.Frame != other.Frame {
		return false
	}
	if test.HasReport && !bytes.Equal(test.Report, other.Report) {
		return false
	}
	if test.HasReport && !reflect.DeepEqual(test.TailReports, other.TailReports) {
		return false
	}
	return test.Executor == other.Executor
}

func (test *ParseTest) Headers() []byte {
	buf := new(bytes.Buffer)
	if test.Title != "" {
		fmt.Fprintf(buf, "TITLE: %v\n", test.Title)
	}
	for _, t := range test.AltTitles {
		fmt.Fprintf(buf, "ALT: %v\n", t)
	}
	if test.Type != crash.UnknownType {
		fmt.Fprintf(buf, "TYPE: %v\n", test.Type)
	}
	if test.Frame != "" {
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
	if strings.Join(test.ContextIDs, "") != "" {
		jsonData, _ := json.Marshal(test.ContextIDs)
		fmt.Fprintf(buf, "CONTEXTS: %s\n", jsonData)
	}
	return buf.Bytes()
}

func testParseFile(t *testing.T, reporter *Reporter, fn string) {
	test := parseReport(t, reporter, fn)
	testParseImpl(t, reporter, test)
}

func parseReport(t *testing.T, reporter *Reporter, testFileName string) *ParseTest {
	data, err := os.ReadFile(testFileName)
	if err != nil {
		t.Fatal(err)
	}
	// Strip all \r from reports because the merger removes it.
	data = bytes.ReplaceAll(data, []byte{'\r'}, nil)
	const (
		phaseHeaders = iota
		phaseLog
		phaseReport
		phaseTailReports
	)
	phase := phaseHeaders
	test := &ParseTest{
		FileName: testFileName,
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
			if string(s.Bytes()) == "TAIL REPORTS:" {
				test.TailReports = [][]byte{{}}
				phase = phaseTailReports
			} else {
				test.Report = append(test.Report, s.Bytes()...)
				test.Report = append(test.Report, '\n')
			}
		case phaseTailReports:
			if string(s.Bytes()) == reportSeparator {
				test.TailReports = append(test.TailReports, []byte{})
				continue
			}
			test.TailReports[len(test.TailReports)-1] = append(test.TailReports[len(test.TailReports)-1], s.Bytes()...)
			test.TailReports[len(test.TailReports)-1] = append(test.TailReports[len(test.TailReports)-1], []byte{'\n'}...)
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
	return test
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
		contextidPrefix  = "CONTEXTS: "
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
	case strings.HasPrefix(ln, contextidPrefix):
		err := json.Unmarshal([]byte(ln[len(contextidPrefix):]), &test.ContextIDs)
		if err != nil {
			t.Fatalf("contextIDs unmarshaling error: %q", err)
		}
	default:
		t.Fatalf("unknown header field %q", ln)
	}
}

func testFromReports(reps ...*Report) *ParseTest {
	if reps == nil || len(reps) > 0 && reps[0] == nil {
		return &ParseTest{}
	}
	ret := &ParseTest{
		Title:           reps[0].Title,
		AltTitles:       reps[0].AltTitles,
		Corrupted:       reps[0].Corrupted,
		corruptedReason: reps[0].CorruptedReason,
		Suppressed:      reps[0].Suppressed,
		Type:            crash.TitleToType(reps[0].Title),
		Frame:           reps[0].Frame,
		Report:          reps[0].Report,
	}
	if reps[0].Executor != nil {
		ret.Executor = fmt.Sprintf("proc=%d, id=%d", reps[0].Executor.ProcID, reps[0].Executor.ExecID)
	}
	sort.Strings(ret.AltTitles)
	ret.ContextIDs = append(ret.ContextIDs, reps[0].ContextID)
	for i := 1; i < len(reps); i++ {
		ret.TailReports = append(ret.TailReports, reps[i].Report)
		ret.ContextIDs = append(ret.ContextIDs, reps[i].ContextID)
	}
	return ret
}

func testParseImpl(t *testing.T, reporter *Reporter, test *ParseTest) {
	gotReports := ParseAll(reporter, test.Log, 0)

	var firstReport *Report
	if len(gotReports) > 0 {
		firstReport = gotReports[0]
	}
	containsCrash := reporter.ContainsCrash(test.Log)
	expectCrash := (test.Title != "")
	if expectCrash && !containsCrash {
		t.Fatalf("did not find crash")
	}
	if !expectCrash && containsCrash {
		t.Fatalf("found unexpected crash: %s", firstReport.Title)
	}
	if firstReport != nil && firstReport.Title == "" {
		t.Fatalf("found crash, but title is empty")
	}
	parsed := testFromReports(gotReports...)
	if !test.Equal(parsed) {
		if *flagUpdate && test.StartLine+test.EndLine == "" {
			updateReportTest(t, test, parsed)
		}
		t.Fatalf("want:\n%s\ngot:\n%sCorrupted reason: %q",
			test.Headers(), parsed.Headers(), parsed.corruptedReason)
	}
	if parsed.Title != "" && len(firstReport.Report) == 0 {
		t.Fatalf("found crash message but report is empty")
	}
	if firstReport == nil {
		return
	}
	checkReport(t, reporter, firstReport, test)
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
	}
}

func updateReportTest(t *testing.T, test, parsed *ParseTest) {
	buf := new(bytes.Buffer)
	if test.Frame == "" {
		// Don't create "FRAME:" record, only update existing.
		parsed.Frame = ""
	}
	buf.Write(parsed.Headers())
	fmt.Fprintf(buf, "\n%s", test.Log)
	if test.HasReport {
		fmt.Fprintf(buf, "REPORT:\n%s", parsed.Report)
		if len(parsed.TailReports) > 0 {
			fmt.Fprintf(buf, "TAIL REPORTS:\n")
			buf.Write(bytes.Join(parsed.TailReports, []byte(reportSeparator+"\n")))
		}
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

func TestSymbolize(t *testing.T) {
	// We cannot fully test symbolization as we need kernel binaries with debug info, but
	// let's at least test symbol demangling that's done as part of Symbolize().
	forEachFile(t, "symbolize", testSymbolizeFile)
}

func testSymbolizeFile(t *testing.T, reporter *Reporter, fn string) {
	test := parseReport(t, reporter, fn)
	if !test.HasReport {
		t.Fatalf("the test must have the REPORT section")
	}
	rep := reporter.Parse(test.Log)
	if rep == nil {
		t.Fatalf("did not find crash")
	}
	err := reporter.Symbolize(rep)
	if err != nil {
		t.Fatalf("failed to symbolize: %v", err)
	}
	parsed := testFromReports(rep)
	if !test.Equal(parsed) {
		if *flagUpdate {
			updateReportTest(t, test, parsed)
		}
		assert.Equal(t, string(test.Report), string(rep.Report), "extracted wrong report")
		t.Fatalf("want:\n%s\ngot:\n%sCorrupted reason: %q",
			test.Headers(), parsed.Headers(), parsed.corruptedReason)
	}
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

func TestTruncate(t *testing.T) {
	assert.Equal(t, []byte(`01234

<<cut 11 bytes out>>`), Truncate([]byte(`0123456789ABCDEF`), 5, 0))
	assert.Equal(t, []byte(`<<cut 11 bytes out>>

BCDEF`), Truncate([]byte(`0123456789ABCDEF`), 0, 5))
	assert.Equal(t, []byte(`0123

<<cut 9 bytes out>>

DEF`), Truncate([]byte(`0123456789ABCDEF`), 4, 3))
}

func TestSplitReportBytes(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantFirst string
	}{
		{
			name:      "empty",
			input:     nil,
			wantFirst: "",
		},
		{
			name:      "single",
			input:     []byte("report1"),
			wantFirst: "report1",
		},
		{
			name:      "split in the middle",
			input:     []byte("report1" + reportSeparator + "report2"),
			wantFirst: "report1",
		},
		{
			name:      "split in the middle, save new line",
			input:     []byte("report1\n" + reportSeparator + "report2"),
			wantFirst: "report1\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			splitted := SplitReportBytes(test.input)
			assert.Equal(t, test.wantFirst, string(splitted[0]))
		})
	}
}
