// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/syzkaller/symbolizer"
)

type oops struct {
	header  []byte
	formats []oopsFormat
}

type oopsFormat struct {
	re  *regexp.Regexp
	fmt string
}

var oopses = []*oops{
	&oops{
		[]byte("BUG:"),
		[]oopsFormat{
			{
				compile("BUG: KASAN: ([a-z\\-]+) in {{FUNC}}(?:.*\\n)+.*(Read|Write) of size ([0-9]+)"),
				"KASAN: %[1]v %[3]v of size %[4]v in %[2]v",
			},
			{
				compile("BUG: KASAN: ([a-z\\-]+) on address(?:.*\\n)+.*(Read|Write) of size ([0-9]+)"),
				"KASAN: %[1]v %[2]v of size %[3]v",
			},
			{
				compile("BUG: unable to handle kernel paging request(?:.*\\n)+.*IP: {{PC}} +{{FUNC}}"),
				"BUG: unable to handle kernel paging request in %[1]v",
			},
			{
				compile("BUG: unable to handle kernel paging request"),
				"BUG: unable to handle kernel paging request",
			},
			{
				compile("BUG: unable to handle kernel NULL pointer dereference(?:.*\\n)+.*IP: {{PC}} +{{FUNC}}"),
				"BUG: unable to handle kernel NULL pointer dereference in %[1]v",
			},
			{
				compile("BUG: spinlock lockup suspected"),
				"BUG: spinlock lockup suspected",
			},
			{
				compile("BUG: soft lockup"),
				"BUG: soft lockup",
			},
		},
	},
	&oops{
		[]byte("WARNING:"),
		[]oopsFormat{
			{
				compile("WARNING: .* at {{SRC}} {{FUNC}}"),
				"WARNING in %[2]v",
			},
		},
	},
	&oops{
		[]byte("INFO:"),
		[]oopsFormat{
			{
				compile("INFO: possible circular locking dependency detected \\](?:.*\\n)+.*is trying to acquire lock(?:.*\\n)+.*at: {{PC}} +{{FUNC}}"),
				"possible deadlock in %[1]v",
			},
			{
				compile("INFO: rcu_preempt detected stalls"),
				"INFO: rcu_preempt detected stalls",
			},
			{
				compile("INFO: suspicious RCU usage(?:.*\n.*)+(?: |\n|\t){{SRC}}"),
				"suspicious RCU usage at %[1]v",
			},
		},
	},
	&oops{
		[]byte("Unable to handle kernel paging request"),
		[]oopsFormat{
			{
				compile("Unable to handle kernel paging request(?:.*\\n)+.*PC is at {{FUNC}}"),
				"unable to handle kernel paging request in %[1]v",
			},
		},
	},
	&oops{
		[]byte("general protection fault:"),
		[]oopsFormat{
			{
				compile("general protection fault:(?:.*\n)+.*RIP: [0-9]+:{{PC}} +{{PC}} +{{FUNC}}"),
				"general protection fault in %[1]v",
			},
		},
	},
	&oops{
		[]byte("Kernel panic"),
		[]oopsFormat{
			{
				compile("Kernel panic - not syncing: Attempted to kill init!"),
				"kernel panic: Attempted to kill init!",
			},
			{
				compile("Kernel panic - not syncing: (.*)"),
				"kernel panic: %[1]v",
			},
		},
	},
	&oops{
		[]byte("kernel BUG"),
		[]oopsFormat{
			{
				compile("kernel BUG (.*)"),
				"kernel BUG %[1]v",
			},
		},
	},
	&oops{
		[]byte("Kernel BUG"),
		[]oopsFormat{
			{
				compile("Kernel BUG (.*)"),
				"kernel BUG %[1]v",
			},
		},
	},
	&oops{
		[]byte("divide error:"),
		[]oopsFormat{
			{
				compile("divide error: (?:.*\n)+.*RIP: [0-9]+:{{PC}} +{{PC}} +{{FUNC}}"),
				"divide error in %[1]v",
			},
		},
	},
	&oops{
		[]byte("invalid opcode:"),
		[]oopsFormat{
			{
				compile("invalid opcode: (?:.*\n)+.*RIP: [0-9]+:{{PC}} +{{PC}} +{{FUNC}}"),
				"invalid opcode in %[1]v",
			},
		},
	},
	&oops{
		[]byte("unreferenced object"),
		[]oopsFormat{
			{
				compile("unreferenced object {{ADDR}} \\(size ([0-9]+)\\):(?:.*\n.*)+backtrace:.*\n.*{{PC}}.*\n.*{{PC}}.*\n.*{{PC}} {{FUNC}}"),
				"memory leak in %[2]v (size %[1]v)",
			},
		},
	},
	&oops{
		[]byte("UBSAN:"),
		[]oopsFormat{},
	},
}

var (
	consoleOutputRe = regexp.MustCompile(`^\[ *[0-9]+\.[0-9]+\] `)
	questionableRe  = regexp.MustCompile(`\[\<[0-9a-f]+\>\] \? +[a-zA-Z0-9_.]+\+0x[0-9a-f]+/[0-9a-f]+`)
	symbolizeRe     = regexp.MustCompile(`\[\<([0-9a-f]+)\>\] +([a-zA-Z0-9_.]+)\+0x([0-9a-f]+)/0x([0-9a-f]+)`)
	eoi             = []byte("<EOI>")
)

func compile(re string) *regexp.Regexp {
	re = strings.Replace(re, "{{ADDR}}", "0x[0-9a-f]+", -1)
	re = strings.Replace(re, "{{PC}}", "\\[\\<[0-9a-f]+\\>\\]", -1)
	re = strings.Replace(re, "{{FUNC}}", "([a-zA-Z0-9_]+)(?:\\.|\\+)", -1)
	re = strings.Replace(re, "{{SRC}}", "([a-zA-Z0-9-_/.]+:[0-9]+)", -1)
	return regexp.MustCompile(re)
}

// ContainsCrash searches kernel console output for oops messages.
func ContainsCrash(output []byte) bool {
	for pos := 0; pos < len(output); {
		next := bytes.IndexByte(output[pos:], '\n')
		if next != -1 {
			next += pos
		} else {
			next = len(output)
		}
		for _, oops := range oopses {
			match := bytes.Index(output[pos:next], oops.header)
			if match == -1 {
				continue
			}
			return true
		}
		pos = next + 1
	}
	return false
}

// Parse extracts information about oops from console output.
// Desc contains a representative description of the first oops (empty if no oops found),
// text contains whole oops text,
// start and end denote region of output with oops message(s).
func Parse(output []byte) (desc string, text []byte, start int, end int) {
	var oops *oops
	for pos := 0; pos < len(output); {
		next := bytes.IndexByte(output[pos:], '\n')
		if next != -1 {
			next += pos
		} else {
			next = len(output)
		}
		for _, oops1 := range oopses {
			match := bytes.Index(output[pos:next], oops1.header)
			if match == -1 {
				continue
			}
			if oops == nil {
				oops = oops1
				start = pos
				desc = string(output[pos+match : next])
			}
			end = next
		}
		if oops != nil {
			if consoleOutputRe.Match(output[pos:next]) &&
				(!questionableRe.Match(output[pos:next]) || bytes.Index(output[pos:next], eoi) != -1) {
				lineStart := bytes.Index(output[pos:next], []byte("] ")) + pos + 2
				lineEnd := next
				if lineEnd != 0 && output[lineEnd-1] == '\r' {
					lineEnd--
				}
				text = append(text, output[lineStart:lineEnd]...)
				text = append(text, '\n')
			}
		}
		pos = next + 1
	}
	if oops == nil {
		return
	}
	desc = extractDescription(output[start:], oops)
	if len(desc) > 0 && desc[len(desc)-1] == '\r' {
		desc = desc[:len(desc)-1]
	}
	return
}

func extractDescription(output []byte, oops *oops) string {
	result := ""
	startPos := -1
	for _, format := range oops.formats {
		match := format.re.FindSubmatchIndex(output)
		if match == nil {
			continue
		}
		if startPos != -1 && startPos <= match[0] {
			continue
		}
		startPos = match[0]
		var args []interface{}
		for i := 2; i < len(match); i += 2 {
			args = append(args, string(output[match[i]:match[i+1]]))
		}
		result = fmt.Sprintf(format.fmt, args...)
	}
	if result != "" {
		return result
	}
	pos := bytes.Index(output, oops.header)
	if pos == -1 {
		panic("non matching oops")
	}
	end := bytes.IndexByte(output[pos:], '\n')
	if end == -1 {
		end = len(output)
	} else {
		end += pos
	}
	return string(output[pos:end])
}

func Symbolize(vmlinux string, text []byte) ([]byte, error) {
	var symbolized []byte
	symbols, err := symbolizer.ReadSymbols(vmlinux)
	if err != nil {
		return nil, err
	}
	symb := symbolizer.NewSymbolizer()
	defer symb.Close()
	symbFunc := func(bin string, pc uint64) ([]symbolizer.Frame, error) {
		return symb.Symbolize(bin, pc)
	}
	strip, _ := filepath.Abs(vmlinux)
	strip = filepath.Dir(strip) + string(filepath.Separator)
	s := bufio.NewScanner(bytes.NewReader(text))
	for s.Scan() {
		line := append([]byte{}, s.Bytes()...)
		line = append(line, '\n')
		line = symbolizeLine(symbFunc, symbols, vmlinux, strip, line)
		symbolized = append(symbolized, line...)
	}
	return symbolized, nil
}

func symbolizeLine(symbFunc func(bin string, pc uint64) ([]symbolizer.Frame, error), symbols map[string][]symbolizer.Symbol, vmlinux, strip string, line []byte) []byte {
	match := symbolizeRe.FindSubmatchIndex(line)
	if match == nil {
		return line
	}
	fn := line[match[4]:match[5]]
	off, err := strconv.ParseUint(string(line[match[6]:match[7]]), 16, 64)
	if err != nil {
		return line
	}
	size, err := strconv.ParseUint(string(line[match[8]:match[9]]), 16, 64)
	if err != nil {
		return line
	}
	symb := symbols[string(fn)]
	if len(symb) == 0 {
		return line
	}
	var funcStart uint64
	for _, s := range symb {
		if funcStart == 0 || int(size) == s.Size {
			funcStart = s.Addr
		}
	}
	frames, err := symbFunc(vmlinux, funcStart+off-1)
	if err != nil || len(frames) == 0 {
		return line
	}
	var symbolized []byte
	for _, frame := range frames {
		file := frame.File
		if strings.HasPrefix(file, strip) {
			file = file[len(strip):]
		}
		if strings.HasPrefix(file, "./") {
			file = file[2:]
		}
		info := fmt.Sprintf(" %v:%v", file, frame.Line)
		modified := append([]byte{}, line...)
		modified = replace(modified, match[9], match[9], []byte(info))
		if frame.Inline {
			modified = replace(modified, match[4], match[9], []byte(frame.Func))
			modified = replace(modified, match[2], match[3], []byte("     inline     "))
		}
		symbolized = append(symbolized, modified...)
	}
	return symbolized
}

// replace replaces [start:end] in where with what, inplace.
func replace(where []byte, start, end int, what []byte) []byte {
	if len(what) >= end-start {
		where = append(where, what[end-start:]...)
		copy(where[start+len(what):], where[end:])
		copy(where[start:], what)
	} else {
		copy(where[start+len(what):], where[end:])
		where = where[:len(where)-(end-start-len(what))]
		copy(where[start:], what)
	}
	return where
}
